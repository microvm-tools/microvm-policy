package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newMeteredProxy is newTestProxy with a usage file.
func newMeteredProxy(t *testing.T, mode string, ep *Endpoint) (*httptest.Server, *syncBuf, string) {
	t.Helper()
	a, err := ParseAllowlist(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	audit := &syncBuf{}
	usage := filepath.Join(t.TempDir(), "usage.json")
	p := &Proxy{
		mode:      mode,
		allow:     a,
		endpoints: []*Endpoint{ep},
		audit:     slog.New(slog.NewJSONHandler(audit, nil)),
		transport: http.DefaultTransport,
		usageFile: usage,
	}
	p.writeUsage()
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	return ts, audit, usage
}

// waitUsage returns the usage file's entry once ok holds. The file is
// written after a response is copied, which a client that knew the body's
// length has already seen the end of: poll, briefly.
func waitUsage(t *testing.T, path string, ok func(u usageEntry) bool) usageEntry {
	t.Helper()
	var last string
	for range 200 {
		raw, err := os.ReadFile(path)
		var u struct{ Endpoints []usageEntry }
		if err == nil && json.Unmarshal(raw, &u) == nil && len(u.Endpoints) == 1 && ok(u.Endpoints[0]) {
			return u.Endpoints[0]
		}
		last = string(raw)
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("usage file never matched: %s", last)
	return usageEntry{}
}

// expectStatuses sends one request per want and checks each status in turn.
func expectStatuses(t *testing.T, url string, wants ...int) []string {
	t.Helper()
	bodies := make([]string, 0, len(wants))
	for i, want := range wants {
		code, body := post(t, url, nil)
		if code != want {
			t.Fatalf("request %d: status %d, want %d (%s)", i+1, code, want, body)
		}
		bodies = append(bodies, body)
	}
	return bodies
}

func post(t *testing.T, url string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader("{}"))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	// The client's own transport would ask for gzip and decompress; this
	// test speaks to the proxy as a client that names its encodings itself.
	resp, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// sseStream is a Messages API stream as the API sends it: input usage in
// message_start, the running output count in message_delta.
func sseStream(input, cacheRead, output int64) string {
	return fmt.Sprintf("event: message_start\n"+
		`data: {"type":"message_start","message":{"id":"m","usage":{"input_tokens":%d,"cache_creation_input_tokens":0,"cache_read_input_tokens":%d,"output_tokens":1}}}`+"\n\n"+
		"event: content_block_delta\n"+
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`+"\n\n"+
		"event: message_delta\n"+
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":%d}}`+"\n\n"+
		"event: message_stop\n"+
		`data: {"type":"message_stop"}`+"\n\n", input, cacheRead, output)
}

func TestBudgetMaxRequests(t *testing.T) {
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.Budget = &Budget{MaxRequests: 2}
	ts, audit, usage := newMeteredProxy(t, "enforce", ep)

	bodies := expectStatuses(t, ts.URL+"/anthropic/v1/messages", 200, 200, 403, 403)
	if !strings.Contains(bodies[3], "API budget (2 requests) is spent") {
		t.Errorf("refusal does not say why: %q", bodies[3])
	}
	if hits.Load() != 2 {
		t.Errorf("upstream saw %d requests, want 2", hits.Load())
	}
	if n := strings.Count(audit.String(), `"decision":"over_budget"`); n != 2 {
		t.Errorf("over_budget audited %d times, want 2:\n%s", n, audit)
	}
	waitUsage(t, usage, func(u usageEntry) bool {
		return u.Requests == 2 && u.Refused == 2 && u.Exhausted && u.Tokens == nil && u.Budget.MaxRequests == 2
	})
}

func TestBudgetTokensFromStream(t *testing.T) {
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		_, _ = io.WriteString(w, sseStream(100, 50, 30))
	}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.Usage = "anthropic"
	ep.Budget = &Budget{MaxTokens: 300}
	ts, _, usage := newMeteredProxy(t, "enforce", ep)

	// 180 a request (100 + 50 cache read + 30 output): the second starts at
	// 180 < 300 and is let through, the third finds 360 and is refused.
	bodies := expectStatuses(t, ts.URL+"/anthropic/v1/messages", 200, 200, 403)
	if bodies[0] != sseStream(100, 50, 30) {
		t.Errorf("stream altered on its way: %q", bodies[0])
	}
	waitUsage(t, usage, func(u usageEntry) bool {
		return u.Tokens != nil && *u.Tokens == Tokens{Input: 200, CacheRead: 100, Output: 60} &&
			u.Requests == 2 && u.Refused == 1 && u.Exhausted
	})
	if hits.Load() != 2 {
		t.Errorf("upstream saw %d requests, want 2", hits.Load())
	}
}

func TestUsageFromJSONBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"m","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":10,"cache_creation_input_tokens":4,"cache_read_input_tokens":0,"output_tokens":5}}`)
	}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.Usage = "anthropic"
	ts, _, usage := newMeteredProxy(t, "enforce", ep)
	if code, _ := post(t, ts.URL+"/anthropic/v1/messages", nil); code != 200 {
		t.Fatalf("status %d", code)
	}
	waitUsage(t, usage, func(u usageEntry) bool {
		return u.Tokens != nil && *u.Tokens == Tokens{Input: 10, CacheCreation: 4, Output: 5} && !u.Exhausted
	})
}

// A client that accepts compression would get a body the meter cannot read:
// the proxy drops its Accept-Encoding, the transport negotiates gzip itself
// and decompresses.
func TestUsageThroughCompression(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ae := r.Header.Get("Accept-Encoding"); ae != "gzip" {
			t.Errorf("upstream Accept-Encoding = %q, want the transport's own gzip", ae)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = io.WriteString(gz, sseStream(7, 0, 3))
		_ = gz.Close()
	}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.Usage = "anthropic"
	ts, _, usage := newMeteredProxy(t, "enforce", ep)
	code, body := post(t, ts.URL+"/anthropic/v1/messages", map[string]string{"Accept-Encoding": "br, gzip"})
	if code != 200 || body != sseStream(7, 0, 3) {
		t.Fatalf("status %d, body %q: want the stream, decompressed", code, body)
	}
	waitUsage(t, usage, func(u usageEntry) bool { return u.Tokens != nil && u.Tokens.total() == 10 })
}

// A line longer than sseLineMax is skipped, not buffered, and the usage
// after it still counts.
func TestUsageSkipsLongLines(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"type":"content_block_delta","delta":{"text":"`+strings.Repeat("x", 2*sseLineMax)+`"}}`+"\n\n")
		_, _ = io.WriteString(w, sseStream(1, 0, 2))
	}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.Usage = "anthropic"
	ts, _, usage := newMeteredProxy(t, "enforce", ep)
	if code, _ := post(t, ts.URL+"/anthropic/v1/messages", nil); code != 200 {
		t.Fatalf("status %d", code)
	}
	waitUsage(t, usage, func(u usageEntry) bool { return u.Tokens != nil && u.Tokens.total() == 3 })
}

// Concurrent requests reserve against the budget: no two pass on the last
// unit.
func TestBudgetConcurrent(t *testing.T) {
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.Budget = &Budget{MaxRequests: 5}
	ts, _, usage := newMeteredProxy(t, "enforce", ep)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/anthropic/v1/messages", nil)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	if hits.Load() != 5 {
		t.Errorf("upstream saw %d requests, want 5", hits.Load())
	}
	waitUsage(t, usage, func(u usageEntry) bool { return u.Requests == 5 && u.Refused == 15 })
}

// Shadow mode relaxes the egress rules, not the budget.
func TestBudgetHoldsInLogMode(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.Budget = &Budget{MaxRequests: 1}
	ts, audit, _ := newMeteredProxy(t, "log", ep)
	post(t, ts.URL+"/anthropic/v1/messages", nil)
	if code, _ := post(t, ts.URL+"/anthropic/v1/messages", nil); code != 403 {
		t.Errorf("log mode let a request past the budget: %d", code)
	}
	if !strings.Contains(audit.String(), `"decision":"over_budget","mode":"log"`) {
		t.Errorf("audit:\n%s", audit)
	}
}

// A denied path is a deny, and spends nothing.
func TestBudgetNotSpentOnDeniedPaths(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.Budget = &Budget{MaxRequests: 1}
	ts, _, usage := newMeteredProxy(t, "enforce", ep)
	if code, _ := post(t, ts.URL+"/anthropic/v1/files", nil); code != 403 {
		t.Fatalf("denied path: %d", code)
	}
	if code, _ := post(t, ts.URL+"/anthropic/v1/messages", nil); code != 200 {
		t.Errorf("the budget was spent by a denied path: %d", code)
	}
	waitUsage(t, usage, func(u usageEntry) bool { return u.Requests == 1 && u.Refused == 0 })
}

// A request refused for want of a credential never went upstream, and
// does not count.
func TestBudgetNotSpentWithoutCredential(t *testing.T) {
	ep := anthropicEndpoint(t, "http://127.0.0.1:1")
	ep.key = ""
	ep.KeyFile = filepath.Join(t.TempDir(), "missing.json")
	ep.Budget = &Budget{MaxRequests: 1}
	if err := ep.initKeyFile(); err != nil {
		t.Fatal(err)
	}
	ts, _, usage := newMeteredProxy(t, "enforce", ep)
	if code, _ := post(t, ts.URL+"/anthropic/v1/messages", nil); code != 503 {
		t.Fatalf("status %d, want 503", code)
	}
	waitUsage(t, usage, func(u usageEntry) bool { return u.Requests == 0 && u.Refused == 0 })
}

func TestBudgetInitRejects(t *testing.T) {
	cases := map[string]func(*Endpoint){
		"unknown usage":           func(ep *Endpoint) { ep.Usage = "openai-ish" },
		"budget limiting nothing": func(ep *Endpoint) { ep.Budget = &Budget{} },
		"negative requests":       func(ep *Endpoint) { ep.Budget = &Budget{MaxRequests: -1} },
		"negative tokens":         func(ep *Endpoint) { ep.Usage = "anthropic"; ep.Budget = &Budget{MaxTokens: -1, MaxRequests: 3} },
		"tokens without usage":    func(ep *Endpoint) { ep.Budget = &Budget{MaxTokens: 1000} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ep := &Endpoint{Prefix: "/anthropic", Upstream: "https://api.anthropic.com", Header: "x-api-key", AllowedPaths: []string{"/v1/messages"}}
			mutate(ep)
			if err := ep.init(); err == nil {
				t.Errorf("init accepted usage %q budget %+v", ep.Usage, ep.Budget)
			}
		})
	}
	ep := &Endpoint{
		Prefix: "/anthropic", Upstream: "https://api.anthropic.com", Header: "x-api-key", AllowedPaths: []string{"/v1/messages"},
		Usage: "anthropic", Budget: &Budget{MaxTokens: 1000, MaxRequests: 10},
	}
	if err := ep.init(); err != nil {
		t.Errorf("valid budget refused: %v", err)
	}
}
