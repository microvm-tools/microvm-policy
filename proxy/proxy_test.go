package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p) //nolint:wrapcheck // io.Writer passthrough
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newTestProxy(t *testing.T, mode, allowlist string, endpoints []*Endpoint) (*httptest.Server, *syncBuf) {
	t.Helper()
	a, err := ParseAllowlist(strings.NewReader(allowlist))
	if err != nil {
		t.Fatal(err)
	}
	audit := &syncBuf{}
	p := &Proxy{
		mode:      mode,
		allow:     a,
		endpoints: endpoints,
		audit:     slog.New(slog.NewJSONHandler(audit, nil)),
		transport: http.DefaultTransport,
	}
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	return ts, audit
}

func anthropicEndpoint(t *testing.T, upstream string) *Endpoint {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	return &Endpoint{
		Prefix:       "/anthropic",
		Upstream:     upstream,
		Header:       "x-api-key",
		AllowedPaths: []string{"/v1/messages"},
		upstreamURL:  u,
		key:          "proxy-held-key",
	}
}

// get fetches url and returns the status and body, closing the response.
func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // test-local URL
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEndpointStripsAndInjects(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Api-Key"); got != "proxy-held-key" {
			t.Errorf("X-Api-Key = %q, want the injected key", got)
		}
		for _, h := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
			if got := r.Header.Get(h); got != "" {
				t.Errorf("%s = %q, want it stripped", h, got)
			}
		}
		if r.URL.Path != "/v1/messages" {
			t.Errorf("upstream path = %q, want /v1/messages", r.URL.Path)
		}
		if r.URL.RawQuery != "beta=true" {
			t.Errorf("query = %q, want beta=true", r.URL.RawQuery)
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}))
	defer backend.Close()

	ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{anthropicEndpoint(t, backend.URL)})

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/anthropic/v1/messages?beta=true", strings.NewReader("prompt"))
	// A planted credential riding on an allowed connection must not survive.
	req.Header.Set("X-Api-Key", "attacker-planted")
	req.Header.Set("Authorization", "Bearer stolen")
	req.Header.Set("Cookie", "session=stolen")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body, _ := io.ReadAll(resp.Body); string(body) != "prompt" {
		t.Errorf("body = %q, want it round-tripped", body)
	}
}

func TestEndpointPathAllowlist(t *testing.T) {
	var backendHits int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits++
	}))
	defer backend.Close()

	t.Run("enforce denies off-list paths", func(t *testing.T) {
		ts, audit := newTestProxy(t, "enforce", "", []*Endpoint{anthropicEndpoint(t, backend.URL)})
		status, body := get(t, ts.URL+"/anthropic/v1/files")
		if status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", status)
		}
		if !strings.Contains(body, "denied") || !strings.Contains(body, "/v1/messages") {
			t.Errorf("denial must name the allowed paths, got %q", body)
		}
		if !strings.Contains(audit.String(), `"decision":"deny"`) {
			t.Errorf("audit log missing deny entry: %s", audit.String())
		}
	})

	t.Run("log mode allows and audits would_deny", func(t *testing.T) {
		before := backendHits
		ts, audit := newTestProxy(t, "log", "", []*Endpoint{anthropicEndpoint(t, backend.URL)})
		if status, _ := get(t, ts.URL+"/anthropic/v1/files"); status != http.StatusOK {
			t.Fatalf("status = %d, want 200 in log mode", status)
		}
		if backendHits != before+1 {
			t.Error("log mode must still reach the backend")
		}
		if !strings.Contains(audit.String(), `"decision":"would_deny"`) {
			t.Errorf("audit log missing would_deny entry: %s", audit.String())
		}
	})

	t.Run("sub-paths of an allowed prefix pass", func(t *testing.T) {
		ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{anthropicEndpoint(t, backend.URL)})
		if status, _ := get(t, ts.URL+"/anthropic/v1/messages/count_tokens"); status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
	})

	t.Run("dot-dot cannot escape the allowed subtree", func(t *testing.T) {
		ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{anthropicEndpoint(t, backend.URL)})
		// Sent raw: the Go client would clean the path before it left.
		resp := rawRequest(t, ts.URL, "GET /anthropic/v1/messages/../files HTTP/1.1\r\nHost: x\r\n\r\n", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 for the cleaned path /v1/files", resp.StatusCode)
		}
	})
}

func TestEndpointExactPathGrant(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.AllowedPaths = []string{"/v1/messages$", "/v1/messages/count_tokens$"}
	ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{ep})
	for p, want := range map[string]int{
		"/v1/messages":                    http.StatusOK,
		"/v1/messages/count_tokens":       http.StatusOK,
		"/v1/messages/batches":            http.StatusForbidden,
		"/v1/messages/batches/b1/results": http.StatusForbidden,
		"/v1/messages/count_tokens/x":     http.StatusForbidden,
		"/v1/messages$":                   http.StatusForbidden,
	} {
		if status, _ := get(t, ts.URL+"/anthropic"+p); status != want {
			t.Errorf("%s: status = %d, want %d", p, status, want)
		}
	}
}

// rawRequest writes req verbatim to the server at serverURL and reads one
// response. The connection stays open for the test (a CONNECT tunnel rides on
// it) and is closed at cleanup.
func rawRequest(t *testing.T, serverURL, req string, forReq *http.Request) *http.Response {
	t.Helper()
	resp, _, _ := rawConn(t, serverURL, req, forReq)
	return resp
}

func rawConn(t *testing.T, serverURL, req string, forReq *http.Request) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(serverURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, forReq)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp, conn, br
}

// startEcho serves a TCP echo on a loopback port and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return echo.Addr().String()
}

func connectVia(t *testing.T, proxyURL, target string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	return rawConn(t, proxyURL, req, &http.Request{Method: http.MethodConnect})
}

func TestConnect(t *testing.T) {
	target := startEcho(t)

	t.Run("allowlisted host:port tunnels", func(t *testing.T) {
		ts, _ := newTestProxy(t, "enforce", target+"\n", nil)
		resp, conn, br := connectVia(t, ts.URL, target)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
		}
		if _, err := conn.Write([]byte("ping\n")); err != nil {
			t.Fatal(err)
		}
		line, err := br.ReadString('\n')
		if err != nil || line != "ping\n" {
			t.Fatalf("echo through tunnel = %q, %v", line, err)
		}
	})

	t.Run("off-list host is denied with an actionable message", func(t *testing.T) {
		ts, audit := newTestProxy(t, "enforce", target+"\n", nil)
		resp, _, _ := connectVia(t, ts.URL, "evil.example.com:443")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("CONNECT status = %d, want 403", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "not in the allowlist") || !strings.Contains(string(body), "EGRESS_ALLOW=evil.example.com") {
			t.Errorf("denial not actionable: %q", body)
		}
		if !strings.Contains(audit.String(), `"host":"evil.example.com"`) {
			t.Errorf("audit log missing the denied host: %s", audit.String())
		}
	})

	t.Run("allowed host on a different port is denied", func(t *testing.T) {
		host, _ := splitHostPort(target, 0)
		ts, _ := newTestProxy(t, "enforce", target+"\n", nil)
		resp, _, _ := connectVia(t, ts.URL, net.JoinHostPort(host, "1"))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("CONNECT status = %d, want 403: ports are per-entry grants", resp.StatusCode)
		}
	})
}

func TestForwardHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "forwarded")
	}))
	defer backend.Close()
	backendHostPort := strings.TrimPrefix(backend.URL, "http://")

	ts, _ := newTestProxy(t, "enforce", backendHostPort+"\n", nil)
	proxyURL, _ := url.Parse(ts.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "forwarded" {
		t.Fatalf("forwarded GET = %d %q, want 200 forwarded", resp.StatusCode, body)
	}

	resp, err = client.Get("http://evil.example.com:80/x")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("off-list forward = %d, want 403", resp.StatusCode)
	}
}

func TestEndpointCustomHeader(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Goog-Api-Key"); got != "gemini-key" {
			t.Errorf("X-Goog-Api-Key = %q, want the injected key", got)
		}
	}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.Header = "x-goog-api-key"
	ep.key = "gemini-key"
	ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{ep})
	resp, err := http.Get(ts.URL + "/anthropic/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestEndpointOAuthPassthrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer client-oauth-token" {
			t.Errorf("Authorization = %q, want the client token passed through", got)
		}
		if got := r.Header.Get("Proxy-Authorization"); got != "" {
			t.Errorf("Proxy-Authorization = %q, want it stripped even in passthrough", got)
		}
	}))
	defer backend.Close()
	ep := anthropicEndpoint(t, backend.URL)
	ep.key = "" // OAuth mode: the client holds its own token
	ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{ep})
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/anthropic/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer client-oauth-token")
	req.Header.Set("Proxy-Authorization", "Basic proxy-cred")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	allowlist := filepath.Join(dir, "allow.txt")
	mustWrite(t, allowlist, "github.com\n")
	config := filepath.Join(dir, "config.json")

	write := func(mode, keyEnv string) {
		cfg := fmt.Sprintf(`{
  "listen": "127.0.0.1:0",
  "mode": %q,
  "allowlistFile": %q,
  "portFile": "",
  "endpoints": [{
    "prefix": "/anthropic",
    "upstream": "https://api.anthropic.com",
    "keyEnv": %q,
    "header": "x-api-key",
    "allowedPaths": ["/v1/messages"]
  }]
}`, mode, allowlist, keyEnv)
		mustWrite(t, config, cfg)
	}

	t.Setenv("EGRESS_TEST_KEY", "k")
	write("enforce", "EGRESS_TEST_KEY")
	if _, _, err := load(config); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}

	write("enforce", "EGRESS_TEST_MISSING")
	if _, _, err := load(config); err == nil || !strings.Contains(err.Error(), "EGRESS_TEST_MISSING") {
		t.Errorf("missing credential env must fail the launch, got %v", err)
	}

	write("observe", "EGRESS_TEST_KEY")
	if _, _, err := load(config); err == nil {
		t.Error("unknown mode must be rejected")
	}
}

func TestEndpointInitRejects(t *testing.T) {
	valid := func() Endpoint {
		return Endpoint{
			Prefix:       "/anthropic",
			Upstream:     "https://api.anthropic.com",
			Header:       "x-api-key",
			AllowedPaths: []string{"/v1/messages"},
		}
	}
	cases := map[string]func(*Endpoint){
		"root prefix":          func(ep *Endpoint) { ep.Prefix = "/" },
		"relative prefix":      func(ep *Endpoint) { ep.Prefix = "anthropic" },
		"non-http upstream":    func(ep *Endpoint) { ep.Upstream = "ftp://api.anthropic.com" },
		"upstream with path":   func(ep *Endpoint) { ep.Upstream = "https://api.anthropic.com/v1" },
		"upstream no host":     func(ep *Endpoint) { ep.Upstream = "https://" },
		"empty header":         func(ep *Endpoint) { ep.Header = "" },
		"uppercase header":     func(ep *Endpoint) { ep.Header = "X-Api-Key" },
		"header with colon":    func(ep *Endpoint) { ep.Header = "x-api-key:" },
		"no allowed paths":     func(ep *Endpoint) { ep.AllowedPaths = nil },
		"relative path":        func(ep *Endpoint) { ep.AllowedPaths = []string{"v1/messages"} },
		"root path":            func(ep *Endpoint) { ep.AllowedPaths = []string{"/"} },
		"exact root path":      func(ep *Endpoint) { ep.AllowedPaths = []string{"/$"} },
		"trailing slash":       func(ep *Endpoint) { ep.AllowedPaths = []string{"/v1/messages/"} },
		"dot segment":          func(ep *Endpoint) { ep.AllowedPaths = []string{"/v1/../files"} },
		"inner dollar":         func(ep *Endpoint) { ep.AllowedPaths = []string{"/v1$/messages"} },
		"double dollar":        func(ep *Endpoint) { ep.AllowedPaths = []string{"/v1/messages$$"} },
		"unset credential env": func(ep *Endpoint) { ep.KeyEnv = "EGRESS_TEST_UNSET" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ep := valid()
			mutate(&ep)
			if err := ep.init(); err == nil {
				t.Errorf("init accepted %+v", &ep)
			}
		})
	}
	ep := valid()
	if err := ep.init(); err != nil {
		t.Fatalf("valid endpoint refused: %v", err)
	}
	ep = valid()
	ep.AllowedPaths = []string{"/v1/messages$", "/v1/models"}
	if err := ep.init(); err != nil {
		t.Fatalf("exact and subtree grants refused: %v", err)
	}
}

func TestLoadFiles(t *testing.T) {
	dir := t.TempDir()
	allowlist := filepath.Join(dir, "allow.txt")
	mustWrite(t, allowlist, "github.com\n")
	config := filepath.Join(dir, "config.json")

	t.Run("audit log goes to the configured file", func(t *testing.T) {
		auditLog := filepath.Join(dir, "audit.jsonl")
		mustWrite(t, config, fmt.Sprintf(`{"mode":"enforce","allowlistFile":%q,"auditLog":%q}`, allowlist, auditLog))
		p, cfg, err := load(config)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Listen != "127.0.0.1:0" {
			t.Errorf("listen = %q, want the 127.0.0.1:0 default", cfg.Listen)
		}
		p.log("connect", "example.com", 443, "", "deny")
		raw, err := os.ReadFile(auditLog)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"host":"example.com"`) {
			t.Errorf("audit log = %q, want the decision recorded", raw)
		}
	})

	failures := map[string]string{
		"missing config":    "",
		"unknown field":     fmt.Sprintf(`{"mode":"enforce","allowlistFile":%q,"typo":1}`, allowlist),
		"missing allowlist": fmt.Sprintf(`{"mode":"enforce","allowlistFile":%q}`, filepath.Join(dir, "nope")),
		"unwritable audit":  fmt.Sprintf(`{"mode":"enforce","allowlistFile":%q,"auditLog":%q}`, allowlist, filepath.Join(dir, "nope", "audit")),
	}
	for name, content := range failures {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, "missing.json")
			if content != "" {
				path = config
				mustWrite(t, path, content)
			}
			if _, _, err := load(path); err == nil {
				t.Error("load succeeded, want an error")
			}
		})
	}
}

func TestUnknownPathNamesTheEndpoints(t *testing.T) {
	ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{anthropicEndpoint(t, "https://api.anthropic.com")})
	status, body := get(t, ts.URL+"/elsewhere")
	if status != http.StatusNotFound || !strings.Contains(body, "/anthropic") {
		t.Errorf("unknown path = %d %q, want 404 naming /anthropic", status, body)
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"example.com:8443", "example.com", 8443},
		{"example.com", "example.com", 443},
		{"example.com:https", "example.com", 443},
		{"[::1]:22", "::1", 22},
	}
	for _, c := range cases {
		if h, p := splitHostPort(c.in, 443); h != c.host || p != c.port {
			t.Errorf("splitHostPort(%q) = %q, %d; want %q, %d", c.in, h, p, c.host, c.port)
		}
	}
}

// chainThrough points ts's tunnel leg at the proxy serving upstreamURL, the
// way HTTPS_PROXY in the host environment would.
func chainThrough(t *testing.T, ts *httptest.Server, upstreamURL string) {
	t.Helper()
	u, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := ts.Config.Handler.(*Proxy)
	if !ok {
		t.Fatal("test server is not serving a *Proxy")
	}
	p.upstreamProxy = http.ProxyURL(u)
}

func TestConnectChainsThroughUpstreamProxy(t *testing.T) {
	target := startEcho(t)

	t.Run("tunnel rides the upstream proxy", func(t *testing.T) {
		upstream, upstreamAudit := newTestProxy(t, "enforce", target+"\n", nil)
		ts, _ := newTestProxy(t, "enforce", target+"\n", nil)
		chainThrough(t, ts, upstream.URL)

		resp, conn, br := connectVia(t, ts.URL, target)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
		}
		if _, err := io.WriteString(conn, "ping\n"); err != nil {
			t.Fatal(err)
		}
		if line, err := br.ReadString('\n'); err != nil || line != "ping\n" {
			t.Fatalf("echo through chained tunnel = %q, %v", line, err)
		}
		if !strings.Contains(upstreamAudit.String(), `"decision":"allow"`) {
			t.Errorf("upstream proxy never saw the CONNECT: %s", upstreamAudit.String())
		}
	})

	t.Run("upstream refusal surfaces as 502", func(t *testing.T) {
		upstream, _ := newTestProxy(t, "enforce", "", nil) // allows nothing
		ts, _ := newTestProxy(t, "enforce", target+"\n", nil)
		chainThrough(t, ts, upstream.URL)

		resp, _, _ := connectVia(t, ts.URL, target)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("CONNECT status = %d, want 502 when the upstream proxy refuses", resp.StatusCode)
		}
	})

	t.Run("unreachable upstream surfaces as 502", func(t *testing.T) {
		ts, _ := newTestProxy(t, "enforce", target+"\n", nil)
		chainThrough(t, ts, "http://127.0.0.1:1")

		resp, _, _ := connectVia(t, ts.URL, target)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("CONNECT status = %d, want 502", resp.StatusCode)
		}
	})
}
