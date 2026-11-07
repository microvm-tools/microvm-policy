package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Budget caps what one proxy process — one session — may spend on an
// endpoint. Zero is no limit on that axis. Checked before a request goes
// upstream, so a request already in flight finishes: a session can overshoot
// maxTokens by what its concurrent requests return.
type Budget struct {
	// MaxRequests counts requests sent upstream: a loop of small calls.
	MaxRequests int64 `json:"maxRequests"`
	// MaxTokens counts tokens as the upstream reports them (Endpoint.Usage):
	// input, cache creation, cache reads and output, summed.
	MaxTokens int64 `json:"maxTokens"`
}

// Tokens is usage as an upstream reports it.
type Tokens struct {
	Input         int64 `json:"input"`
	CacheCreation int64 `json:"cacheCreation"`
	CacheRead     int64 `json:"cacheRead"`
	Output        int64 `json:"output"`
}

func (t Tokens) total() int64 { return t.Input + t.CacheCreation + t.CacheRead + t.Output }

func (t *Tokens) add(o Tokens) {
	t.Input += o.Input
	t.CacheCreation += o.CacheCreation
	t.CacheRead += o.CacheRead
	t.Output += o.Output
}

// meter is an endpoint's spend so far.
type meter struct {
	mu       sync.Mutex
	requests int64
	refused  int64
	tokens   Tokens
}

// spentLocked reports whether either limit is reached; meter.mu is held.
func (ep *Endpoint) spentLocked() bool {
	b, m := ep.Budget, &ep.meter
	return b != nil && ((b.MaxRequests > 0 && m.requests >= b.MaxRequests) ||
		(b.MaxTokens > 0 && m.tokens.total() >= b.MaxTokens))
}

// admit reserves one request against the budget, or refuses it.
func (ep *Endpoint) admit() bool {
	ep.meter.mu.Lock()
	defer ep.meter.mu.Unlock()
	if ep.spentLocked() {
		ep.meter.refused++
		return false
	}
	ep.meter.requests++
	return true
}

// unadmit returns a reservation for a request that never went upstream.
func (ep *Endpoint) unadmit() {
	ep.meter.mu.Lock()
	ep.meter.requests--
	ep.meter.mu.Unlock()
}

func (ep *Endpoint) charge(t Tokens) {
	ep.meter.mu.Lock()
	ep.meter.tokens.add(t)
	ep.meter.mu.Unlock()
}

// budgetMsg is what a refused request is told: legible to the agent acting
// on it, and final — the budget does not come back within the session.
func (ep *Endpoint) budgetMsg() string {
	b := ep.Budget
	var limits []string
	if b.MaxRequests > 0 {
		limits = append(limits, fmt.Sprintf("%d requests", b.MaxRequests))
	}
	if b.MaxTokens > 0 {
		limits = append(limits, fmt.Sprintf("%d tokens", b.MaxTokens))
	}
	return fmt.Sprintf("egress-proxy: %s: this session's API budget (%s) is spent — no further requests will be sent; finish with what you have",
		ep.Prefix, strings.Join(limits, ", "))
}

// --- the usage summary file ---

type usageEntry struct {
	Prefix    string  `json:"prefix"`
	Upstream  string  `json:"upstream"`
	Requests  int64   `json:"requests"`
	Refused   int64   `json:"refused"`
	Tokens    *Tokens `json:"tokens"` // null: the endpoint is not metered
	Budget    *Budget `json:"budget"`
	Exhausted bool    `json:"exhausted"`
}

// writeUsage replaces UsageFile with the spend so far: written whole to a
// temporary file beside it and renamed, so a reader never sees half of one.
func (p *Proxy) writeUsage() {
	if p.usageFile == "" {
		return
	}
	p.usageMu.Lock()
	defer p.usageMu.Unlock()
	entries := make([]usageEntry, 0, len(p.endpoints))
	for _, ep := range p.endpoints {
		ep.meter.mu.Lock()
		e := usageEntry{
			Prefix: ep.Prefix, Upstream: ep.Upstream,
			Requests: ep.meter.requests, Refused: ep.meter.refused,
			Budget: ep.Budget, Exhausted: ep.spentLocked(),
		}
		if ep.Usage != "" {
			t := ep.meter.tokens
			e.Tokens = &t
		}
		ep.meter.mu.Unlock()
		entries = append(entries, e)
	}
	raw, err := json.Marshal(map[string]any{"endpoints": entries})
	if err == nil {
		err = writeFileAtomic(p.usageFile, append(raw, '\n'))
	}
	if err != nil {
		// Nothing to fail: the request is already answered. Say so where
		// the launcher's journal sees it.
		fmt.Fprintln(os.Stderr, "egress-proxy: usage file:", err)
	}
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// --- reading usage out of responses ---

// usageParsers are the response formats a metered endpoint can name.
var usageParsers = map[string]func(contentType string) usageParser{
	"anthropic": newAnthropicUsage,
}

// usageParser sees a response body as it streams past (Write) and reports
// what it found when the body ends — or is cut short (result).
type usageParser interface {
	Write(p []byte) (int, error)
	result() Tokens
}

// sseLineMax bounds one buffered event line. Usage arrives in small events;
// a longer line (a large content delta) is skipped, not buffered.
const sseLineMax = 1 << 20

// jsonBodyMax bounds a buffered non-streaming body.
const jsonBodyMax = 32 << 20

// anthropicUsageJSON is the Messages API's usage object. In a stream,
// message_start carries the input side and message_delta the running
// output count; each field is cumulative, so the largest seen is the total.
type anthropicUsageJSON struct {
	Input         int64 `json:"input_tokens"`
	CacheCreation int64 `json:"cache_creation_input_tokens"`
	CacheRead     int64 `json:"cache_read_input_tokens"`
	Output        int64 `json:"output_tokens"`
}

type anthropicUsage struct {
	sse     bool
	line    []byte
	skip    bool // the current line outgrew sseLineMax
	body    bytes.Buffer
	tooBig  bool
	maxSeen Tokens
}

func newAnthropicUsage(contentType string) usageParser {
	return &anthropicUsage{sse: strings.HasPrefix(strings.ToLower(contentType), "text/event-stream")}
}

func (a *anthropicUsage) Write(p []byte) (int, error) {
	n := len(p)
	if !a.sse {
		if !a.tooBig {
			if a.body.Len()+len(p) > jsonBodyMax {
				a.tooBig = true
				a.body.Reset()
			} else {
				a.body.Write(p)
			}
		}
		return n, nil
	}
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		chunk := p
		if i >= 0 {
			chunk = p[:i]
		}
		if !a.skip {
			if len(a.line)+len(chunk) > sseLineMax {
				a.skip = true
				a.line = a.line[:0]
			} else {
				a.line = append(a.line, chunk...)
			}
		}
		if i < 0 {
			break
		}
		if !a.skip {
			a.event(a.line)
		}
		a.line, a.skip = a.line[:0], false
		p = p[i+1:]
	}
	return n, nil
}

func (a *anthropicUsage) event(line []byte) {
	data, ok := bytes.CutPrefix(bytes.TrimRight(line, "\r"), []byte("data:"))
	if !ok || !bytes.Contains(data, []byte(`"usage"`)) {
		return
	}
	var ev struct {
		Message *struct {
			Usage *anthropicUsageJSON `json:"usage"`
		} `json:"message"`
		Usage *anthropicUsageJSON `json:"usage"`
	}
	if json.Unmarshal(bytes.TrimSpace(data), &ev) != nil {
		return
	}
	if ev.Message != nil {
		a.see(ev.Message.Usage)
	}
	a.see(ev.Usage)
}

func (a *anthropicUsage) see(u *anthropicUsageJSON) {
	if u == nil {
		return
	}
	a.maxSeen.Input = max(a.maxSeen.Input, u.Input)
	a.maxSeen.CacheCreation = max(a.maxSeen.CacheCreation, u.CacheCreation)
	a.maxSeen.CacheRead = max(a.maxSeen.CacheRead, u.CacheRead)
	a.maxSeen.Output = max(a.maxSeen.Output, u.Output)
}

func (a *anthropicUsage) result() Tokens {
	if !a.sse && !a.tooBig && a.body.Len() > 0 {
		var body struct {
			Usage *anthropicUsageJSON `json:"usage"`
		}
		if json.Unmarshal(a.body.Bytes(), &body) == nil {
			a.see(body.Usage)
		}
	}
	return a.maxSeen
}

// initBudget checks an endpoint's usage format and budget at start.
func (ep *Endpoint) initBudget() error {
	if ep.Usage != "" {
		if _, ok := usageParsers[ep.Usage]; !ok {
			return fmt.Errorf("usage must be \"anthropic\" or empty, got %q", ep.Usage)
		}
	}
	b := ep.Budget
	if b == nil {
		return nil
	}
	if b.MaxRequests < 0 || b.MaxTokens < 0 {
		return errors.New("budget limits must not be negative")
	}
	if b.MaxRequests == 0 && b.MaxTokens == 0 {
		// A budget that limits nothing is a typo, not a choice.
		return errors.New("budget sets neither maxRequests nor maxTokens")
	}
	if b.MaxTokens > 0 && ep.Usage == "" {
		return errors.New("budget.maxTokens needs usage set: the proxy cannot count tokens it does not know how to read")
	}
	return nil
}
