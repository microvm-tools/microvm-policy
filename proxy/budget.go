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

// meter is an endpoint's spend so far. unknown counts successful metered
// responses whose usage could not be read: under a token budget one is
// enough to end the session, since what it spent is not known.
type meter struct {
	mu       sync.Mutex
	requests int64
	refused  int64
	unknown  int64
	tokens   Tokens
}

// spentLocked reports whether either limit is reached; meter.mu is held.
func (ep *Endpoint) spentLocked() bool {
	b, m := ep.Budget, &ep.meter
	return b != nil && ((b.MaxRequests > 0 && m.requests >= b.MaxRequests) ||
		(b.MaxTokens > 0 && (m.tokens.total() >= b.MaxTokens || m.unknown > 0)))
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

// refuse counts a request turned away without being admitted.
func (ep *Endpoint) refuse() {
	ep.meter.mu.Lock()
	ep.meter.refused++
	ep.meter.mu.Unlock()
}

// charge adds what a response reported — or, when its usage could not be
// read (ok false), counts it as unknown.
func (ep *Endpoint) charge(t Tokens, ok bool) {
	ep.meter.mu.Lock()
	ep.meter.tokens.add(t)
	if !ok {
		ep.meter.unknown++
	}
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
	ep.meter.mu.Lock()
	unknown := ep.meter.unknown
	ep.meter.mu.Unlock()
	if b.MaxTokens > 0 && unknown > 0 {
		return fmt.Sprintf("egress-proxy: %s: the usage of an earlier response could not be read, so this session's API budget (%s) can no longer be kept — no further requests will be sent; finish with what you have",
			ep.Prefix, strings.Join(limits, ", "))
	}
	return fmt.Sprintf("egress-proxy: %s: this session's API budget (%s) is spent — no further requests will be sent; finish with what you have",
		ep.Prefix, strings.Join(limits, ", "))
}

// unmeterableMsg is what a request is told when a token budget is set and
// the proxy cannot read what the request costs: a batch, billed later.
func (ep *Endpoint) unmeterableMsg(rest string) string {
	return fmt.Sprintf("egress-proxy: %s %s: refused under this session's token budget — the proxy cannot read what it costs (it reads %s)",
		ep.Prefix, rest, usageFormats[ep.Usage].metered)
}

// budgetDecision applies the budget to a request its path grant let
// through: refused, the decision is over_budget and refusal says why.
// Admitted, the request is reserved now, so concurrent requests cannot all
// pass on the same last unit.
func (ep *Endpoint) budgetDecision(rest, decision string) (string, string) {
	if decision == "deny" {
		return decision, ""
	}
	if ep.Budget != nil && ep.Budget.MaxTokens > 0 && ep.pathClass(rest) == pathUnmeterable {
		ep.refuse()
		return "over_budget", ep.unmeterableMsg(rest)
	}
	if !ep.admit() {
		return "over_budget", ep.budgetMsg()
	}
	return decision, ""
}

// --- the usage summary file ---

type usageEntry struct {
	Prefix   string  `json:"prefix"`
	Upstream string  `json:"upstream"`
	Requests int64   `json:"requests"`
	Refused  int64   `json:"refused"`
	Tokens   *Tokens `json:"tokens"` // null: the endpoint is not metered
	// Unknown counts successful responses whose usage could not be read.
	Unknown   int64   `json:"unknownUsage"`
	Budget    *Budget `json:"budget"`
	Exhausted bool    `json:"exhausted"`
}

// writeUsage replaces UsageFile with the spend so far: written whole to a
// temporary file beside it and renamed, so a reader never sees half of one.
func (p *Proxy) writeUsage() {
	if err := p.saveUsage(); err != nil {
		// Nothing to fail: the request is already answered. Say so where
		// the launcher's journal sees it.
		fmt.Fprintln(os.Stderr, "egress-proxy: usage file:", err)
	}
}

// saveUsage is writeUsage, reporting a failure: at start it is fatal.
func (p *Proxy) saveUsage() error {
	if p.usageFile == "" {
		return nil
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
			e.Unknown = ep.meter.unknown
		}
		ep.meter.mu.Unlock()
		entries = append(entries, e)
	}
	raw, err := json.Marshal(map[string]any{"endpoints": entries})
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	return writeFileAtomic(p.usageFile, append(raw, '\n'))
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

// pathClass is what a path under a metered endpoint costs, as far as the
// proxy can tell.
type pathClass int

const (
	// pathUnmeterable costs tokens the proxy cannot read (a batch, billed
	// when it runs): refused under a token budget.
	pathUnmeterable pathClass = iota
	// pathMetered reports its usage in the response.
	pathMetered
	// pathFree costs no tokens.
	pathFree
)

// usageFormat is a response format a metered endpoint can name: how to read
// usage out of a response, and which paths report it.
type usageFormat struct {
	parser   func(contentType string) usageParser
	classify func(path string) pathClass
	metered  string // the metered paths, for messages
}

var usageFormats = map[string]usageFormat{
	"anthropic": {parser: newAnthropicUsage, classify: anthropicPathClass, metered: "/v1/messages and /v1/messages/count_tokens"},
}

// anthropicPathClass: the Messages API reports usage in each response, and
// token counting is free. Everything else under a /v1/messages grant — the
// batches — is billed later, out of the proxy's sight.
func anthropicPathClass(p string) pathClass {
	switch p {
	case "/v1/messages":
		return pathMetered
	case "/v1/messages/count_tokens":
		return pathFree
	}
	return pathUnmeterable
}

// pathClass for an endpoint without a usage format: nothing is metered, and
// nothing needs to be.
func (ep *Endpoint) pathClass(rest string) pathClass {
	if ep.Usage == "" {
		return pathFree
	}
	return usageFormats[ep.Usage].classify(rest)
}

// usageParser sees a response body as it streams past (Write) and reports
// what it found when the body ends — or is cut short (result): the tokens,
// and whether any usage was seen at all.
type usageParser interface {
	Write(p []byte) (int, error)
	result() (Tokens, bool)
}

// sseLineMax bounds one buffered event line, and one event's data. Usage
// arrives in small events; a longer one (a large content delta) is skipped,
// not buffered.
const sseLineMax = 1 << 20

// jsonBodyMax bounds a buffered non-streaming body. One past it is not read:
// its usage is unknown.
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
	sse      bool
	line     []byte
	lineSkip bool   // the current line outgrew sseLineMax
	data     []byte // the current event's data lines, joined by "\n"
	hasData  bool
	dataSkip bool // the current event outgrew sseLineMax
	body     bytes.Buffer
	tooBig   bool
	maxSeen  Tokens
	seen     bool
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
		if !a.lineSkip {
			if len(a.line)+len(chunk) > sseLineMax {
				a.lineSkip = true
				a.line = a.line[:0]
			} else {
				a.line = append(a.line, chunk...)
			}
		}
		if i < 0 {
			break
		}
		a.endLine()
		p = p[i+1:]
	}
	return n, nil
}

// endLine takes one complete line. A skipped line spoils its event.
func (a *anthropicUsage) endLine() {
	if a.lineSkip {
		a.dataSkip = true
	} else {
		a.field(a.line)
	}
	a.line, a.lineSkip = a.line[:0], false
}

// field reads one line of an event: data lines are gathered, as the event
// stream format joins them, and a blank line ends the event. Other fields
// (event:, id:, comments) carry nothing to count.
func (a *anthropicUsage) field(line []byte) {
	line = bytes.TrimRight(line, "\r")
	if len(line) == 0 {
		a.dispatch()
		return
	}
	v, ok := bytes.CutPrefix(line, []byte("data:"))
	if !ok || a.dataSkip {
		return
	}
	v = bytes.TrimPrefix(v, []byte(" "))
	extra := len(v)
	if a.hasData {
		extra++
	}
	if len(a.data)+extra > sseLineMax {
		a.dataSkip = true
		a.data = a.data[:0]
		return
	}
	if a.hasData {
		a.data = append(a.data, '\n')
	}
	a.data = append(a.data, v...)
	a.hasData = true
}

func (a *anthropicUsage) dispatch() {
	if a.hasData && !a.dataSkip {
		a.event(a.data)
	}
	a.data, a.hasData, a.dataSkip = a.data[:0], false, false
}

func (a *anthropicUsage) event(data []byte) {
	if !bytes.Contains(data, []byte(`"usage"`)) {
		return
	}
	var ev struct {
		Message *struct {
			Usage *anthropicUsageJSON `json:"usage"`
		} `json:"message"`
		Usage *anthropicUsageJSON `json:"usage"`
	}
	if json.Unmarshal(data, &ev) != nil {
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
	a.seen = true
	a.maxSeen.Input = max(a.maxSeen.Input, u.Input)
	a.maxSeen.CacheCreation = max(a.maxSeen.CacheCreation, u.CacheCreation)
	a.maxSeen.CacheRead = max(a.maxSeen.CacheRead, u.CacheRead)
	a.maxSeen.Output = max(a.maxSeen.Output, u.Output)
}

func (a *anthropicUsage) result() (Tokens, bool) {
	if a.sse {
		// A stream that ends without its final newline or blank line still
		// had its last event.
		if len(a.line) > 0 || a.lineSkip {
			a.endLine()
		}
		a.dispatch()
	} else if !a.tooBig && a.body.Len() > 0 {
		var body struct {
			Usage *anthropicUsageJSON `json:"usage"`
		}
		if json.Unmarshal(a.body.Bytes(), &body) == nil {
			a.see(body.Usage)
		}
	}
	return a.maxSeen, a.seen
}

// initBudget checks an endpoint's usage format and budget at start.
func (ep *Endpoint) initBudget() error {
	if ep.Usage != "" {
		if _, ok := usageFormats[ep.Usage]; !ok {
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
