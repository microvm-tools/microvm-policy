package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
)

type Proxy struct {
	mode      string // "enforce" or "log"
	allow     *Allowlist
	endpoints []*Endpoint
	audit     *slog.Logger
	transport http.RoundTripper
	// upstreamProxy picks the proxy the tunnel leg chains through (nil: dial
	// direct). Production uses http.ProxyFromEnvironment, which reads the
	// environment once per process, so tests inject their own.
	upstreamProxy func(*http.Request) (*url.URL, error)
	// usageFile receives each endpoint's spend (Config.UsageFile).
	usageFile string
	usageMu   sync.Mutex
}

// decide maps an allowlist verdict to this mode's action. Log mode is the
// shadow rung: the denial is recorded, nothing is blocked.
func (p *Proxy) decide(allowed bool) string {
	if allowed {
		return "allow"
	}
	if p.mode == "log" {
		return "would_deny"
	}
	return "deny"
}

func (p *Proxy) log(kind, host string, port int, pathStr, decision string) {
	p.audit.LogAttrs(context.Background(), slog.LevelInfo, "decision",
		slog.String("kind", kind),
		slog.String("host", host),
		slog.Int("port", port),
		slog.String("path", pathStr),
		slog.String("decision", decision),
		slog.String("mode", p.mode),
	)
}

// Rule 2 of the policy track: every denial is loud, actionable, and legible
// to whatever reads it — a person or an agent acting on the error.
func denyMsg(what, host string) string {
	return fmt.Sprintf("egress-proxy: %s denied: %s is not in the allowlist — add a line to the allowlist file or EGRESS_ALLOW=%s, or launch with EGRESS_POLICY=open", what, host, host)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	// Absolute-form means the client is using us as its HTTP proxy for a
	// plain-http URL. Origin-form means a BASE_URL pointed directly here —
	// the deployment sets NO_PROXY for the proxy's own address, so endpoint
	// traffic never arrives absolute-form.
	if r.URL.IsAbs() {
		p.serveForwardHTTP(w, r)
		return
	}
	for _, ep := range p.endpoints {
		if r.URL.Path == ep.Prefix || strings.HasPrefix(r.URL.Path, ep.Prefix+"/") {
			p.serveEndpoint(ep, w, r)
			return
		}
	}
	prefixes := make([]string, len(p.endpoints))
	for i, ep := range p.endpoints {
		prefixes[i] = ep.Prefix
	}
	http.Error(w, "egress-proxy: unknown path "+r.URL.Path+" — reverse-proxied endpoints are "+strings.Join(prefixes, ", "), http.StatusNotFound)
}

// --- opaque CONNECT tunnel, never decrypted ---

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.Host, 443)
	decision := p.decide(p.allow.Allowed(host, port))
	p.log("connect", host, port, "", decision)
	if decision == "deny" {
		http.Error(w, denyMsg("CONNECT "+r.Host, host), http.StatusForbidden)
		return
	}
	upstream, err := p.dialContext(r.Context(), host, port)
	if err != nil {
		http.Error(w, "egress-proxy: cannot reach "+r.Host+": "+err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "egress-proxy: connection cannot be hijacked", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	_, err = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err == nil {
		err = buf.Flush()
	}
	if err != nil {
		// The client hung up before the tunnel opened.
		_ = upstream.Close()
		_ = client.Close()
		return
	}
	// Copy errors only mean one side hung up; either way the tunnel is over,
	// and closing both ends is all there is to do.
	go func() {
		// buf's read side drains bytes the client sent early, then the conn.
		_, _ = io.Copy(upstream, buf)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
}

// dialContext opens the raw tunnel leg, chaining through the host's own
// proxy environment when one is set, so corporate upstream proxies work.
func (p *Proxy) dialContext(ctx context.Context, host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	paddr := p.upstreamProxyAddr(addr)
	if paddr == "" {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("direct: %w", err)
		}
		return conn, nil
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", paddr)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %s: %w", paddr, err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream proxy %s: %w", paddr, err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream proxy %s: %w", paddr, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream proxy %s refused CONNECT %s: %s", paddr, addr, resp.Status)
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}

// upstreamProxyAddr is the host:port of the proxy a tunnel to addr chains
// through, or "" to dial direct.
func (p *Proxy) upstreamProxyAddr(addr string) string {
	if p.upstreamProxy == nil {
		return ""
	}
	proxyURL, err := p.upstreamProxy(&http.Request{URL: &url.URL{Scheme: "https", Host: addr}})
	if err != nil || proxyURL == nil {
		return ""
	}
	if proxyURL.Port() != "" {
		return proxyURL.Host
	}
	port := "80"
	if proxyURL.Scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(proxyURL.Hostname(), port)
}

// bufferedConn keeps bytes the upstream proxy's reader buffered past its
// CONNECT response from being lost.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b) //nolint:wrapcheck // io.Reader contract: io.EOF must arrive unwrapped
}

// --- reverse-proxied LLM endpoints ---

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Te",
	"Trailer", "Transfer-Encoding", "Upgrade",
}

// Client-supplied credentials never pass through: in Anthropic's containment
// disclosure an attacker planted a key in the workspace and rode out over an
// allowed host. Strip everything credential-shaped, then inject our own.
var credentialHeaders = []string{
	"Authorization", "X-Api-Key", "Proxy-Authorization", "Cookie",
}

func (p *Proxy) serveEndpoint(ep *Endpoint, w http.ResponseWriter, r *http.Request) {
	// path.Clean defeats /../ hops out of the allowed subtree; the server
	// hands us the path decoded, so encoded dots are already visible here.
	rest := path.Clean("/" + strings.TrimPrefix(r.URL.Path, ep.Prefix))
	decision := p.decide(pathAllowed(ep.AllowedPaths, rest))
	// The budget, once the path is granted: a request it refuses never goes
	// upstream. One it admits is reserved now, so concurrent requests cannot
	// all pass on the same last unit.
	if decision != "deny" && !ep.admit() {
		decision = "over_budget"
	}
	p.log("api", ep.upstreamURL.Host, 0, rest, decision)
	switch decision {
	case "deny":
		http.Error(w, fmt.Sprintf(
			"egress-proxy: %s %s denied: allowed paths on %s are %s — the path allowlist is a capability grant; extend the proxy config if this endpoint is genuinely needed",
			r.Method, rest, ep.upstreamURL.Host, strings.Join(ep.AllowedPaths, ", ")),
			http.StatusForbidden)
		return
	case "over_budget":
		// 403, not 429: API clients retry a 429, and this does not come back.
		p.writeUsage()
		http.Error(w, ep.budgetMsg(), http.StatusForbidden)
		return
	}
	out := r.Clone(r.Context())
	out.URL = &url.URL{
		Scheme:   ep.upstreamURL.Scheme,
		Host:     ep.upstreamURL.Host,
		Path:     rest,
		RawQuery: r.URL.RawQuery,
	}
	out.Host = ep.upstreamURL.Host
	out.RequestURI = "" // outgoing requests must not carry the server form
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	// Proxy-directed auth never travels upstream in either mode.
	out.Header.Del("Proxy-Authorization")
	if err := ep.injectCredential(out); err != nil {
		// ⛔ Refused in BOTH modes, and never sent on without a credential:
		// with no usable file there is nothing to inject, and falling through
		// to passthrough would carry the client's own token instead. It never
		// went upstream, so it spends nothing.
		ep.unadmit()
		p.log("api", ep.upstreamURL.Host, 0, rest, "deny")
		http.Error(w, fmt.Sprintf("egress-proxy: %s: credential unavailable: %v", ep.Prefix, err), http.StatusServiceUnavailable)
		return
	}
	p.forwardMetered(ep, w, out)
}

// injectCredential replaces the client's credentials with the endpoint's
// own: the key from keyEnv, or the one keyFile holds now. With no key held
// (OAuth mode) the client's own token passes through: the path allowlist
// still applies, but a planted credential cannot be stripped when the
// legitimate one travels in the same header. API-key mode gets the full
// guarantee; say so rather than imply otherwise.
func (ep *Endpoint) injectCredential(out *http.Request) error {
	key := ep.key
	if ep.KeyFile != "" {
		k, err := ep.fileKey()
		if err != nil {
			return err
		}
		key = k
	}
	if key == "" {
		return nil
	}
	for _, h := range credentialHeaders {
		out.Header.Del(h)
	}
	if ep.Header == "authorization" {
		out.Header.Set("Authorization", "Bearer "+key)
	} else {
		out.Header.Set(ep.Header, key) // Set canonicalises the name
	}
	return nil
}

// forwardMetered sends an admitted request upstream and, for an endpoint
// with a usage format, charges what the response reports.
func (p *Proxy) forwardMetered(ep *Endpoint, w http.ResponseWriter, out *http.Request) {
	defer p.writeUsage()
	if ep.Usage == "" {
		p.roundTrip(w, out, nil)
		return
	}
	// Usage is read from the body as it passes, so it must arrive as text.
	// Without the client's Accept-Encoding the transport asks for gzip
	// itself and hands on the body decompressed.
	out.Header.Del("Accept-Encoding")
	var parser usageParser
	p.roundTrip(w, out, func(resp *http.Response) io.Writer {
		parser = usageParsers[ep.Usage](resp.Header.Get("Content-Type"))
		return parser
	})
	if parser != nil {
		// Charged even when the copy was cut short: what streamed was spent.
		ep.charge(parser.result())
	}
}

// pathAllowed grants "/v1/messages" and everything below it, but
// "/v1/messages$" only that exact path: a subtree can hold endpoints the
// grant never meant, such as /v1/messages/batches, which stores results
// for later retrieval.
func pathAllowed(allowed []string, rest string) bool {
	for _, a := range allowed {
		if exact, ok := strings.CutSuffix(a, "$"); ok {
			if rest == exact {
				return true
			}
			continue
		}
		if rest == a || strings.HasPrefix(rest, a+"/") {
			return true
		}
	}
	return false
}

// --- plain-HTTP forward proxying (absolute-form requests) ---

func (p *Proxy) serveForwardHTTP(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.URL.Host, 80)
	decision := p.decide(p.allow.Allowed(host, port))
	p.log("http", host, port, r.URL.Path, decision)
	if decision == "deny" {
		http.Error(w, denyMsg(r.Method+" "+r.URL.String(), host), http.StatusForbidden)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	// No credential handling here: like the CONNECT tunnel, third-party
	// traffic passes untouched — the proxy manages credentials only for the
	// endpoints it owns.
	p.roundTrip(w, out, nil)
}

// roundTrip sends out and streams the response back. tap, when set, names a
// writer that sees the response body too, as it passes.
func (p *Proxy) roundTrip(w http.ResponseWriter, out *http.Request, tap func(*http.Response) io.Writer) {
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "egress-proxy: upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	hdr := w.Header()
	for k, vv := range resp.Header {
		for _, v := range vv {
			hdr.Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// The Claude API streams SSE: hand chunks on as they arrive. A copy error
	// mid-stream means the client or upstream went away after the status was
	// sent; there is no way left to report it.
	var body io.Reader = resp.Body
	if tap != nil {
		body = io.TeeReader(resp.Body, tap(resp))
	}
	_, _ = io.Copy(&flushWriter{w: w}, body)
}

type flushWriter struct{ w http.ResponseWriter }

func (f *flushWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err //nolint:wrapcheck // io.Writer passthrough: io.Copy inspects the error as-is
}

func splitHostPort(hostport string, def int) (string, int) {
	h, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, def
	}
	n, err := strconv.Atoi(ps)
	if err != nil {
		return h, def
	}
	return h, n
}
