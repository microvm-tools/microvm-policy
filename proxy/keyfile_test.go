package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var keyFileNow = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

// keyFileEndpoint is an `authorization` endpoint whose credential is a file.
func keyFileEndpoint(t *testing.T, upstream, file string) *Endpoint {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	return &Endpoint{
		Prefix:       "/sign",
		Upstream:     upstream,
		Header:       "authorization",
		AllowedPaths: []string{"/service/sign"},
		KeyFile:      file,
		upstreamURL:  u,
		now:          func() time.Time { return keyFileNow },
	}
}

func credentialJSON(value string, expires time.Time) string {
	return fmt.Sprintf(`{"value":%q,"expires_at":%q}`, value, expires.Format(time.RFC3339))
}

// sendWithPlantedToken sends a request carrying a client-planted credential,
// which must never reach upstream.
func sendWithPlantedToken(t *testing.T, base string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/sign/service/sign", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer client-planted")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// A file credential is injected, and re-read: a refreshed token is used on
// the next request.
func TestKeyFileInjectsAndRereads(t *testing.T) {
	var got atomic.Value
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
	}))
	defer backend.Close()
	file := filepath.Join(t.TempDir(), "credential.json")
	mustWrite(t, file, credentialJSON("token-1", keyFileNow.Add(15*time.Minute)))
	ts, _ := newTestProxy(t, "enforce", "", []*Endpoint{keyFileEndpoint(t, backend.URL, file)})

	if code := sendWithPlantedToken(t, ts.URL); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if g, _ := got.Load().(string); g != "Bearer token-1" {
		t.Errorf("upstream got %q, want the file's token", g)
	}
	mustWrite(t, file, credentialJSON("token-2", keyFileNow.Add(15*time.Minute)))
	sendWithPlantedToken(t, ts.URL)
	if g, _ := got.Load().(string); g != "Bearer token-2" {
		t.Errorf("after the refresh upstream got %q, want token-2", g)
	}
}

// ⛔ Every way a file credential can be unusable refuses the request, in
// both modes, and nothing reaches upstream: not without a credential, and
// not with the client's planted one (passthrough).
func TestKeyFileRefusesWhenUnusable(t *testing.T) {
	for name, content := range map[string]string{
		"missing file":           "",
		"malformed":              "{not json",
		"empty value":            credentialJSON("", keyFileNow.Add(time.Hour)),
		"no expires_at":          `{"value":"token-1"}`,
		"expired":                credentialJSON("token-1", keyFileNow.Add(-time.Minute)),
		"inside the skew window": credentialJSON("token-1", keyFileNow.Add(keyFileSkew/2)),
	} {
		for _, mode := range []string{"enforce", "log"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				var reached atomic.Int32
				backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reached.Add(1)
				}))
				defer backend.Close()
				file := filepath.Join(t.TempDir(), "credential.json")
				if content != "" {
					mustWrite(t, file, content)
				}
				ts, audit := newTestProxy(t, mode, "", []*Endpoint{keyFileEndpoint(t, backend.URL, file)})
				if code := sendWithPlantedToken(t, ts.URL); code != http.StatusServiceUnavailable {
					t.Errorf("status %d, want 503", code)
				}
				if reached.Load() != 0 {
					t.Error("the request reached upstream")
				}
				if !strings.Contains(audit.String(), `"decision":"deny"`) {
					t.Errorf("no deny decision in the audit log: %s", audit.String())
				}
			})
		}
	}
}

func TestKeyFileInitRejects(t *testing.T) {
	base := func() Endpoint {
		return Endpoint{
			Prefix: "/sign", Upstream: "https://keys.example", Header: "authorization",
			AllowedPaths: []string{"/service/sign"}, KeyFile: "/run/credential.json",
		}
	}
	ep := base()
	if err := ep.init(); err != nil {
		t.Fatalf("a valid keyFile endpoint was refused: %v", err)
	}
	for name, mutate := range map[string]func(*Endpoint){
		"keyEnv and keyFile": func(ep *Endpoint) { ep.KeyEnv = "HOME" },
		"relative keyFile":   func(ep *Endpoint) { ep.KeyFile = "credential.json" },
	} {
		t.Run(name, func(t *testing.T) {
			ep := base()
			mutate(&ep)
			if err := ep.init(); err == nil {
				t.Errorf("init accepted %+v", &ep)
			}
		})
	}
}
