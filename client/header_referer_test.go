package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// A Referer given in Request.Headers goes out on the wire, because caller
// headers are applied after the Referer field, but Sec-Fetch-Site and the CORS
// Origin used to be worked out from the field alone. A navigation then sent the
// page as its Referer beside Sec-Fetch-Site: none, a CORS request sent
// cross-site with the target's own origin as its Origin, and a no-cors request
// sent cross-site. httpcloak.Client has no Referer field, so every Referer its
// callers set took that path.
//
// Chromium, Gecko and WebKit derive Sec-Fetch-Site and Origin from the
// initiating document, the same document the Referer names. In the Chrome 156
// and Firefox 159 captures of 2026-10-28 no request paired Sec-Fetch-Site: none
// with a Referer, and every CORS Origin outside a tainted redirect hop was the
// Referer's origin. The tests assert what the receiving server saw.

// headerRefererSeen is one request as the server received it.
type headerRefererSeen struct {
	proto, referer, site, mode, origin string
	hasOrigin                          bool
}

// headerRefererServer serves HTTP/1.1 and HTTP/2 and records the last request.
// The client reaches it as api.example.test, so a Referer on www.example.test
// is same-site and one on www.elsewhere.test cross-site.
type headerRefererServer struct {
	target string // https://api.example.test:port

	mu   sync.Mutex
	seen headerRefererSeen
}

func newHeaderRefererServer(t *testing.T) *headerRefererServer {
	t.Helper()
	s := &headerRefererServer{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hasOrigin := r.Header["Origin"]
		s.mu.Lock()
		s.seen = headerRefererSeen{
			proto:     r.Proto,
			referer:   r.Header.Get("Referer"),
			site:      r.Header.Get("Sec-Fetch-Site"),
			mode:      r.Header.Get("Sec-Fetch-Mode"),
			origin:    r.Header.Get("Origin"),
			hasOrigin: hasOrigin,
		}
		s.mu.Unlock()
		io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	s.target = "https://api.example.test:" + u.Port()
	return s
}

// send sends req through c and returns it as the server saw it, failing the
// test unless it arrived over proto. Every call needs a fresh req, because Do
// writes the headers it sent back into req.Headers.
func (s *headerRefererServer) send(t *testing.T, c *Client, req *Request, proto string) headerRefererSeen {
	t.Helper()
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	got := s.seen
	s.mu.Unlock()
	if got.proto != proto {
		t.Fatalf("server saw %s, want %s", got.proto, proto)
	}
	return got
}

// forEachHeaderRefererClient runs fn in a subtest for each preset the fix was
// checked against, over HTTP/1.1 and HTTP/2.
func forEachHeaderRefererClient(t *testing.T, fn func(t *testing.T, c *Client, proto string)) {
	protocols := []struct {
		name  string
		opt   Option
		proto string // as the server reports it
	}{
		{"h1", WithForceHTTP1(), "HTTP/1.1"},
		{"h2", WithForceHTTP2(), "HTTP/2.0"},
	}
	for _, preset := range []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"} {
		for _, p := range protocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				c := NewClient(preset, p.opt, WithInsecureSkipVerify(), WithPreferIPv4(),
					WithConnectTo("api.example.test", "127.0.0.1"), WithTimeout(10*time.Second))
				defer c.Close()
				fn(t, c, p.proto)
			})
		}
	}
}

var headerRefererModes = []struct {
	name string // the Sec-Fetch-Mode it sends
	mode FetchMode
	dest string
}{
	{"navigate", FetchModeNavigate, ""},
	{"cors", FetchModeCORS, ""},
	{"no-cors", FetchModeNoCors, "script"},
}

// checkHeaderRefererOrigin fails unless a CORS request's Origin is the
// Referer's origin and a navigation or no-cors GET sends none. Whether a
// same-origin CORS GET should send an Origin at all is a separate question, so
// it may go either way here.
func checkHeaderRefererOrigin(t *testing.T, mode FetchMode, site, wantOrigin string, got headerRefererSeen) {
	t.Helper()
	switch {
	case mode != FetchModeCORS && got.hasOrigin:
		t.Errorf("Origin = %q, want none", got.origin)
	case mode == FetchModeCORS && got.hasOrigin && got.origin != wantOrigin:
		t.Errorf("Origin = %q, want the Referer's origin %q", got.origin, wantOrigin)
	case mode == FetchModeCORS && !got.hasOrigin && site != "same-origin":
		t.Errorf("no Origin on a %s CORS request, want %q", site, wantOrigin)
	}
}

// TestClientHeaderRefererSetsSiteAndOrigin sends the same Referer in the field,
// in Headers as "Referer" and in Headers as "referer", and expects the same
// Sec-Fetch-Site and Origin from all three.
func TestClientHeaderRefererSetsSiteAndOrigin(t *testing.T) {
	s := newHeaderRefererServer(t)
	relations := []struct {
		site, referer, origin string
	}{
		{"same-origin", s.target + "/page", s.target},
		{"same-site", "https://www.example.test/page", "https://www.example.test"},
		{"cross-site", "https://www.elsewhere.test/page", "https://www.elsewhere.test"},
	}
	sources := []struct {
		name string
		set  func(req *Request, referer string)
	}{
		{"field", func(req *Request, referer string) { req.Referer = referer }},
		{"header", func(req *Request, referer string) { req.Headers = map[string][]string{"Referer": {referer}} }},
		{"lowercase header", func(req *Request, referer string) { req.Headers = map[string][]string{"referer": {referer}} }},
	}
	forEachHeaderRefererClient(t, func(t *testing.T, c *Client, proto string) {
		for _, m := range headerRefererModes {
			for _, rel := range relations {
				for _, src := range sources {
					t.Run(m.name+"/"+rel.site+"/"+src.name, func(t *testing.T) {
						req := &Request{URL: s.target + "/x", FetchMode: m.mode, FetchDest: m.dest}
						src.set(req, rel.referer)
						got := s.send(t, c, req, proto)
						if got.referer != rel.referer {
							t.Fatalf("Referer = %q, want %q", got.referer, rel.referer)
						}
						if got.mode != m.name {
							t.Fatalf("Sec-Fetch-Mode = %q, want %q", got.mode, m.name)
						}
						if got.site != rel.site {
							t.Errorf("Sec-Fetch-Site = %q, want %q", got.site, rel.site)
						}
						checkHeaderRefererOrigin(t, m.mode, rel.site, rel.origin, got)
					})
				}
			}
		}
	})
}

// TestClientHeaderRefererWinsOverField gives the field and Headers different
// Referers. The header's goes out, so Sec-Fetch-Site and Origin follow it, an
// empty one included: that request carries no Referer to derive them from.
func TestClientHeaderRefererWinsOverField(t *testing.T) {
	s := newHeaderRefererServer(t)
	page := s.target + "/page"
	forEachHeaderRefererClient(t, func(t *testing.T, c *Client, proto string) {
		for _, m := range headerRefererModes {
			t.Run(m.name+"/cross-site header over same-origin field", func(t *testing.T) {
				req := &Request{URL: s.target + "/x", FetchMode: m.mode, FetchDest: m.dest, Referer: page,
					Headers: map[string][]string{"Referer": {"https://www.elsewhere.test/page"}}}
				got := s.send(t, c, req, proto)
				if got.referer != "https://www.elsewhere.test/page" {
					t.Fatalf("Referer = %q, want the header's", got.referer)
				}
				if got.site != "cross-site" {
					t.Errorf("Sec-Fetch-Site = %q, want cross-site", got.site)
				}
				checkHeaderRefererOrigin(t, m.mode, "cross-site", "https://www.elsewhere.test", got)
			})
		}

		// A navigation with no Referer is a typed one. CORS and no-cors have
		// no such reading, so their default for a request with none is left
		// alone here.
		t.Run("navigate/empty header over same-origin field", func(t *testing.T) {
			req := &Request{URL: s.target + "/x", Referer: page, Headers: map[string][]string{"Referer": {""}}}
			got := s.send(t, c, req, proto)
			if got.referer != "" {
				t.Fatalf("Referer = %q, want the header's empty one", got.referer)
			}
			if got.site != "none" {
				t.Errorf("Sec-Fetch-Site = %q, want none", got.site)
			}
		})
	})
}
