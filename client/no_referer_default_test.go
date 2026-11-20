package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// A CORS request that named no page, with no Referer and no Origin from the
// caller, went out cross-site with the target's own origin as its Origin. No
// browser sends that pair: an Origin equal to the target's makes the request
// same-origin. Go 1.25+'s http.CrossOriginProtection refuses a request other
// than GET, HEAD or OPTIONS unless it is same-origin, so every Referer-less
// JSON POST got a 403.
//
// Chrome 156 and Firefox 159 were captured on 2026-10-28 sending fetch() and
// XHR requests from a page served with Referrer-Policy: no-referrer, and with
// fetch()'s referrerPolicy option. They sent the Sec-Fetch-Site and Origin of
// the default policy, only without the Referer. To their own origin that was
// same-origin, with no Origin on a GET or HEAD and their origin on a POST.
// With no page named, the client now takes the target's origin for the page
// and sends exactly that. It takes the page from a caller's Origin when there
// is no Referer, and from a Referer in Headers as well as the field. The
// server here runs CrossOriginProtection and records each request before it.

// noPageSeen is one request as the server received it.
type noPageSeen struct {
	proto, site, mode, origin string
	hasOrigin                 bool
}

// noPageServer serves HTTP/1.1 and HTTP/2 behind CrossOriginProtection and
// records the last request. The client reaches it as api.example.test, so
// www.example.test is same-site and www.elsewhere.test cross-site.
type noPageServer struct {
	target string // https://api.example.test:port

	mu   sync.Mutex
	seen noPageSeen
}

func newNoPageServer(t *testing.T) *noPageServer {
	t.Helper()
	s := &noPageServer{}
	app := http.NewCrossOriginProtection().Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hasOrigin := r.Header["Origin"]
		s.mu.Lock()
		s.seen = noPageSeen{
			proto:     r.Proto,
			site:      r.Header.Get("Sec-Fetch-Site"),
			mode:      r.Header.Get("Sec-Fetch-Mode"),
			origin:    r.Header.Get("Origin"),
			hasOrigin: hasOrigin,
		}
		s.mu.Unlock()
		app.ServeHTTP(w, r)
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

// send sends req through c and returns it as the server saw it, with the
// status CrossOriginProtection let through, failing the test unless it arrived
// over proto. Every call needs a fresh req, because Do writes the headers it
// sent back into req.Headers.
func (s *noPageServer) send(t *testing.T, c *Client, req *Request, proto string) (noPageSeen, int) {
	t.Helper()
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	got := s.seen
	s.mu.Unlock()
	if got.proto != proto {
		t.Fatalf("server saw %s, want %s", got.proto, proto)
	}
	return got, resp.StatusCode
}

// forEachNoPageClient runs fn in a subtest for each preset the change was
// checked against, over HTTP/1.1 and HTTP/2.
func forEachNoPageClient(t *testing.T, fn func(t *testing.T, c *Client, proto string)) {
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

// TestClientNoPageCORSIsSameOrigin sends CORS requests that name no page, set
// as such and sniffed from the request's shape, and expects what Chrome and
// Firefox sent to their own origin with no Referer.
func TestClientNoPageCORSIsSameOrigin(t *testing.T) {
	s := newNoPageServer(t)
	cases := []struct {
		name    string
		method  string
		mode    FetchMode
		headers func() map[string][]string
		body    string
		origin  bool // whether Origin goes out, as the target's own
	}{
		{"fetch GET", "GET", FetchModeCORS, nil, "", false},
		{"fetch HEAD", "HEAD", FetchModeCORS, nil, "", false},
		{"fetch POST", "POST", FetchModeCORS, func() map[string][]string {
			return map[string][]string{"Content-Type": {"application/json"}}
		}, `{"a":1}`, true},
		{"JSON POST sniffed as cors", "POST", FetchModeNavigate, func() map[string][]string {
			return map[string][]string{"Content-Type": {"application/json"}}
		}, `{"a":1}`, true},
		{"JSON GET sniffed as cors", "GET", FetchModeNavigate, func() map[string][]string {
			return map[string][]string{"Accept": {"application/json"}}
		}, "", false},
	}
	forEachNoPageClient(t, func(t *testing.T, c *Client, proto string) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				req := &Request{Method: tc.method, URL: s.target + "/x", FetchMode: tc.mode}
				if tc.headers != nil {
					req.Headers = tc.headers()
				}
				if tc.body != "" {
					req.Body = strings.NewReader(tc.body)
				}
				got, status := s.send(t, c, req, proto)
				if got.mode != "cors" {
					t.Fatalf("Sec-Fetch-Mode = %q, want cors", got.mode)
				}
				if got.site != "same-origin" {
					t.Errorf("Sec-Fetch-Site = %q, want same-origin", got.site)
				}
				switch {
				case tc.origin && got.origin != s.target:
					t.Errorf("Origin = %q (sent %v), want the target's %q", got.origin, got.hasOrigin, s.target)
				case !tc.origin && got.hasOrigin:
					t.Errorf("Origin = %q, want none on a same-origin %s", got.origin, tc.method)
				}
				if status != http.StatusOK {
					t.Errorf("CrossOriginProtection answered %d, want 200", status)
				}
			})
		}
	})
}

// TestClientCallerOriginNamesThePage gives no Referer but an Origin, which
// then names the page in every mode, and goes out as the caller set it.
func TestClientCallerOriginNamesThePage(t *testing.T) {
	s := newNoPageServer(t)
	origins := []struct {
		name, origin, site string
	}{
		{"own origin", s.target, "same-origin"},
		{"same-site", "https://www.example.test", "same-site"},
		{"cross-site", "https://www.elsewhere.test", "cross-site"},
		// An opaque origin, as a sandboxed frame sends, is cross-site to
		// every URL.
		{"opaque", "null", "cross-site"},
	}
	modes := []struct {
		name string // the Sec-Fetch-Mode it sends
		mode FetchMode
		dest string
	}{
		{"navigate", FetchModeNavigate, ""},
		{"cors", FetchModeCORS, ""},
		{"no-cors", FetchModeNoCors, "script"},
	}
	forEachNoPageClient(t, func(t *testing.T, c *Client, proto string) {
		for _, m := range modes {
			for _, o := range origins {
				t.Run(m.name+"/"+o.name, func(t *testing.T) {
					req := &Request{URL: s.target + "/x", FetchMode: m.mode, FetchDest: m.dest,
						Headers: map[string][]string{"Origin": {o.origin}}}
					got, _ := s.send(t, c, req, proto)
					if got.mode != m.name {
						t.Fatalf("Sec-Fetch-Mode = %q, want %q", got.mode, m.name)
					}
					if got.site != o.site {
						t.Errorf("Sec-Fetch-Site = %q, want %q", got.site, o.site)
					}
					if got.origin != o.origin {
						t.Errorf("Origin = %q, want the caller's %q", got.origin, o.origin)
					}
				})
			}
		}
	})
}

// TestClientWireRefererNamesThePage gives the Referer in Headers only, the
// one way httpcloak.Client callers can give it. It names the page, over a
// caller's Origin too, so the no-page default does not apply. Which Origin a
// request to a page the Referer names carries is not this change's: only that
// one goes out where a browser always sends one, and that a same-origin
// request's names its own origin.
func TestClientWireRefererNamesThePage(t *testing.T) {
	s := newNoPageServer(t)
	page := func() string { return s.target + "/page" }
	cases := []struct {
		name    string
		mode    FetchMode
		headers func() map[string][]string
		site    string
		origin  string // "" for none, "*" for one with any value, else the one it must be
		ownOK   bool   // the request may also send its own origin, or none
	}{
		{"cors GET from its own origin", FetchModeCORS, func() map[string][]string {
			return map[string][]string{"Referer": {page()}}
		}, "same-origin", "", true},
		{"cors GET from another site", FetchModeCORS, func() map[string][]string {
			return map[string][]string{"Referer": {"https://www.elsewhere.test/page"}}
		}, "cross-site", "*", false},
		{"cors GET with a Referer and another Origin", FetchModeCORS, func() map[string][]string {
			return map[string][]string{"Referer": {page()}, "Origin": {"https://www.elsewhere.test"}}
		}, "same-origin", "https://www.elsewhere.test", false},
		{"navigation from the same site", FetchModeNavigate, func() map[string][]string {
			return map[string][]string{"referer": {"https://www.example.test/page"}}
		}, "same-site", "", false},
	}
	forEachNoPageClient(t, func(t *testing.T, c *Client, proto string) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				req := &Request{URL: s.target + "/x", FetchMode: tc.mode, Headers: tc.headers()}
				got, _ := s.send(t, c, req, proto)
				if got.site != tc.site {
					t.Errorf("Sec-Fetch-Site = %q, want %q", got.site, tc.site)
				}
				switch {
				case tc.ownOK && got.hasOrigin && got.origin != s.target:
					t.Errorf("Origin = %q, want none or the page's own %q", got.origin, s.target)
				case tc.ownOK:
				case tc.origin == "" && got.hasOrigin:
					t.Errorf("Origin = %q, want none", got.origin)
				case tc.origin == "*" && !got.hasOrigin:
					t.Errorf("no Origin on a %s CORS request", tc.site)
				case tc.origin != "" && tc.origin != "*" && got.origin != tc.origin:
					t.Errorf("Origin = %q, want %q", got.origin, tc.origin)
				}
			})
		}
	})
}

// TestClientNoPageDefaultsElsewhere covers what the change leaves alone: a
// navigation that names no page is a typed one, and a CORS request whose site
// the caller forces keeps an Origin, as every cross-site CORS request must.
func TestClientNoPageDefaultsElsewhere(t *testing.T) {
	s := newNoPageServer(t)
	forEachNoPageClient(t, func(t *testing.T, c *Client, proto string) {
		t.Run("typed navigation", func(t *testing.T) {
			got, _ := s.send(t, c, &Request{URL: s.target + "/x"}, proto)
			if got.site != "none" || got.hasOrigin {
				t.Errorf("Sec-Fetch-Site = %q, Origin = %q (sent %v), want none and no Origin", got.site, got.origin, got.hasOrigin)
			}
		})
		t.Run("cors GET forced cross-site", func(t *testing.T) {
			got, _ := s.send(t, c, &Request{URL: s.target + "/x", FetchMode: FetchModeCORS, FetchSite: FetchSiteCrossSite}, proto)
			if got.site != "cross-site" || !got.hasOrigin {
				t.Errorf("Sec-Fetch-Site = %q, Origin sent = %v, want cross-site with an Origin", got.site, got.hasOrigin)
			}
		})
	})
}
