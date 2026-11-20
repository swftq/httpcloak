package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The client follows redirects in its own loop, so the session's Referer rule
// needs its own coverage here. The cases are the ones captured from Chrome 156
// and Firefox 159 on 2026-10-28: a page below the root of one origin whose
// fetch(), XHR, iframe and form POST were redirected within that origin, out to
// a second origin and back. The two browsers sent the same Referer on every
// hop. Each hop carried the Referer of the request before it, with
// strict-origin-when-cross-origin applied again for the new URL, and never the
// URL that issued the 3xx. Each wire test asserts what the browsers sent, as
// the receiving server saw it.
//
// The capture's https -> http hops have no wire test here, because the client
// refuses any URL that is not https. TestRedirectRefererClient covers that part
// of the rule.

// redirectRefererClient is a copy of session's redirectReferer, so it gets the
// same cases as session's TestRedirectReferer.
func TestRedirectRefererClient(t *testing.T) {
	cases := []struct {
		name     string
		referrer string
		nextURL  string
		want     string
	}{
		{"same origin keeps the full Referer", "https://example.com/a/b?q=1", "https://example.com/next", "https://example.com/a/b?q=1"},
		{"cross-origin -> origin only", "https://example.com/a/b?q=1", "https://other.example/x", "https://example.com/"},
		{"another port is another origin", "https://example.com/a", "https://example.com:8443/b", "https://example.com/"},
		{"cross-origin non-default port kept", "https://example.com:8443/x", "https://other.example/", "https://example.com:8443/"},
		{"cross-origin default https port dropped", "https://example.com:443/x", "https://other.example/", "https://example.com/"},
		{"https Referer to http omits", "https://example.com/a", "http://other.example/b", ""},
		{"https Referer to http on its own host omits", "https://example.com/a", "http://example.com/a", ""},
		{"http Referer to https sends the http origin", "http://example.com/a", "https://example.com/a", "http://example.com/"},
		{"http Referer cross-origin over http", "http://example.com/a", "http://other.example/", "http://example.com/"},
		// A Referer trimmed on an earlier hop is already the origin, and a hop
		// back onto that origin sends it as it is: Chrome and Firefox both kept
		// it trimmed on the last hop of a page -> XO -> page chain.
		{"trimmed Referer stays trimmed back on its origin", "https://example.com/", "https://example.com/landing", "https://example.com/"},
		{"default port spelled out is the same origin", "https://example.com:443/a", "https://example.com/b", "https://example.com/a"},
		// Chrome never leaks the fragment or credentials in Referer, and drops a
		// redundant default port from the same-origin document URL.
		{"same-origin strips fragment", "https://example.com/a#section", "https://example.com/b", "https://example.com/a"},
		{"same-origin strips credentials", "https://user:pass@example.com/a", "https://example.com/b", "https://example.com/a"},
		{"same-origin strips creds+fragment keeps query", "https://user:pass@example.com/a?q=1#f", "https://example.com/b", "https://example.com/a?q=1"},
		{"http same-origin default port dropped", "http://example.com:80/a", "http://example.com/b", "http://example.com/a"},
		{"http same-origin non-default port kept", "http://example.com:8080/a", "http://example.com:8080/b", "http://example.com:8080/a"},
		{"cross-origin strips creds+fragment keeps port", "https://user:pass@example.com:8443/a#f", "https://other.example/", "https://example.com:8443/"},
		{"http cross-origin default port dropped", "http://example.com:80/a", "http://other.example/", "http://example.com/"},
		{"IPv6 cross-origin keeps brackets", "http://[::1]:8080/a", "http://other.example/", "http://[::1]:8080/"},
		{"IPv6 same origin", "http://[::1]:8080/a?b=1", "http://[::1]:8080/c", "http://[::1]:8080/a?b=1"},
		// No Referer, or one a browser could not have sent, gives none.
		{"no Referer stays none", "", "https://example.com/", ""},
		{"relative Referer", "/a/b", "https://example.com/", ""},
		{"not a URL", "not a url", "https://example.com/", ""},
		{"non-http scheme", "android-app://com.example/", "https://example.com/", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := redirectRefererClient(c.referrer, c.nextURL)
			if got != c.want {
				t.Fatalf("redirectRefererClient(%q, %q) = %q, want %q", c.referrer, c.nextURL, got, c.want)
			}
		})
	}
}

// refererPage is where the captured page lived. It sits below the root, so a
// Referer trimmed to the origin cannot pass for the page.
const refererPage = "/app/page.html?q=1"

// refererOrigin is one origin of a redirect chain. It records each request as
// it arrived, and answers a path it has a route for with that route's
// redirect and any other path with a 200.
type refererOrigin struct {
	url string // https://host:port, no trailing slash

	mu     sync.Mutex
	routes map[string]refererRoute
	seen   map[string]refererHit
}

type refererRoute struct {
	status   int
	location string
}

type refererHit struct {
	method, proto string
	referer       []string // every Referer field, as received
}

func newRefererOrigin(t *testing.T) *refererOrigin {
	t.Helper()
	o := &refererOrigin{routes: map[string]refererRoute{}, seen: map[string]refererHit{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		o.mu.Lock()
		o.seen[r.URL.Path] = refererHit{method: r.Method, proto: r.Proto, referer: r.Header.Values("Referer")}
		route, ok := o.routes[r.URL.Path]
		o.mu.Unlock()
		if ok {
			w.Header().Set("Location", route.location)
			w.WriteHeader(route.status)
			return
		}
		io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	o.url = srv.URL
	return o
}

func (o *refererOrigin) redirect(path string, status int, location string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.routes[path] = refererRoute{status: status, location: location}
}

// hit returns the request for path as it arrived, failing the test if that
// path was never requested or carried more than one Referer field.
func (o *refererOrigin) hit(t *testing.T, path string) refererHit {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	h, ok := o.seen[path]
	if !ok {
		t.Fatalf("%s%s was never requested", o.url, path)
	}
	if len(h.referer) > 1 {
		t.Fatalf("%s%s carried %d Referer fields %q", o.url, path, len(h.referer), h.referer)
	}
	return h
}

// referer returns the Referer the request for path arrived with, "" for none.
func (o *refererOrigin) referer(t *testing.T, path string) string {
	t.Helper()
	if h := o.hit(t, path); len(h.referer) == 1 {
		return h.referer[0]
	}
	return ""
}

// The redirect code is the same for every preset, but each preset builds its
// own header block, so the checks run for every browser family the library
// mimics. WebKit was not captured: its SubresourceLoader regenerates the hop's
// Referer from the previous request's with the same policy, for navigations as
// well as subresources.
var refererPresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

var refererProtocols = []struct {
	name  string
	force Option
	proto string // as the server reports it
}{
	{"h1", WithForceHTTP1(), "HTTP/1.1"},
	{"h2", WithForceHTTP2(), "HTTP/2.0"},
}

func newRefererClient(t *testing.T, preset string, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{
		WithInsecureSkipVerify(), // httptest's certificate
		WithPreferIPv4(),         // the servers listen on 127.0.0.1 only
		WithTimeout(20 * time.Second),
	}, opts...)
	c := NewClient(preset, opts...)
	t.Cleanup(func() { c.Close() })
	return c
}

// send issues req through the client, following its redirects.
func send(t *testing.T, c *Client, req *Request) {
	t.Helper()
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
}

// Before, a hop's Referer was a copy of the first request's, full and
// unchanged on every hop and every origin. A request with none sent the
// first URL of the chain on each hop instead.
func TestClientRedirectHopReferer(t *testing.T) {
	for _, preset := range refererPresets {
		for _, p := range refererProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a, b, c := newRefererOrigin(t), newRefererOrigin(t), newRefererOrigin(t)
				cl := newRefererClient(t, preset, p.force)
				page := a.url + refererPage
				pageOrigin := a.url + "/"

				// A typed navigation that redirects: no Referer on either hop.
				a.redirect("/start", http.StatusFound, "/land/start")
				send(t, cl, &Request{Method: "GET", URL: a.url + "/start"})
				if got := a.referer(t, "/land/start"); got != "" {
					t.Errorf("typed navigation's hop carried Referer %q; it had none to carry", got)
				}
				if got := a.hit(t, "/land/start").proto; got != p.proto {
					t.Fatalf("hop went out over %s, want %s", got, p.proto)
				}

				// A 302 within the page's origin: the page, not the 3xx URL,
				// whether the Referer came in the field or in the headers.
				a.redirect("/r/same", http.StatusFound, "/land/same")
				send(t, cl, &Request{Method: "GET", URL: a.url + "/r/same", Referer: page})
				if got := a.referer(t, "/land/same"); got != page {
					t.Errorf("same-origin hop Referer = %q, want the page %q", got, page)
				}
				a.redirect("/r/same-header", http.StatusFound, "/land/same-header")
				send(t, cl, &Request{
					Method: "GET", URL: a.url + "/r/same-header",
					Headers: map[string][]string{"referer": {page}},
				})
				if got := a.referer(t, "/land/same-header"); got != page {
					t.Errorf("same-origin hop Referer from the headers = %q, want the page %q", got, page)
				}

				// Out to another origin: the page's origin alone.
				a.redirect("/r/xo", http.StatusFound, b.url+"/land/xo")
				send(t, cl, &Request{Method: "GET", URL: a.url + "/r/xo", Referer: page})
				if got := b.referer(t, "/land/xo"); got != pageOrigin {
					t.Errorf("cross-origin hop Referer = %q, want %q", got, pageOrigin)
				}

				// The same from fetch(): the mode changes the header block, not
				// the Referer.
				a.redirect("/r/fetch-xo", http.StatusFound, b.url+"/land/fetch-xo")
				send(t, cl, &Request{Method: "GET", URL: a.url + "/r/fetch-xo", Referer: page, FetchMode: FetchModeCORS})
				if got := b.referer(t, "/land/fetch-xo"); got != pageOrigin {
					t.Errorf("fetch()'s cross-origin hop Referer = %q, want %q", got, pageOrigin)
				}

				// Out and back again: still the origin alone on the last hop,
				// because that hop starts from what the hop before it sent.
				a.redirect("/r/chain", http.StatusFound, b.url+"/r/bounce")
				b.redirect("/r/bounce", http.StatusFound, a.url+"/land/chain")
				send(t, cl, &Request{Method: "GET", URL: a.url + "/r/chain", Referer: page})
				if got := b.referer(t, "/r/bounce"); got != pageOrigin {
					t.Errorf("chain's cross-origin hop Referer = %q, want %q", got, pageOrigin)
				}
				if got := a.referer(t, "/land/chain"); got != pageOrigin {
					t.Errorf("chain's hop back to the page's origin Referer = %q, want it still trimmed to %q",
						got, pageOrigin)
				}

				// A first request to the other origin, which the browser sends
				// with the page's origin, redirected back onto the page's
				// origin: still that origin, never the other origin's.
				b.redirect("/r/back", http.StatusFound, a.url+"/land/back")
				send(t, cl, &Request{Method: "GET", URL: b.url + "/r/back", Referer: pageOrigin})
				if got := a.referer(t, "/land/back"); got != pageOrigin {
					t.Errorf("hop back from the other origin Referer = %q, want %q", got, pageOrigin)
				}

				// No Referer across three origins: none on any hop.
				a.redirect("/r/abc", http.StatusFound, b.url+"/r/bc")
				b.redirect("/r/bc", http.StatusFound, c.url+"/land/abc")
				send(t, cl, &Request{Method: "GET", URL: a.url + "/r/abc"})
				if got := b.referer(t, "/r/bc"); got != "" {
					t.Errorf("first hop of a chain sent with no Referer carried %q", got)
				}
				if got := c.referer(t, "/land/abc"); got != "" {
					t.Errorf("second hop of a chain sent with no Referer carried %q", got)
				}
			})
		}
	}
}

// A form POST answered with 303: the GET names the page, not the form's
// action. HTTP/2 only, because over HTTP/1.1 the GET still carries the
// POST's Content-Length and the server waits for a body that never comes.
// That is a fault in what the hop carries, not in its Referer.
func TestClientRedirectHopRefererAfter303(t *testing.T) {
	for _, preset := range refererPresets {
		t.Run(preset, func(t *testing.T) {
			a := newRefererOrigin(t)
			cl := newRefererClient(t, preset, WithForceHTTP2())
			page := a.url + refererPage

			a.redirect("/r/form-post", http.StatusSeeOther, "/land/form-post")
			send(t, cl, &Request{
				Method: "POST", URL: a.url + "/r/form-post", Referer: page,
				Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
				Body:    strings.NewReader("b=2"),
			})
			if got := a.hit(t, "/land/form-post").method; got != "GET" {
				t.Fatalf("303 hop went out as %s, want GET", got)
			}
			if got := a.referer(t, "/land/form-post"); got != page {
				t.Errorf("GET after the 303 Referer = %q, want the page %q", got, page)
			}
		})
	}
}

// With WithTLSOnly the client sends the caller's headers and does not read
// the Referer field, so a hop's Referer can only come from the headers it
// carries. It follows the same rule there. It used to go out verbatim on
// every hop.
func TestClientRedirectHopRefererTLSOnly(t *testing.T) {
	for _, preset := range refererPresets {
		for _, p := range refererProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a, b := newRefererOrigin(t), newRefererOrigin(t)
				cl := newRefererClient(t, preset, WithTLSOnly(), p.force)
				page := a.url + refererPage
				pageOrigin := a.url + "/"
				headers := func() map[string][]string {
					return map[string][]string{"User-Agent": {"mirror/1"}, "Referer": {page}}
				}

				a.redirect("/r/same", http.StatusFound, "/land/same")
				send(t, cl, &Request{Method: "GET", URL: a.url + "/r/same", Headers: headers()})
				if got := a.referer(t, "/land/same"); got != page {
					t.Errorf("same-origin hop Referer = %q, want the page %q", got, page)
				}
				if got := a.hit(t, "/land/same").proto; got != p.proto {
					t.Fatalf("hop went out over %s, want %s", got, p.proto)
				}

				a.redirect("/r/chain", http.StatusFound, b.url+"/r/bounce")
				b.redirect("/r/bounce", http.StatusFound, a.url+"/land/chain")
				send(t, cl, &Request{Method: "GET", URL: a.url + "/r/chain", Headers: headers()})
				if got := b.referer(t, "/r/bounce"); got != pageOrigin {
					t.Errorf("cross-origin hop Referer = %q, want %q", got, pageOrigin)
				}
				if got := a.referer(t, "/land/chain"); got != pageOrigin {
					t.Errorf("hop back to the page's origin Referer = %q, want it still trimmed to %q",
						got, pageOrigin)
				}
			})
		}
	}
}
