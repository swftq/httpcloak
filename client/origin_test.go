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

	"github.com/sardanioss/httpcloak/fingerprint"
)

// The cases here are the ones captured from Chrome 156 and Firefox 159 on
// 2026-10-28. A page below the root of one origin sent fetch(), XHR, no-cors
// fetch(), iframe and form requests that were redirected within that origin,
// out to a second origin and back, and from https down to http, with 302, 303,
// 307 and 308. Each wire test asserts the Origin the browsers sent, as the
// receiving server saw it. The two browsers agreed on every request but one
// kind: a form or no-cors POST's 307 or 308 to another origin, which Chrome
// sent as "null" and Firefox with the page's origin.
//
// The client refuses any URL that is not https, so the capture's https -> http
// hops have no wire test here. TestRedirectOriginClient covers that part of
// the rule.

// TestRedirectOriginClient walks the rule through whole chains: the first
// request, then each hop, as Fetch and Firefox send them and as Chromium does
// where it differs.
func TestRedirectOriginClient(t *testing.T) {
	const (
		page  = "https://page.example"
		other = "https://other.example"
		down  = "http://down.example"
	)
	type step struct {
		url, method     string
		fetch, chromium string // the Origin sent, "" for none
	}
	cases := []struct {
		name  string
		mode  string
		steps []step // the first request, then each hop
	}{
		{"cors GET to its own origin, away and back", "cors", []step{
			{page + "/a", "GET", "", ""},
			{other + "/b", "GET", page, page},
			{page + "/c", "GET", "null", "null"},
		}},
		{"cors GET to another origin, then back", "cors", []step{
			{other + "/a", "GET", page, page},
			{page + "/b", "GET", "null", "null"},
		}},
		{"cors HEAD to its own origin", "cors", []step{
			{page + "/a", "HEAD", "", ""},
		}},
		{"cors POST 303 on its own origin", "cors", []step{
			{page + "/a", "POST", page, page},
			{page + "/b", "GET", "", ""},
		}},
		{"cors POST 303 away and back", "cors", []step{
			{page + "/a", "POST", page, page},
			{other + "/b", "GET", page, page},
			{page + "/c", "GET", "null", "null"},
		}},
		{"cors POST 307 away and on within that origin", "cors", []step{
			{page + "/a", "POST", page, page},
			{other + "/b", "POST", page, page},
			{other + "/c", "POST", page, page},
		}},
		{"cors GET down to http and back up", "cors", []step{
			{page + "/a", "GET", "", ""},
			{down + "/b", "GET", page, page},
			{page + "/c", "GET", "null", "null"},
		}},
		{"form POST 307 on its own origin", "navigate", []step{
			{page + "/a", "POST", page, page},
			{page + "/b", "POST", page, page},
		}},
		{"form POST 307 away and back", "navigate", []step{
			{page + "/a", "POST", page, page},
			{other + "/b", "POST", page, "null"},
			{page + "/c", "POST", "null", "null"},
		}},
		{"form POST 303", "navigate", []step{
			{page + "/a", "POST", page, page},
			{page + "/b", "GET", "", ""},
		}},
		{"form POST 307 down to http", "navigate", []step{
			{page + "/a", "POST", page, page},
			{down + "/b", "POST", "null", "null"},
		}},
		{"no-cors POST 307 to another origin", "no-cors", []step{
			{page + "/a", "POST", page, page},
			{other + "/b", "POST", page, "null"},
		}},
		{"no-cors GET to another origin", "no-cors", []step{
			{other + "/a", "GET", "", ""},
			{page + "/b", "GET", "", ""},
		}},
		{"navigation GET away and back", "navigate", []step{
			{page + "/a", "GET", "", ""},
			{other + "/b", "GET", "", ""},
			{page + "/c", "GET", "", ""},
		}},
		{"websocket to its own origin", "websocket", []step{
			{page + "/a", "GET", page, page},
		}},
	}
	for _, c := range cases {
		for _, preset := range []string{"firefox-latest", "chrome-latest"} {
			t.Run(c.name+"/"+preset, func(t *testing.T) {
				p := fingerprint.Get(preset)
				if p == nil {
					t.Fatalf("no preset %q", preset)
				}
				ro := newRedirectOriginClient(c.mode, page, c.steps[0].url, p)
				for i, s := range c.steps {
					var got string
					var ok bool
					if i == 0 {
						got, ok = ro.originFor(s.url, s.method)
					} else {
						got, ok = ro.next(c.steps[i-1].url, s.url, s.method)
					}
					want := s.fetch
					if chromiumPresetClient(p) {
						want = s.chromium
					}
					if ok != (want != "") || got != want {
						t.Errorf("request %d, %s %s: Origin %q (sent %v), want %q", i, s.method, s.url, got, ok, want)
					}
				}
			})
		}
	}
}

func TestSerializeOriginClient(t *testing.T) {
	cases := []struct{ url, want string }{
		{"https://Example.com/a?q=1#f", "https://example.com"},
		{"https://example.com:443/a", "https://example.com"},
		{"https://example.com:8443/a", "https://example.com:8443"},
		{"http://example.com:80/a", "http://example.com"},
		{"http://user:pass@example.com:8080/", "http://example.com:8080"},
		{"http://[::1]:8080/a", "http://[::1]:8080"},
		{"ftp://example.com/a", ""},
		{"null", ""},
		{"/relative", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := serializeOriginClient(c.url); got != c.want {
			t.Errorf("serializeOriginClient(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

// The presets that take Chromium's rule are the desktop and Android Chrome
// ones; Chrome on iOS runs on WebKit.
func TestChromiumPresetClient(t *testing.T) {
	for preset, want := range map[string]bool{
		"chrome-latest":         true,
		"android-chrome-latest": true,
		"firefox-latest":        false,
		"safari-latest":         false,
		"chrome-latest-ios":     false,
	} {
		if got := chromiumPresetClient(fingerprint.Get(preset)); got != want {
			t.Errorf("chromiumPresetClient(%s) = %v, want %v", preset, got, want)
		}
	}
}

// originHopPage is where the captured page lived.
const originHopPage = "/app/page.html?q=1"

// originHopServer is one origin of a redirect chain. It records each request
// as it arrived, and answers a path it has a route for with that route's
// redirect and any other path with a 200.
type originHopServer struct {
	url string // https://host:port, no trailing slash

	mu     sync.Mutex
	routes map[string]originHopRoute
	seen   map[string]originHopHit
}

type originHopRoute struct {
	status   int
	location string
}

type originHopHit struct {
	method, proto, mode string
	origin              []string // every Origin field, as received
}

func newOriginHopServer(t *testing.T) *originHopServer {
	t.Helper()
	o := &originHopServer{routes: map[string]originHopRoute{}, seen: map[string]originHopHit{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		o.mu.Lock()
		o.seen[r.URL.Path] = originHopHit{
			method: r.Method,
			proto:  r.Proto,
			mode:   r.Header.Get("Sec-Fetch-Mode"),
			origin: r.Header.Values("Origin"),
		}
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

func (o *originHopServer) redirect(path string, status int, location string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.routes[path] = originHopRoute{status: status, location: location}
}

// hit returns the request for path as it arrived, failing the test if that
// path was never requested or carried more than one Origin field.
func (o *originHopServer) hit(t *testing.T, path string) originHopHit {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	h, ok := o.seen[path]
	if !ok {
		t.Fatalf("%s%s was never requested", o.url, path)
	}
	if len(h.origin) > 1 {
		t.Fatalf("%s%s carried %d Origin fields %q", o.url, path, len(h.origin), h.origin)
	}
	return h
}

// wantOrigin fails the test unless the request for path arrived with the
// Origin want, or with none when want is "".
func (o *originHopServer) wantOrigin(t *testing.T, path, want string) {
	t.Helper()
	var got string
	if h := o.hit(t, path); len(h.origin) == 1 {
		got = h.origin[0]
	}
	if got != want {
		t.Errorf("%s%s Origin = %q, want %q", o.url, path, got, want)
	}
}

// wantMethod fails the test unless the request for path went out as method.
func (o *originHopServer) wantMethod(t *testing.T, path, method string) {
	t.Helper()
	if got := o.hit(t, path).method; got != method {
		t.Errorf("%s%s went out as %s, want %s", o.url, path, got, method)
	}
}

// The redirect code is the same for every preset, but each preset builds its
// own header block, and a Chromium preset takes Chromium's rule for a form or
// no-cors POST. So the checks run for every browser family the library
// mimics, over HTTP/1.1 and HTTP/2. WebKit was not captured. Its
// SubresourceLoader makes the request's origin opaque on the same hops, and
// the Safari and iOS Chrome presets follow Fetch, as Firefox does.
var originHopPresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

var originHopProtocols = []struct {
	name  string
	force Option
	proto string // as the server reports it
}{
	{"h1", WithForceHTTP1(), "HTTP/1.1"},
	{"h2", WithForceHTTP2(), "HTTP/2.0"},
}

func newOriginHopClient(t *testing.T, preset string, opts ...Option) *Client {
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

// followOrigin issues req through the client, following its redirects.
func followOrigin(t *testing.T, c *Client, req *Request) {
	t.Helper()
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
}

// originHeaders returns a fresh header map for one request. doOnce writes
// every header it sent back into the map it is given, so no two requests may
// share one.
func originHeaders(kv ...string) map[string][]string {
	h := make(map[string][]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		h[kv[i]] = []string{kv[i+1]}
	}
	return h
}

// Before, a cors request carried Origin whatever its target, the Referer's
// origin or else the target's own, and a form or no-cors POST carried none.
func TestClientFirstRequestOrigin(t *testing.T) {
	for _, preset := range originHopPresets {
		for _, p := range originHopProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a, b := newOriginHopServer(t), newOriginHopServer(t)
				c := newOriginHopClient(t, preset, p.force)
				page, pageOrigin := a.url+originHopPage, a.url

				// A fetch() GET or HEAD to the page's own origin sends none,
				// whether the mode is set or sniffed and wherever the Referer
				// comes from.
				followOrigin(t, c, &Request{Method: "GET", URL: a.url + "/cors-get-same", Referer: page, FetchMode: FetchModeCORS})
				a.wantOrigin(t, "/cors-get-same", "")
				if got := a.hit(t, "/cors-get-same").proto; got != p.proto {
					t.Fatalf("request went out over %s, want %s", got, p.proto)
				}
				followOrigin(t, c, &Request{Method: "HEAD", URL: a.url + "/cors-head-same", Referer: page, FetchMode: FetchModeCORS})
				a.wantOrigin(t, "/cors-head-same", "")
				followOrigin(t, c, &Request{
					Method: "GET", URL: a.url + "/api-get-same",
					Headers: originHeaders("referer", page, "Accept", "application/json"),
				})
				if got := a.hit(t, "/api-get-same").mode; got != "cors" {
					t.Fatalf("Accept: application/json went out as Sec-Fetch-Mode %q, want cors", got)
				}
				a.wantOrigin(t, "/api-get-same", "")

				// To another origin, or with a method other than GET or HEAD, it
				// sends the page's origin.
				followOrigin(t, c, &Request{Method: "GET", URL: b.url + "/cors-get-xo", Referer: page, FetchMode: FetchModeCORS})
				b.wantOrigin(t, "/cors-get-xo", pageOrigin)
				followOrigin(t, c, &Request{
					Method: "POST", URL: a.url + "/cors-post-same", Referer: page, FetchMode: FetchModeCORS,
					Body: strings.NewReader(`{"b":2}`), Headers: originHeaders("Content-Type", "application/json"),
				})
				a.wantOrigin(t, "/cors-post-same", pageOrigin)

				// A form POST and a no-cors POST send the page's origin too; a
				// navigation's or a no-cors GET sends none, even cross-origin.
				followOrigin(t, c, &Request{
					Method: "POST", URL: a.url + "/form-post-same", Referer: page,
					Body: strings.NewReader("b=2"), Headers: originHeaders("Content-Type", "application/x-www-form-urlencoded"),
				})
				if got := a.hit(t, "/form-post-same").mode; got != "navigate" {
					t.Fatalf("form POST went out as Sec-Fetch-Mode %q, want navigate", got)
				}
				a.wantOrigin(t, "/form-post-same", pageOrigin)
				followOrigin(t, c, &Request{
					Method: "POST", URL: b.url + "/nc-post-xo", Referer: page, FetchMode: FetchModeNoCors,
					Body: strings.NewReader("b=2"), Headers: originHeaders("Content-Type", "text/plain;charset=UTF-8"),
				})
				b.wantOrigin(t, "/nc-post-xo", pageOrigin)
				followOrigin(t, c, &Request{Method: "GET", URL: b.url + "/nc-get-xo", Referer: page, FetchMode: FetchModeNoCors, FetchDest: "image"})
				b.wantOrigin(t, "/nc-get-xo", "")
				followOrigin(t, c, &Request{Method: "GET", URL: b.url + "/nav-get-xo", Referer: page})
				b.wantOrigin(t, "/nav-get-xo", "")

				// The Sec-Fetch-Mode on the wire decides, the caller's included:
				// a no-cors GET sends none, though its headers were built for cors.
				followOrigin(t, c, &Request{
					Method: "GET", URL: b.url + "/caller-no-cors-xo", Referer: page,
					Headers: originHeaders("Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Dest", "script"),
				})
				b.wantOrigin(t, "/caller-no-cors-xo", "")

				// With no Referer, fetch() takes the target's origin for the
				// page, so a GET to it goes out same-origin with no Origin, and
				// no other mode makes one up.
				followOrigin(t, c, &Request{Method: "GET", URL: a.url + "/cors-get-noref", FetchMode: FetchModeCORS})
				a.wantOrigin(t, "/cors-get-noref", "")
				followOrigin(t, c, &Request{
					Method: "POST", URL: a.url + "/form-post-noref",
					Body: strings.NewReader("b=2"), Headers: originHeaders("Content-Type", "application/x-www-form-urlencoded"),
				})
				a.wantOrigin(t, "/form-post-noref", "")
				followOrigin(t, c, &Request{
					Method: "POST", URL: a.url + "/nc-post-noref", FetchMode: FetchModeNoCors,
					Body: strings.NewReader("b=2"), Headers: originHeaders("Content-Type", "text/plain;charset=UTF-8"),
				})
				a.wantOrigin(t, "/nc-post-noref", "")

				// The caller's Origin goes out as set.
				followOrigin(t, c, &Request{
					Method: "GET", URL: a.url + "/caller-origin", Referer: page, FetchMode: FetchModeCORS,
					Headers: originHeaders("origin", "https://caller.example"),
				})
				a.wantOrigin(t, "/caller-origin", "https://caller.example")

				// The Referer's origin is serialized the way a browser writes an
				// Origin: lowercase, without the scheme's default port.
				followOrigin(t, c, &Request{Method: "GET", URL: a.url + "/cors-get-spelled", Referer: "https://Page.Example:443/x", FetchMode: FetchModeCORS})
				a.wantOrigin(t, "/cors-get-spelled", "https://page.example")
			})
		}
	}
}

// Before, every hop repeated the first request's Origin, or its lack of one.
func TestClientRedirectHopOrigin(t *testing.T) {
	for _, preset := range originHopPresets {
		// What a form or no-cors POST's 307 to another origin carries.
		offOrigin := func(pageOrigin string) string {
			if chromiumPresetClient(fingerprint.Get(preset)) {
				return "null"
			}
			return pageOrigin
		}
		for _, p := range originHopProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a, b := newOriginHopServer(t), newOriginHopServer(t)
				c := newOriginHopClient(t, preset, p.force)
				page, pageOrigin := a.url+originHopPage, a.url
				fetch := func(method, url string) *Request {
					req := &Request{Method: method, URL: url, Referer: page, FetchMode: FetchModeCORS}
					if method == "POST" {
						req.Body = strings.NewReader(`{"b":2}`)
						req.Headers = originHeaders("Content-Type", "application/json")
					}
					return req
				}
				form := func(url string) *Request {
					return &Request{
						Method: "POST", URL: url, Referer: page, Body: strings.NewReader("b=2"),
						Headers: originHeaders("Content-Type", "application/x-www-form-urlencoded"),
					}
				}
				// A POST with no body, for the hops a 303 turns into a GET. The
				// GET would carry the POST's Content-Length, and over HTTP/1.1 a
				// server then waits for a body that never comes.
				bodyless := func(req *Request) *Request {
					req.Body = nil
					return req
				}

				// A fetch() GET within the page's origin: no Origin on either
				// request.
				a.redirect("/r/fetch-same", http.StatusFound, "/land/fetch-same")
				followOrigin(t, c, fetch("GET", a.url+"/r/fetch-same"))
				a.wantOrigin(t, "/r/fetch-same", "")
				a.wantOrigin(t, "/land/fetch-same", "")
				if got := a.hit(t, "/land/fetch-same").proto; got != p.proto {
					t.Fatalf("hop went out over %s, want %s", got, p.proto)
				}

				// Redirected to another origin, the hop gains the page's.
				a.redirect("/r/fetch-xo", http.StatusFound, b.url+"/land/fetch-xo")
				followOrigin(t, c, fetch("GET", a.url+"/r/fetch-xo"))
				b.wantOrigin(t, "/land/fetch-xo", pageOrigin)

				// Out and back: "null" from the hop that leaves the other
				// origin, Fetch's tainted origin.
				a.redirect("/r/fetch-chain", http.StatusFound, b.url+"/r/fetch-bounce")
				b.redirect("/r/fetch-bounce", http.StatusFound, a.url+"/land/fetch-chain")
				followOrigin(t, c, fetch("GET", a.url+"/r/fetch-chain"))
				b.wantOrigin(t, "/r/fetch-bounce", pageOrigin)
				a.wantOrigin(t, "/land/fetch-chain", "null")

				// A first request to the other origin, which carries the page's
				// origin, redirected back onto the page's origin.
				b.redirect("/r/xo-back", http.StatusFound, a.url+"/land/xo-back")
				followOrigin(t, c, fetch("GET", b.url+"/r/xo-back"))
				b.wantOrigin(t, "/r/xo-back", pageOrigin)
				a.wantOrigin(t, "/land/xo-back", "null")

				// A fetch() POST keeps its method and the page's origin through a
				// 307 or 308 to another origin, and is tainted coming back.
				a.redirect("/r/fpost-chain", http.StatusTemporaryRedirect, b.url+"/r/fpost-bounce")
				b.redirect("/r/fpost-bounce", http.StatusTemporaryRedirect, a.url+"/land/fpost-chain")
				followOrigin(t, c, fetch("POST", a.url+"/r/fpost-chain"))
				b.wantOrigin(t, "/r/fpost-bounce", pageOrigin)
				a.wantOrigin(t, "/land/fpost-chain", "null")
				a.wantMethod(t, "/land/fpost-chain", "POST")
				a.redirect("/r/fpost308-xo", http.StatusPermanentRedirect, b.url+"/land/fpost308-xo")
				followOrigin(t, c, fetch("POST", a.url+"/r/fpost308-xo"))
				b.wantOrigin(t, "/land/fpost308-xo", pageOrigin)

				// A fetch() POST answered with 303: the GET carries the page's
				// origin only off that origin.
				a.redirect("/r/fpost303-same", http.StatusSeeOther, "/land/fpost303-same")
				followOrigin(t, c, bodyless(fetch("POST", a.url+"/r/fpost303-same")))
				a.wantOrigin(t, "/r/fpost303-same", pageOrigin)
				a.wantMethod(t, "/land/fpost303-same", "GET")
				a.wantOrigin(t, "/land/fpost303-same", "")
				a.redirect("/r/fpost303-xo", http.StatusSeeOther, b.url+"/land/fpost303-xo")
				followOrigin(t, c, bodyless(fetch("POST", a.url+"/r/fpost303-xo")))
				b.wantMethod(t, "/land/fpost303-xo", "GET")
				b.wantOrigin(t, "/land/fpost303-xo", pageOrigin)

				// A navigation's GET hops carry none, out and back again.
				a.redirect("/r/nav-chain", http.StatusFound, b.url+"/r/nav-bounce")
				b.redirect("/r/nav-bounce", http.StatusFound, a.url+"/land/nav-chain")
				followOrigin(t, c, &Request{Method: "GET", URL: a.url + "/r/nav-chain", Referer: page})
				b.wantOrigin(t, "/r/nav-bounce", "")
				a.wantOrigin(t, "/land/nav-chain", "")

				// A form POST answered with 303 sends the page's origin, and the
				// GET after it none.
				a.redirect("/r/form-post", http.StatusSeeOther, "/land/form-post")
				followOrigin(t, c, bodyless(form(a.url+"/r/form-post")))
				a.wantOrigin(t, "/r/form-post", pageOrigin)
				a.wantMethod(t, "/land/form-post", "GET")
				a.wantOrigin(t, "/land/form-post", "")

				// A form POST answered with 307 keeps the page's origin on that
				// origin. Off it, Chrome sends "null" at once, and Firefox the
				// page's origin until the chain is tainted.
				a.redirect("/r/form307-same", http.StatusTemporaryRedirect, "/land/form307-same")
				followOrigin(t, c, form(a.url+"/r/form307-same"))
				a.wantOrigin(t, "/land/form307-same", pageOrigin)
				a.redirect("/r/form307-chain", http.StatusTemporaryRedirect, b.url+"/r/form307-bounce")
				b.redirect("/r/form307-bounce", http.StatusTemporaryRedirect, a.url+"/land/form307-chain")
				followOrigin(t, c, form(a.url+"/r/form307-chain"))
				b.wantOrigin(t, "/r/form307-bounce", offOrigin(pageOrigin))
				a.wantOrigin(t, "/land/form307-chain", "null")
				a.wantMethod(t, "/land/form307-chain", "POST")

				// A no-cors POST goes the way the form does.
				a.redirect("/r/ncpost-xo", http.StatusTemporaryRedirect, b.url+"/land/ncpost-xo")
				followOrigin(t, c, &Request{
					Method: "POST", URL: a.url + "/r/ncpost-xo", Referer: page, FetchMode: FetchModeNoCors,
					Body: strings.NewReader("b=2"), Headers: originHeaders("Content-Type", "text/plain;charset=UTF-8"),
				})
				a.wantOrigin(t, "/r/ncpost-xo", pageOrigin)
				b.wantOrigin(t, "/land/ncpost-xo", offOrigin(pageOrigin))

				// A fetch() with no Referer takes the target's origin for the
				// page's. Its first request, a GET to that origin, sends none;
				// the hops then carry it as any cors chain does.
				a.redirect("/r/noref-chain", http.StatusFound, b.url+"/r/noref-bounce")
				b.redirect("/r/noref-bounce", http.StatusFound, a.url+"/land/noref-chain")
				followOrigin(t, c, &Request{Method: "GET", URL: a.url + "/r/noref-chain", FetchMode: FetchModeCORS})
				a.wantOrigin(t, "/r/noref-chain", "")
				b.wantOrigin(t, "/r/noref-bounce", a.url)
				a.wantOrigin(t, "/land/noref-chain", "null")

				// The caller's Origin is the page's origin. A first request to
				// another origin carries it on hops within that origin, and the
				// hop that leaves it is tainted.
				callerPage := "https://page.example"
				a.redirect("/r/caller-chain", http.StatusFound, "/r/caller-next")
				a.redirect("/r/caller-next", http.StatusFound, b.url+"/land/caller-chain")
				followOrigin(t, c, &Request{
					Method: "GET", URL: a.url + "/r/caller-chain", FetchMode: FetchModeCORS,
					Headers: originHeaders("Referer", callerPage+"/", "Origin", callerPage),
				})
				a.wantOrigin(t, "/r/caller-chain", callerPage)
				a.wantOrigin(t, "/r/caller-next", callerPage)
				b.wantOrigin(t, "/land/caller-chain", "null")
			})
		}
	}
}

// TLSOnly sends only the caller's headers. A request with no Sec-Fetch-Mode
// among them does not say which kind of browser request it is, so its hops
// carry the caller's Origin as given, as every hop did before. Name the mode
// and the hops follow the rule, from the caller's Origin.
func TestClientRedirectHopOriginTLSOnly(t *testing.T) {
	for _, preset := range originHopPresets {
		for _, p := range originHopProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a, b := newOriginHopServer(t), newOriginHopServer(t)
				c := newOriginHopClient(t, preset, p.force, WithTLSOnly())

				// With neither, a hop to another origin gains no Origin.
				a.redirect("/r/plain", http.StatusFound, b.url+"/land/plain")
				followOrigin(t, c, &Request{Method: "GET", URL: a.url + "/r/plain", Headers: originHeaders("Referer", a.url+originHopPage)})
				a.wantOrigin(t, "/r/plain", "")
				b.wantOrigin(t, "/land/plain", "")

				// No mode: the caller's Origin unchanged, where fetch() would
				// send "null".
				b.redirect("/r/as-given", http.StatusFound, a.url+"/land/as-given")
				followOrigin(t, c, &Request{Method: "GET", URL: b.url + "/r/as-given", Headers: originHeaders("Origin", a.url)})
				a.wantOrigin(t, "/land/as-given", a.url)

				// cors named: the hop that leaves the other origin is tainted.
				b.redirect("/r/cors", http.StatusFound, a.url+"/land/cors")
				followOrigin(t, c, &Request{
					Method: "GET", URL: b.url + "/r/cors",
					Headers: originHeaders("Origin", a.url, "Sec-Fetch-Mode", "cors"),
				})
				b.wantOrigin(t, "/r/cors", a.url)
				a.wantOrigin(t, "/land/cors", "null")
			})
		}
	}
}
