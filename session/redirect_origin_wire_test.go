package session

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// The cases here are the ones captured from Chrome 156 and Firefox 159 on
// 2026-10-28. A page below the root of one origin sent fetch(), XHR, no-cors
// fetch(), iframe and form requests that were redirected within that origin,
// out to a second origin and back, and from https down to http, with 302, 303,
// 307 and 308. Each test asserts the Origin the browsers sent, as the
// receiving server saw it. The two browsers agreed on every hop but one kind:
// a form or no-cors POST's 307 or 308 to another origin, which Chrome sent as
// "null" and Firefox with the page's origin.

// originPage is where the captured page lived.
const originPage = "/app/page.html?q=1"

// originServer is one origin of a redirect chain. It records each request as
// it arrived, and answers a path it has a route for with that route's
// redirect and any other path with a 200.
type originServer struct {
	url string // scheme://host:port, no trailing slash

	mu     sync.Mutex
	routes map[string]originRoute
	seen   map[string]originHit
}

type originRoute struct {
	status   int
	location string
}

type originHit struct {
	method, proto, mode, accept string
	origin                      []string // every Origin field, as received
}

func newOriginServer(t *testing.T, secure bool) *originServer {
	t.Helper()
	o := &originServer{routes: map[string]originRoute{}, seen: map[string]originHit{}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		o.mu.Lock()
		o.seen[r.URL.Path] = originHit{
			method: r.Method,
			proto:  r.Proto,
			mode:   r.Header.Get("Sec-Fetch-Mode"),
			accept: r.Header.Get("Accept"),
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
	})
	var srv *httptest.Server
	if secure {
		srv = httptest.NewUnstartedServer(h)
		srv.EnableHTTP2 = true
		srv.StartTLS()
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	o.url = srv.URL
	return o
}

func (o *originServer) redirect(path string, status int, location string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.routes[path] = originRoute{status: status, location: location}
}

// hit returns the request for path as it arrived, failing the test if that
// path was never requested or carried more than one Origin field.
func (o *originServer) hit(t *testing.T, path string) originHit {
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
func (o *originServer) wantOrigin(t *testing.T, path, want string) {
	t.Helper()
	var got string
	if h := o.hit(t, path); len(h.origin) == 1 {
		got = h.origin[0]
	}
	if got != want {
		t.Errorf("%s%s Origin = %q, want %q", o.url, path, got, want)
	}
}

func newOriginSession(t *testing.T, preset string) *Session {
	t.Helper()
	s := NewSession("", &protocol.SessionConfig{
		Preset:             preset,
		FollowRedirects:    true,
		InsecureSkipVerify: true, // httptest's certificate
		DisableHTTP3:       true, // the test origins speak TCP only
		PreferIPv4:         true, // they listen on 127.0.0.1 only
	})
	t.Cleanup(func() { s.Close() })
	return s
}

// follow issues req through the session, following its redirects.
func follow(t *testing.T, s *Session, req *transport.Request) {
	t.Helper()
	if _, err := s.Request(context.Background(), req); err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
}

// fetchRequest is a page's fetch() or XHR as Chrome and Firefox sent it. origin
// is the Origin of the first request: none for a GET to the page's own
// origin, the page's origin for a POST or for a request to another origin.
func fetchRequest(method, url, page, origin string) *transport.Request {
	h := map[string][]string{
		"Referer":        {page},
		"Sec-Fetch-Mode": {"cors"},
		"Sec-Fetch-Dest": {"empty"},
	}
	if origin != "" {
		h["Origin"] = []string{origin}
	}
	req := &transport.Request{Method: method, URL: url, Headers: h}
	if method == "POST" {
		req.Body = []byte("b=2")
		h["Content-Type"] = []string{"text/plain;charset=UTF-8"}
	}
	return req
}

// formRequest is the page's form POST, a navigation with the page's origin.
func formRequest(url, page, origin string) *transport.Request {
	return &transport.Request{
		Method: "POST", URL: url, Body: []byte("b=2"),
		Headers: map[string][]string{
			"Referer":      {page},
			"Origin":       {origin},
			"Content-Type": {"application/x-www-form-urlencoded"},
		},
	}
}

// noCORSPostRequest is fetch(url, {method: "POST", mode: "no-cors"}).
func noCORSPostRequest(url, page, origin string) *transport.Request {
	return &transport.Request{
		Method: "POST", URL: url, Body: []byte("b=2"),
		Headers: map[string][]string{
			"Referer":        {page},
			"Origin":         {origin},
			"Sec-Fetch-Mode": {"no-cors"},
			"Sec-Fetch-Dest": {"empty"},
			"Content-Type":   {"text/plain;charset=UTF-8"},
		},
	}
}

// The session code is the same for every preset, but each preset builds its
// own header block, and a Chromium preset takes Chromium's rule for a form or
// no-cors POST. So the check runs for every browser family the library
// mimics, over HTTP/1.1 and HTTP/2. WebKit was not captured. Its
// SubresourceLoader makes the request's origin opaque on the same hops, and
// the Safari and iOS Chrome presets follow Fetch, as Firefox does.
var originPresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

func TestRedirectHopOrigin(t *testing.T) {
	for _, preset := range originPresets {
		// What a form or no-cors POST's 307 to another origin carries.
		chromium := preset == "chrome-latest"
		for _, secure := range []bool{false, true} {
			wantProto := "HTTP/1.1"
			if secure {
				wantProto = "HTTP/2.0"
			}
			t.Run(preset+"/"+wantProto, func(t *testing.T) {
				a, b := newOriginServer(t, secure), newOriginServer(t, secure)
				s := newOriginSession(t, preset)
				page, pageOrigin := a.url+originPage, a.url
				offOrigin := pageOrigin
				if chromium {
					offOrigin = "null"
				}

				// A fetch() GET within the page's origin: no Origin on either
				// request.
				a.redirect("/r/fetch-same", http.StatusFound, "/land/fetch-same")
				follow(t, s, fetchRequest("GET", a.url+"/r/fetch-same", page, ""))
				a.wantOrigin(t, "/land/fetch-same", "")
				if got := a.hit(t, "/land/fetch-same").proto; got != wantProto {
					t.Fatalf("hop went out over %s, want %s", got, wantProto)
				}

				// Redirected to another origin, the hop gains the page's.
				a.redirect("/r/fetch-xo", http.StatusFound, b.url+"/land/fetch-xo")
				follow(t, s, fetchRequest("GET", a.url+"/r/fetch-xo", page, ""))
				b.wantOrigin(t, "/land/fetch-xo", pageOrigin)

				// Out and back: "null" from the hop that leaves the other
				// origin, Fetch's tainted origin.
				a.redirect("/r/fetch-chain", http.StatusFound, b.url+"/r/fetch-bounce")
				b.redirect("/r/fetch-bounce", http.StatusFound, a.url+"/land/fetch-chain")
				follow(t, s, fetchRequest("GET", a.url+"/r/fetch-chain", page, ""))
				b.wantOrigin(t, "/r/fetch-bounce", pageOrigin)
				a.wantOrigin(t, "/land/fetch-chain", "null")

				// A first request to the other origin, which carries the page's
				// origin, redirected back onto the page's origin.
				b.redirect("/r/xo-back", http.StatusFound, a.url+"/land/xo-back")
				follow(t, s, fetchRequest("GET", b.url+"/r/xo-back", page, pageOrigin))
				a.wantOrigin(t, "/land/xo-back", "null")

				// A fetch() POST keeps its method and the page's origin through a
				// 307 or 308 to another origin, and is tainted coming back.
				a.redirect("/r/fpost-chain", http.StatusTemporaryRedirect, b.url+"/r/fpost-bounce")
				b.redirect("/r/fpost-bounce", http.StatusTemporaryRedirect, a.url+"/land/fpost-chain")
				follow(t, s, fetchRequest("POST", a.url+"/r/fpost-chain", page, pageOrigin))
				b.wantOrigin(t, "/r/fpost-bounce", pageOrigin)
				a.wantOrigin(t, "/land/fpost-chain", "null")
				if got := a.hit(t, "/land/fpost-chain").method; got != "POST" {
					t.Fatalf("307 hop went out as %s, want POST", got)
				}
				a.redirect("/r/fpost308-xo", http.StatusPermanentRedirect, b.url+"/land/fpost308-xo")
				follow(t, s, fetchRequest("POST", a.url+"/r/fpost308-xo", page, pageOrigin))
				b.wantOrigin(t, "/land/fpost308-xo", pageOrigin)

				// A fetch() POST answered with 303: the GET carries the page's
				// origin only off that origin.
				a.redirect("/r/fpost303-same", http.StatusSeeOther, "/land/fpost303-same")
				follow(t, s, fetchRequest("POST", a.url+"/r/fpost303-same", page, pageOrigin))
				a.wantOrigin(t, "/land/fpost303-same", "")
				a.redirect("/r/fpost303-xo", http.StatusSeeOther, b.url+"/land/fpost303-xo")
				follow(t, s, fetchRequest("POST", a.url+"/r/fpost303-xo", page, pageOrigin))
				if got := b.hit(t, "/land/fpost303-xo").method; got != "GET" {
					t.Fatalf("303 hop went out as %s, want GET", got)
				}
				b.wantOrigin(t, "/land/fpost303-xo", pageOrigin)

				// An iframe's GET hops carry none, out and back again.
				a.redirect("/r/frame-chain", http.StatusFound, b.url+"/r/frame-bounce")
				b.redirect("/r/frame-bounce", http.StatusFound, a.url+"/land/frame-chain")
				follow(t, s, &transport.Request{Method: "GET", URL: a.url + "/r/frame-chain", Headers: map[string][]string{
					"Referer":        {page},
					"Sec-Fetch-Mode": {"navigate"},
					"Sec-Fetch-Dest": {"iframe"},
				}})
				b.wantOrigin(t, "/r/frame-bounce", "")
				a.wantOrigin(t, "/land/frame-chain", "")

				// A form POST answered with 303: the GET after it carries none.
				a.redirect("/r/form-post", http.StatusSeeOther, "/land/form-post")
				follow(t, s, formRequest(a.url+"/r/form-post", page, pageOrigin))
				a.wantOrigin(t, "/r/form-post", pageOrigin)
				a.wantOrigin(t, "/land/form-post", "")

				// A form POST answered with 307 keeps the page's origin on that
				// origin. Off it, Chrome sends "null" at once, and Firefox the
				// page's origin until the chain is tainted.
				a.redirect("/r/form307-same", http.StatusTemporaryRedirect, "/land/form307-same")
				follow(t, s, formRequest(a.url+"/r/form307-same", page, pageOrigin))
				a.wantOrigin(t, "/land/form307-same", pageOrigin)
				a.redirect("/r/form307-chain", http.StatusTemporaryRedirect, b.url+"/r/form307-bounce")
				b.redirect("/r/form307-bounce", http.StatusTemporaryRedirect, a.url+"/land/form307-chain")
				follow(t, s, formRequest(a.url+"/r/form307-chain", page, pageOrigin))
				b.wantOrigin(t, "/r/form307-bounce", offOrigin)
				a.wantOrigin(t, "/land/form307-chain", "null")

				// A no-cors POST goes the way the form does.
				a.redirect("/r/ncpost-xo", http.StatusTemporaryRedirect, b.url+"/land/ncpost-xo")
				follow(t, s, noCORSPostRequest(a.url+"/r/ncpost-xo", page, pageOrigin))
				b.wantOrigin(t, "/land/ncpost-xo", offOrigin)
			})
		}

		// https -> http. Outside cors mode the referrer policy makes Origin
		// "null" there in every browser; a fetch() keeps the https page's
		// origin, and is tainted once the chain comes back up.
		t.Run(preset+"/downgrade", func(t *testing.T) {
			a, down := newOriginServer(t, true), newOriginServer(t, false)
			s := newOriginSession(t, preset)
			page, pageOrigin := a.url+originPage, a.url

			a.redirect("/r/fetch-down-up", http.StatusFound, down.url+"/r/fetch-up")
			down.redirect("/r/fetch-up", http.StatusFound, a.url+"/land/fetch-down-up")
			follow(t, s, fetchRequest("GET", a.url+"/r/fetch-down-up", page, ""))
			down.wantOrigin(t, "/r/fetch-up", pageOrigin)
			a.wantOrigin(t, "/land/fetch-down-up", "null")

			a.redirect("/r/fpost-down", http.StatusTemporaryRedirect, down.url+"/land/fpost-down")
			follow(t, s, fetchRequest("POST", a.url+"/r/fpost-down", page, pageOrigin))
			down.wantOrigin(t, "/land/fpost-down", pageOrigin)

			a.redirect("/r/form307-down", http.StatusTemporaryRedirect, down.url+"/land/form307-down")
			follow(t, s, formRequest(a.url+"/r/form307-down", page, pageOrigin))
			down.wantOrigin(t, "/land/form307-down", "null")

			a.redirect("/r/ncpost-down", http.StatusTemporaryRedirect, down.url+"/land/ncpost-down")
			follow(t, s, noCORSPostRequest(a.url+"/r/ncpost-down", page, pageOrigin))
			down.wantOrigin(t, "/land/ncpost-down", "null")
		})
	}
}

// A request the caller gave no Sec-Fetch-Mode goes out in cors mode when the
// transport's sniff reads it as fetch-shaped, and its hops take cors rules
// too. A JSON POST answered with 303 turns into a bare GET, which the sniff
// alone would send as a navigation. Chrome and Firefox sent that GET in cors
// mode, with Accept */* and, off the page's origin, the page's origin.
func TestRedirectHopOriginSniffedCORS(t *testing.T) {
	for _, preset := range originPresets {
		for _, secure := range []bool{false, true} {
			name := preset + "/HTTP/1.1"
			if secure {
				name = preset + "/HTTP/2.0"
			}
			t.Run(name, func(t *testing.T) {
				a, b := newOriginServer(t, secure), newOriginServer(t, secure)
				s := newOriginSession(t, preset)
				page, pageOrigin := a.url+originPage, a.url
				jsonPost := func(url string) *transport.Request {
					return &transport.Request{
						Method: "POST", URL: url, Body: []byte(`{"b":2}`),
						Headers: map[string][]string{
							"Referer":      {page},
							"Origin":       {pageOrigin},
							"Content-Type": {"application/json"},
						},
					}
				}

				a.redirect("/r/json303-xo", http.StatusSeeOther, b.url+"/land/json303-xo")
				follow(t, s, jsonPost(a.url+"/r/json303-xo"))
				land := b.hit(t, "/land/json303-xo")
				if land.method != "GET" || land.mode != "cors" || land.accept != "*/*" {
					t.Errorf("GET after the 303 went out as %s, Sec-Fetch-Mode %q, Accept %q; "+
						"want GET, cors, */*", land.method, land.mode, land.accept)
				}
				b.wantOrigin(t, "/land/json303-xo", pageOrigin)

				a.redirect("/r/json303-same", http.StatusSeeOther, "/land/json303-same")
				follow(t, s, jsonPost(a.url+"/r/json303-same"))
				if got := a.hit(t, "/land/json303-same").mode; got != "cors" {
					t.Errorf("GET after a same-origin 303 Sec-Fetch-Mode = %q, want cors", got)
				}
				a.wantOrigin(t, "/land/json303-same", "")

				// A GET whose Accept the sniff reads as an API call.
				a.redirect("/r/api-xo", http.StatusFound, b.url+"/land/api-xo")
				follow(t, s, &transport.Request{Method: "GET", URL: a.url + "/r/api-xo", Headers: map[string][]string{
					"Referer": {page},
					"Accept":  {"application/json"},
				}})
				b.wantOrigin(t, "/land/api-xo", pageOrigin)
			})
		}
	}
}

// A request that goes out with no Sec-Fetch-Mode, here a TLS-only one, does
// not say which kind of browser request it is. Its hops carry the caller's
// Origin as given, as every hop did before.
func TestRedirectHopOriginWithoutAMode(t *testing.T) {
	a, b := newOriginServer(t, false), newOriginServer(t, false)
	s := newOriginSession(t, "chrome-latest")
	tlsOnly := true
	b.redirect("/r/back", http.StatusFound, a.url+"/land/back")
	follow(t, s, &transport.Request{
		Method: "GET", URL: b.url + "/r/back", TLSOnly: &tlsOnly,
		Headers: map[string][]string{"Origin": {a.url}},
	})
	// A browser's fetch() would send "null" here.
	a.wantOrigin(t, "/land/back", a.url)
}

// exactHopPairs is what a hop sent under ExactHeaders, as spelled and in
// order, minus the framing the transport writes itself.
func exactHopPairs(rec hopRecord) []string {
	var out []string
	for _, p := range rec.rawPairs {
		name, _, _ := strings.Cut(p, ":")
		if !strings.EqualFold(name, "Host") && !strings.EqualFold(name, "Content-Length") {
			out = append(out, p)
		}
	}
	return out
}

// Under ExactHeaders the transport never reads Headers, so the hop's Origin
// reaches the wire only through the list. An Origin pair follows the same rule
// as the header, in its own slot and spelling. A list without one gains none,
// and a list without a Sec-Fetch-Mode is sent as given.
func TestRedirectHopOriginInExactHeaders(t *testing.T) {
	list := func(mode, origin string) []fingerprint.HeaderPair {
		l := []fingerprint.HeaderPair{{Key: "user-agent", Value: "mirror/1"}}
		if mode != "" {
			l = append(l, fingerprint.HeaderPair{Key: "Sec-Fetch-Mode", Value: mode})
		}
		if origin != "" {
			l = append(l, fingerprint.HeaderPair{Key: "origin", Value: origin})
		}
		return append(l, fingerprint.HeaderPair{Key: "Accept", Value: "*/*"})
	}
	// What a hop must send, given the list's mode and the Origin it carries.
	wire := func(mode, origin string) []string {
		var out []string
		for _, hp := range list(mode, origin) {
			out = append(out, hp.Key+": "+hp.Value)
		}
		return out
	}
	only := func(t *testing.T, c *bodyCapture) hopRecord {
		t.Helper()
		hops := c.recorded()
		if len(hops) != 1 {
			t.Fatalf("server saw %d requests, want 1", len(hops))
		}
		return hops[0]
	}

	// The page the requests come from; nothing is ever sent to it.
	const pageOrigin = "http://page.example"

	t.Run("tainted becomes null in its slot", func(t *testing.T) {
		b, c := newOriginServer(t, false), newBodyCapture(t, 200)
		s := newOriginSession(t, "chrome-latest")
		b.redirect("/r/x", http.StatusTemporaryRedirect, c.url+"land")
		follow(t, s, &transport.Request{
			Method: "POST", URL: b.url + "/r/x", Body: []byte("b=2"),
			ExactHeaders: list("cors", pageOrigin),
		})
		if got := exactHopPairs(only(t, c)); !slices.Equal(got, wire("cors", "null")) {
			t.Errorf("tainted hop sent %q, want %q", got, wire("cors", "null"))
		}
	})

	t.Run("dropped where the hop sends none", func(t *testing.T) {
		c := newBodyCapture(t, http.StatusSeeOther, 200)
		s := newOriginSession(t, "chrome-latest")
		follow(t, s, &transport.Request{
			Method: "POST", URL: c.url + "hop0", Body: []byte("b=2"),
			ExactHeaders: list("navigate", strings.TrimSuffix(c.url, "/")),
		})
		hops := c.recorded()
		if len(hops) != 2 {
			t.Fatalf("server saw %d hops, want 2", len(hops))
		}
		if got := exactHopPairs(hops[1]); !slices.Equal(got, wire("navigate", "")) {
			t.Errorf("GET after the 303 sent %q, want %q", got, wire("navigate", ""))
		}
	})

	t.Run("a list without one gains none", func(t *testing.T) {
		a, c := newOriginServer(t, false), newBodyCapture(t, 200)
		s := newOriginSession(t, "chrome-latest")
		a.redirect("/r/x", http.StatusFound, c.url+"land")
		follow(t, s, &transport.Request{Method: "GET", URL: a.url + "/r/x", ExactHeaders: list("cors", "")})
		if got := exactHopPairs(only(t, c)); !slices.Equal(got, wire("cors", "")) {
			t.Errorf("cross-origin hop sent %q, want %q", got, wire("cors", ""))
		}
	})

	t.Run("a list without a mode goes as given", func(t *testing.T) {
		b, c := newOriginServer(t, false), newBodyCapture(t, 200)
		s := newOriginSession(t, "chrome-latest")
		b.redirect("/r/x", http.StatusTemporaryRedirect, c.url+"land")
		follow(t, s, &transport.Request{
			Method: "POST", URL: b.url + "/r/x", Body: []byte("b=2"),
			ExactHeaders: list("", pageOrigin),
		})
		if got := exactHopPairs(only(t, c)); !slices.Equal(got, wire("", pageOrigin)) {
			t.Errorf("hop sent %q, want the list as given %q", got, wire("", pageOrigin))
		}
	})
}

func TestSerializeOrigin(t *testing.T) {
	cases := []struct{ url, want string }{
		{"https://Example.com/a?q=1#f", "https://example.com"},
		{"https://example.com:443/a", "https://example.com"},
		{"https://example.com:8443/a", "https://example.com:8443"},
		{"http://example.com:80/a", "http://example.com"},
		{"http://user:pass@example.com:8080/", "http://example.com:8080"},
		{"http://[::1]:8080/a", "http://[::1]:8080"},
		{"ftp://example.com/a", ""},
		{"null", ""},
	}
	for _, c := range cases {
		if got := serializeOrigin(c.url); got != c.want {
			t.Errorf("serializeOrigin(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}
