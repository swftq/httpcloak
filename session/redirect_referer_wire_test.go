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
// 2026-10-28: a page below the root of one origin whose fetch(), XHR, iframe
// and form POST were redirected within that origin, out to a second origin
// and back, and from https down to http. The two browsers sent the same
// Referer on every hop. Each hop carried the Referer of the request before it,
// with strict-origin-when-cross-origin applied again for the new URL, and
// never the URL that issued the 3xx. Each test asserts what the browsers sent,
// as the receiving server saw it.

// refererPage is where the captured page lived. It sits below the root, so a
// Referer trimmed to the origin cannot pass for the page.
const refererPage = "/app/page.html?q=1"

// refererOrigin is one origin of a redirect chain. It records each request as
// it arrived, and answers a path it has a route for with that route's
// redirect and any other path with a 200.
type refererOrigin struct {
	url string // scheme://host:port, no trailing slash

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

func newRefererOrigin(t *testing.T, secure bool) *refererOrigin {
	t.Helper()
	o := &refererOrigin{routes: map[string]refererRoute{}, seen: map[string]refererHit{}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func newRefererSession(t *testing.T, preset string) *Session {
	t.Helper()
	s := NewSession("", &protocol.SessionConfig{
		Preset:             preset,
		FollowRedirects:    true,
		InsecureSkipVerify: true, // httptest's certificate
		DisableHTTP3:       true, // the test origins speak TCP only
	})
	t.Cleanup(func() { s.Close() })
	return s
}

// send issues req through the session, following its redirects.
func send(t *testing.T, s *Session, req *transport.Request) {
	t.Helper()
	if _, err := s.Request(context.Background(), req); err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
}

// getWithReferer is a GET carrying referer, or no Referer at all when it is "".
func getWithReferer(t *testing.T, s *Session, url, referer string) {
	t.Helper()
	req := &transport.Request{Method: "GET", URL: url}
	if referer != "" {
		req.Headers = map[string][]string{"Referer": {referer}}
	}
	send(t, s, req)
}

// The session code is the same for every preset, but each preset builds its
// own header block, so the check runs for every browser family the library
// mimics, over HTTP/1.1 and HTTP/2. WebKit was not captured: its
// SubresourceLoader regenerates the hop's Referer from the previous request's
// with the same policy, for navigations as well as subresources.
var refererPresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

func TestRedirectHopReferer(t *testing.T) {
	for _, preset := range refererPresets {
		for _, secure := range []bool{false, true} {
			wantProto := "HTTP/1.1"
			if secure {
				wantProto = "HTTP/2.0"
			}
			t.Run(preset+"/"+wantProto, func(t *testing.T) {
				a, b := newRefererOrigin(t, secure), newRefererOrigin(t, secure)
				s := newRefererSession(t, preset)
				page := a.url + refererPage
				pageOrigin := a.url + "/"

				// A typed navigation that redirects: no Referer on either hop.
				a.redirect("/start", http.StatusFound, refererPage)
				getWithReferer(t, s, a.url+"/start", "")
				if got := a.referer(t, "/app/page.html"); got != "" {
					t.Errorf("typed navigation's hop carried Referer %q; it had none to carry", got)
				}
				if got := a.hit(t, "/app/page.html").proto; got != wantProto {
					t.Fatalf("hop went out over %s, want %s", got, wantProto)
				}

				// A 302 within the page's origin: the page, not the 3xx URL.
				a.redirect("/r/same", http.StatusFound, "/land/same")
				getWithReferer(t, s, a.url+"/r/same", page)
				if got := a.referer(t, "/land/same"); got != page {
					t.Errorf("same-origin hop Referer = %q, want the page %q", got, page)
				}

				// Out to another origin: the page's origin alone.
				a.redirect("/r/xo", http.StatusFound, b.url+"/land/xo")
				getWithReferer(t, s, a.url+"/r/xo", page)
				if got := b.referer(t, "/land/xo"); got != pageOrigin {
					t.Errorf("cross-origin hop Referer = %q, want %q", got, pageOrigin)
				}

				// Out and back again: still the origin alone on the last hop,
				// because that hop starts from what the hop before it sent.
				a.redirect("/r/chain", http.StatusFound, b.url+"/r/bounce")
				b.redirect("/r/bounce", http.StatusFound, a.url+"/land/chain")
				getWithReferer(t, s, a.url+"/r/chain", page)
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
				getWithReferer(t, s, b.url+"/r/back", pageOrigin)
				if got := a.referer(t, "/land/back"); got != pageOrigin {
					t.Errorf("hop back from the other origin Referer = %q, want %q", got, pageOrigin)
				}

				// A form POST answered with 303: the GET names the page.
				a.redirect("/r/form-post", http.StatusSeeOther, "/land/form-post")
				send(t, s, &transport.Request{
					Method: "POST", URL: a.url + "/r/form-post", Body: []byte("b=2"),
					Headers: map[string][]string{
						"Referer":      {page},
						"Content-Type": {"application/x-www-form-urlencoded"},
					},
				})
				land := a.hit(t, "/land/form-post")
				if land.method != "GET" {
					t.Fatalf("303 hop went out as %s, want GET", land.method)
				}
				if got := a.referer(t, "/land/form-post"); got != page {
					t.Errorf("GET after the 303 Referer = %q, want the page %q", got, page)
				}
			})
		}

		// https -> http: no Referer, and none again once the chain is back
		// on https, because the hop back starts from the downgraded hop.
		t.Run(preset+"/downgrade", func(t *testing.T) {
			a, down := newRefererOrigin(t, true), newRefererOrigin(t, false)
			s := newRefererSession(t, preset)
			page := a.url + refererPage

			a.redirect("/r/down", http.StatusFound, down.url+"/land/down")
			getWithReferer(t, s, a.url+"/r/down", page)
			if got := down.referer(t, "/land/down"); got != "" {
				t.Errorf("https -> http hop carried Referer %q, want none", got)
			}

			a.redirect("/r/down-up", http.StatusFound, down.url+"/r/up")
			down.redirect("/r/up", http.StatusFound, a.url+"/land/down-up")
			getWithReferer(t, s, a.url+"/r/down-up", page)
			if got := down.referer(t, "/r/up"); got != "" {
				t.Errorf("https -> http hop carried Referer %q, want none", got)
			}
			if got := a.referer(t, "/land/down-up"); got != "" {
				t.Errorf("hop back up to https carried Referer %q; the downgraded hop sent "+
					"none and the next hop starts from that", got)
			}
		})
	}
}

// exactPairs is what a hop sent under ExactHeaders, as spelled and in order,
// minus the Host line the transport writes as framing.
func exactPairs(rec hopRecord) []string {
	var out []string
	for _, p := range rec.rawPairs {
		if !strings.HasPrefix(strings.ToLower(p), "host:") {
			out = append(out, p)
		}
	}
	return out
}

// ExactHeaders replaces the pipeline, so a hop sends the caller's pairs and
// nothing else, but a Referer pair among them follows the same rule as the
// header: worked out again for each new URL, in the pair's own slot and
// spelling, and left out where the hop should carry none. Before, it went out
// verbatim on every hop, https -> http and DisableRedirectReferer included,
// because the transport does not read Headers in that mode.
func TestRedirectHopRefererInExactHeaders(t *testing.T) {
	exact := func(referer string) []fingerprint.HeaderPair {
		return []fingerprint.HeaderPair{
			{Key: "user-agent", Value: "mirror/1"},
			{Key: "referer", Value: referer},
			{Key: "Accept", Value: "*/*"},
		}
	}
	// What the hop must send, given the Referer it should carry ("" for none).
	want := func(referer string) []string {
		if referer == "" {
			return []string{"user-agent: mirror/1", "Accept: */*"}
		}
		return []string{"user-agent: mirror/1", "referer: " + referer, "Accept: */*"}
	}

	t.Run("same origin keeps it in its slot", func(t *testing.T) {
		srv := newBodyCapture(t, 302, 200)
		s := newRefererSession(t, "chrome-latest")
		page := srv.url + "app/page.html?q=1"
		send(t, s, &transport.Request{Method: "GET", URL: srv.url + "hop0", ExactHeaders: exact(page)})
		hops := srv.recorded()
		if len(hops) != 2 {
			t.Fatalf("server saw %d hops, want 2", len(hops))
		}
		if got := exactPairs(hops[1]); !slices.Equal(got, want(page)) {
			t.Errorf("hop 2 sent %q, want %q", got, want(page))
		}
	})

	t.Run("cross-origin cuts it to its origin", func(t *testing.T) {
		a, b := newRefererOrigin(t, false), newBodyCapture(t, 200)
		s := newRefererSession(t, "chrome-latest")
		a.redirect("/r/xo", http.StatusFound, b.url+"land")
		send(t, s, &transport.Request{Method: "GET", URL: a.url + "/r/xo", ExactHeaders: exact(a.url + refererPage)})
		hops := b.recorded()
		if len(hops) != 1 {
			t.Fatalf("other origin saw %d requests, want 1", len(hops))
		}
		if got := exactPairs(hops[0]); !slices.Equal(got, want(a.url+"/")) {
			t.Errorf("cross-origin hop sent %q, want %q", got, want(a.url+"/"))
		}
	})

	t.Run("https to http drops it", func(t *testing.T) {
		a, down := newRefererOrigin(t, true), newBodyCapture(t, 200)
		s := newRefererSession(t, "chrome-latest")
		a.redirect("/r/down", http.StatusFound, down.url+"land")
		send(t, s, &transport.Request{Method: "GET", URL: a.url + "/r/down", ExactHeaders: exact(a.url + refererPage)})
		hops := down.recorded()
		if len(hops) != 1 {
			t.Fatalf("http origin saw %d requests, want 1", len(hops))
		}
		if got := exactPairs(hops[0]); !slices.Equal(got, want("")) {
			t.Errorf("https -> http hop sent %q, want %q", got, want(""))
		}
	})

	t.Run("DisableRedirectReferer drops it", func(t *testing.T) {
		srv := newBodyCapture(t, 302, 200)
		s := newRefererSession(t, "chrome-latest")
		page := srv.url + "app/page.html?q=1"
		send(t, s, &transport.Request{
			Method: "GET", URL: srv.url + "hop0", ExactHeaders: exact(page),
			DisableRedirectReferer: true,
		})
		hops := srv.recorded()
		if len(hops) != 2 {
			t.Fatalf("server saw %d hops, want 2", len(hops))
		}
		if got := exactPairs(hops[0]); !slices.Equal(got, want(page)) {
			t.Errorf("hop 1 sent %q, want the caller's pairs %q", got, want(page))
		}
		if got := exactPairs(hops[1]); !slices.Equal(got, want("")) {
			t.Errorf("hop 2 sent %q despite DisableRedirectReferer, want %q", got, want(""))
		}
	})

	// With nothing but a Referer listed, leaving it out would empty the list,
	// and an empty list means no exact mode at all: the hop would go out with
	// the full preset pipeline. The session stops there instead of sending it.
	t.Run("a lone Referer that must go stops the chain", func(t *testing.T) {
		a, down := newRefererOrigin(t, true), newBodyCapture(t, 200)
		s := newRefererSession(t, "chrome-latest")
		a.redirect("/r/down", http.StatusFound, down.url+"land")
		resp, err := s.Request(context.Background(), &transport.Request{
			Method: "GET", URL: a.url + "/r/down",
			ExactHeaders: []fingerprint.HeaderPair{{Key: "referer", Value: a.url + refererPage}},
		})
		if err == nil || !strings.Contains(err.Error(), "ExactHeaders") {
			t.Fatalf("err = %v, want the hop refused for an emptied ExactHeaders", err)
		}
		if resp == nil || resp.StatusCode != http.StatusFound {
			t.Errorf("resp = %+v, want the 302 handed back with the error", resp)
		}
		if n := len(down.recorded()); n != 0 {
			t.Errorf("http origin saw %d requests, want none", n)
		}
	})
}
