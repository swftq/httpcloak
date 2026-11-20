package session

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// The session resolves a redirect's Location, and Warmup a page's src and
// href, with resolveURL. The cases are the ones captured from Chrome 156 and
// Firefox 159 on 2026-10-28: a fetch() answered with a 302 carrying the case's
// Location, and an img, a script and a stylesheet with the case as their URL.
// The two browsers sent the same request-target for each, every way it was
// given, and each test here asserts that target as the receiving server read
// it.
//
// Before, a %3F in a relative reference's path was split into a query
// (/enc%3Fq=1 went out as /enc?q=1), an absolute reference kept its dot
// segments, and the query went out unencoded: a space in it split the
// HTTP/1.1 request line, and the server answered 400.

// locationOrigin records the raw request-target of every request it receives.
// It answers a target it has a route for with a 302 to that route's Location,
// one it has a page for with the page, and anything else with "ok".
type locationOrigin struct {
	url  string // https://host:port, no trailing slash
	host string // host:port, for a protocol-relative reference

	mu     sync.Mutex
	routes map[string]string
	pages  map[string]string
	hits   []locationHit
}

type locationHit struct {
	target, proto string
}

func newLocationOrigin(t *testing.T) *locationOrigin {
	t.Helper()
	o := &locationOrigin{routes: map[string]string{}, pages: map[string]string{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		o.mu.Lock()
		o.hits = append(o.hits, locationHit{target: r.RequestURI, proto: r.Proto})
		location, isRoute := o.routes[r.RequestURI]
		page, isPage := o.pages[r.RequestURI]
		o.mu.Unlock()
		switch {
		case isRoute:
			// Not http.Redirect, which would clean and escape the value.
			w.Header().Set("Location", location)
			w.WriteHeader(http.StatusFound)
		case isPage:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, page)
		default:
			io.WriteString(w, "ok")
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	o.url = srv.URL
	o.host = strings.TrimPrefix(srv.URL, "https://")
	return o
}

func (o *locationOrigin) redirect(target, location string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.routes[target] = location
}

func (o *locationOrigin) page(target, body string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pages[target] = body
}

func (o *locationOrigin) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.hits)
}

// since returns the requests received after the first n.
func (o *locationOrigin) since(n int) []locationHit {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]locationHit(nil), o.hits[n:]...)
}

// locationCase is a reference given by the page or the 302 at /dir/sub/page on
// origin a, and the request-target both browsers sent for it, on origin b when
// other is set. fragment is what the resolved URL has after want.
type locationCase struct {
	id, ref  string
	other    bool
	want     string
	fragment string
}

func locationCases(a, b *locationOrigin) []locationCase {
	return []locationCase{
		{"rootq", "/app/page.html?q=1", false, "/app/page.html?q=1", ""},
		{"relpath", "next?x=1", false, "/dir/sub/next?x=1", ""},
		{"dotdot", "../up?x=2", false, "/dir/up?x=2", ""},
		{"deepdots", "../../a/./b/../c?x=4", false, "/a/c?x=4", ""},
		{"qonly", "?page=2", false, "/dir/sub/page?page=2", ""},
		{"proto", "//" + b.host + "/pr?x=6", true, "/pr?x=6", ""},
		{"absdots", a.url + "/a/b/../abs?x=8", false, "/a/abs?x=8", ""},
		{"frag", "/frag?x=7#sec", false, "/frag?x=7", "#sec"},
		{"emptyq", "/eq?", false, "/eq?", ""},
		{"enc3f", "/enc%3Fq=1", false, "/enc%3Fq=1", ""},
		// The query is encoded as both browsers encoded it, whatever form the
		// reference took. %XX escapes are left alone, even invalid ones, and
		// so are the characters the set leaves out.
		{"combined", `/enc?q=a b&n=café&s='x'&d="y"<>`, false, "/enc?q=a%20b&n=caf%C3%A9&s=%27x%27&d=%22y%22%3C%3E", ""},
		{"absq", a.url + "/absq?q=a b&n=café", false, "/absq?q=a%20b&n=caf%C3%A9", ""},
		{"protoq", "//" + b.host + "/protoq?q=a b", true, "/protoq?q=a%20b", ""},
		{"qonlyenc", "?q=a b'", false, "/dir/sub/page?q=a%20b%27", ""},
		{"keepq", "/keep?q=a%20b&r=%zz&p=+&e=%C3%A9&l=%c3%a9", false, "/keep?q=a%20b&r=%zz&p=+&e=%C3%A9&l=%c3%a9", ""},
		{"qchars", "/qc?a={}|^`&b=\\&c=[]&d=/?:@!$&e=;,", false, "/qc?a={}|^`&b=\\&c=[]&d=/?:@!$&e=;,", ""},
	}
}

// Resolution is the same for every preset, but each preset sends through its
// own header pipeline, so the checks run for every browser family the library
// mimics. WebKit was not captured; its URL parser follows the URL standard,
// which agrees with both browsers on these cases.
var locationPresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

var locationProtocols = []struct {
	name   string
	h1, h2 bool
	proto  string // as the server reports it
}{
	{"h1", true, false, "HTTP/1.1"},
	{"h2", false, true, "HTTP/2.0"},
}

func newLocationSession(t *testing.T, preset string, forceHTTP1, forceHTTP2 bool) *Session {
	t.Helper()
	s := NewSession("", &protocol.SessionConfig{
		Preset:             preset,
		FollowRedirects:    true,
		InsecureSkipVerify: true, // httptest's certificate
		DisableHTTP3:       true, // the test origins speak TCP only
		ForceHTTP1:         forceHTTP1,
		ForceHTTP2:         forceHTTP2,
	})
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRedirectLocation(t *testing.T) {
	for _, preset := range locationPresets {
		for _, p := range locationProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a, b := newLocationOrigin(t), newLocationOrigin(t)
				s := newLocationSession(t, preset, p.h1, p.h2)

				for _, tc := range locationCases(a, b) {
					from := "/dir/sub/page?case=" + tc.id
					a.redirect(from, tc.ref)
					na, nb := a.count(), b.count()
					var to []string
					resp, err := s.Request(context.Background(), &transport.Request{
						Method: "GET",
						URL:    a.url + from,
						OnRedirect: func(r *transport.Redirect) error {
							to = append(to, r.To)
							return nil
						},
					})
					if err != nil {
						t.Errorf("%s: Location %q: %v", tc.id, tc.ref, err)
						continue
					}
					ha, hb := a.since(na), b.since(nb)
					if len(ha) == 0 || ha[0].target != from {
						t.Errorf("%s: first request = %v, want %q", tc.id, ha, from)
						continue
					}
					hops, origin := ha[1:], a
					if tc.other {
						hops, origin = hb, b
					}
					if len(hops) != 1 || len(ha)-1+len(hb) != 1 {
						t.Errorf("%s: Location %q: after the 302, A got %v and B got %v; want one request, %q",
							tc.id, tc.ref, ha[1:], hb, tc.want)
						continue
					}
					if hops[0].target != tc.want {
						t.Errorf("%s: Location %q: hop target = %q, want %q", tc.id, tc.ref, hops[0].target, tc.want)
					}
					if hops[0].proto != p.proto {
						t.Errorf("%s: hop went out over %s, want %s", tc.id, hops[0].proto, p.proto)
					}
					want := origin.url + tc.want + tc.fragment
					if len(to) != 1 || to[0] != want {
						t.Errorf("%s: OnRedirect saw To = %q, want [%q]", tc.id, to, want)
					}
					if resp.FinalURL != want {
						t.Errorf("%s: FinalURL = %q, want %q", tc.id, resp.FinalURL, want)
					}
					if len(resp.History) != 1 || resp.History[0].URL != a.url+from {
						t.Errorf("%s: History = %v, want the 302 from %q", tc.id, resp.History, a.url+from)
					}
				}

				// A Location that does not parse fails the request before
				// OnRedirect is asked and before anything is sent, as the fetch()
				// failed in both browsers. It used to reach OnRedirect as given and
				// then fail in the transport.
				for i, bad := range []string{"/bad%zz?x=17", a.url + "/bad%zz?x=17"} {
					from := fmt.Sprintf("/dir/sub/page?case=bad%d", i)
					a.redirect(from, bad)
					na := a.count()
					called := false
					resp, err := s.Request(context.Background(), &transport.Request{
						Method: "GET",
						URL:    a.url + from,
						OnRedirect: func(*transport.Redirect) error {
							called = true
							return nil
						},
					})
					var perr *url.Error
					if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("invalid redirect Location %q", bad)) || !errors.As(err, &perr) {
						t.Errorf("Location %q: err = %v, want an invalid redirect Location error wrapping the parse error", bad, err)
					}
					if resp != nil {
						t.Errorf("Location %q: got a %d response alongside the error, want none", bad, resp.StatusCode)
					}
					if called {
						t.Errorf("Location %q: OnRedirect was asked about a hop that cannot be taken", bad)
					}
					if got := a.since(na); len(got) != 1 {
						t.Errorf("Location %q: requests = %v, want only the one that got the 302", bad, got)
					}
				}
			})
		}
	}
}

// Warmup resolves the page's subresource URLs with the same rule. Both browsers
// requested the same target for a case whether it came as a Location or as the
// URL of an img, a script or a stylesheet.
func TestWarmupSubresourceURLs(t *testing.T) {
	for _, preset := range locationPresets {
		for _, p := range locationProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a, b := newLocationOrigin(t), newLocationOrigin(t)
				s := newLocationSession(t, preset, p.h1, p.h2)

				// Each element kind takes every third case, so each of Warmup's
				// three paths into resolveURL is crossed.
				var body strings.Builder
				body.WriteString("<!doctype html><html><head>\n")
				var want []string
				for i, tc := range locationCases(a, b) {
					ref := html.EscapeString(tc.ref)
					switch i % 3 {
					case 0:
						fmt.Fprintf(&body, "<img src=\"%s\">\n", ref)
					case 1:
						fmt.Fprintf(&body, "<script src=\"%s\"></script>\n", ref)
					case 2:
						fmt.Fprintf(&body, "<link rel=\"stylesheet\" href=\"%s\">\n", ref)
					}
					origin := "A "
					if tc.other {
						origin = "B "
					}
					want = append(want, origin+tc.want)
				}
				// Neither browser requested a URL that does not parse.
				fmt.Fprintf(&body, "<img src=\"%s\">\n", html.EscapeString("/bad%zz?x=17"))
				fmt.Fprintf(&body, "<script src=\"%s\"></script>\n", html.EscapeString(a.url+"/bad%zz?x=18"))
				body.WriteString("</head><body></body></html>\n")

				const pagePath = "/dir/sub/page?warmup=1"
				a.page(pagePath, body.String())
				if err := s.Warmup(context.Background(), a.url+pagePath); err != nil {
					t.Fatalf("Warmup: %v", err)
				}

				ha, hb := a.since(0), b.since(0)
				if len(ha) == 0 || ha[0].target != pagePath {
					t.Fatalf("first request = %v, want the page, %q", ha, pagePath)
				}
				var got []string
				for _, h := range ha[1:] {
					got = append(got, "A "+h.target)
				}
				for _, h := range hb {
					got = append(got, "B "+h.target)
				}
				sort.Strings(got)
				sort.Strings(want)
				if strings.Join(got, "\n") != strings.Join(want, "\n") {
					t.Errorf("subresource targets:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
				}
				for _, h := range append(ha[1:], hb...) {
					if h.proto != p.proto {
						t.Errorf("%q went out over %s, want %s", h.target, h.proto, p.proto)
					}
				}
			})
		}
	}
}
