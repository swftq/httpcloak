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

// The client follows redirects in its own loop, which resolves each Location
// with JoinURL's resolution. The cases are the ones captured from Chrome 156
// and Firefox 159 on 2026-10-28: a fetch() of /r/<case>/dir/sub/page?orig=1
// answered with a 302 carrying the case's Location. The two browsers sent the
// same request-target for every case here, and each wire test asserts that
// target as the receiving server read it.
//
// Before, a relative Location's "?" was escaped into the path, so
// /app/page.html?q=1 went out as /app/page.html%3Fq=1, and an absolute one was
// sent with its dot segments.

// locationOrigin records the raw request-target of every request it receives,
// and answers a target it has a route for with a 302 to that route's Location.
type locationOrigin struct {
	url  string // https://host:port, no trailing slash
	host string // host:port, for a protocol-relative Location

	mu     sync.Mutex
	routes map[string]string
	hits   []locationHit
}

type locationHit struct {
	target, proto string
}

func newLocationOrigin(t *testing.T) *locationOrigin {
	t.Helper()
	o := &locationOrigin{routes: map[string]string{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		o.mu.Lock()
		o.hits = append(o.hits, locationHit{target: r.RequestURI, proto: r.Proto})
		location, ok := o.routes[r.RequestURI]
		o.mu.Unlock()
		if ok {
			// Not http.Redirect, which would clean and escape the value.
			w.Header().Set("Location", location)
			w.WriteHeader(http.StatusFound)
			return
		}
		io.WriteString(w, "ok")
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

// Resolution is the same for every preset, but each preset sends through its
// own header pipeline, so the checks run for every browser family the library
// mimics. WebKit was not captured; its URL parser follows the URL standard,
// which agrees with both browsers on these cases.
var locationPresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

func TestClientRedirectLocation(t *testing.T) {
	for _, preset := range locationPresets {
		for _, p := range []struct {
			name  string
			force Option
			proto string // as the server reports it
		}{
			{"h1", WithForceHTTP1(), "HTTP/1.1"},
			{"h2", WithForceHTTP2(), "HTTP/2.0"},
		} {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				a, b := newLocationOrigin(t), newLocationOrigin(t)
				c := NewClient(preset, p.force,
					WithInsecureSkipVerify(), // httptest's certificate
					WithPreferIPv4(),         // the servers listen on 127.0.0.1 only
					WithTimeout(20*time.Second),
				)
				t.Cleanup(func() { c.Close() })

				cases := []struct {
					id, location string
					to           *locationOrigin
					want         string // the hop's request-target
					fragment     string // what FinalURL has after want
				}{
					{"rootq", "/app/page.html?q=1", a, "/app/page.html?q=1", ""},
					{"relpath", "next?x=1", a, "/r/relpath/dir/sub/next?x=1", ""},
					{"dotdot", "../up?x=2", a, "/r/dotdot/dir/up?x=2", ""},
					{"deepdots", "../../a/./b/../c?x=4", a, "/r/deepdots/a/c?x=4", ""},
					{"qonly", "?page=2", a, "/r/qonly/dir/sub/page?page=2", ""},
					{"proto", "//" + b.host + "/pr?x=6", b, "/pr?x=6", ""},
					{"absdots", a.url + "/a/b/../abs?x=8", a, "/a/abs?x=8", ""},
					{"frag", "/frag?x=7#sec", a, "/frag?x=7", "#sec"},
					{"emptyq", "/eq?", a, "/eq?", ""},
					{"enc3f", "/enc%3Fq=1", a, "/enc%3Fq=1", ""},
					// The query is encoded as both browsers encoded it, whatever
					// form the reference took. %XX escapes are left alone, even
					// invalid ones, and so are the characters the set leaves out.
					{"combined", `/enc?q=a b&n=café&s='x'&d="y"<>`, a, "/enc?q=a%20b&n=caf%C3%A9&s=%27x%27&d=%22y%22%3C%3E", ""},
					{"qonlyenc", "?q=a b'", a, "/r/qonlyenc/dir/sub/page?q=a%20b%27", ""},
					{"keepq", "/keep?q=a%20b&r=%zz&p=+&e=%C3%A9&l=%c3%a9", a, "/keep?q=a%20b&r=%zz&p=+&e=%C3%A9&l=%c3%a9", ""},
					{"qchars", "/qc?a={}|^`&b=\\&c=[]&d=/?:@!$&e=;,", a, "/qc?a={}|^`&b=\\&c=[]&d=/?:@!$&e=;,", ""},
				}
				for _, tc := range cases {
					from := "/r/" + tc.id + "/dir/sub/page?orig=1"
					a.redirect(from, tc.location)
					na, nb := a.count(), b.count()
					resp, err := c.Do(context.Background(), &Request{Method: "GET", URL: a.url + from})
					if err != nil {
						t.Errorf("%s: Location %q: %v", tc.id, tc.location, err)
						continue
					}
					ha, hb := a.since(na), b.since(nb)
					if len(ha) == 0 || ha[0].target != from {
						t.Errorf("%s: first request = %v, want %q", tc.id, ha, from)
						continue
					}
					hops := ha[1:]
					if tc.to == b {
						hops = hb
					}
					if len(hops) != 1 || len(ha)-1+len(hb) != 1 {
						t.Errorf("%s: Location %q: after the 302, A got %v and B got %v; want one request, %q",
							tc.id, tc.location, ha[1:], hb, tc.want)
						continue
					}
					if hops[0].target != tc.want {
						t.Errorf("%s: Location %q: hop target = %q, want %q", tc.id, tc.location, hops[0].target, tc.want)
					}
					if hops[0].proto != p.proto {
						t.Errorf("%s: hop went out over %s, want %s", tc.id, hops[0].proto, p.proto)
					}
					if want := tc.to.url + tc.want + tc.fragment; resp.FinalURL != want {
						t.Errorf("%s: FinalURL = %q, want %q", tc.id, resp.FinalURL, want)
					}
				}

				// A Location that does not parse fails the request, as it
				// failed the fetch() in both browsers, and nothing follows it.
				// It used to go out with the % escaped: /bad%25zz%3Fx=17.
				const bad = "/r/badpct/dir/sub/page?orig=1"
				a.redirect(bad, "/bad%zz?x=17")
				na := a.count()
				_, err := c.Do(context.Background(), &Request{Method: "GET", URL: a.url + bad})
				if err == nil || !strings.Contains(err.Error(), "invalid redirect Location") {
					t.Errorf("unparseable Location: err = %v, want an invalid redirect Location error", err)
				}
				if got := a.since(na); len(got) != 1 {
					t.Errorf("unparseable Location: requests = %v, want only the one that got the 302", got)
				}
			})
		}
	}
}
