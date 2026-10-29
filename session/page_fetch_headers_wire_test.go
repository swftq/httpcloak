package session

import (
	"context"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// What a browser sends beside a Referer, captured from Chrome 156 and Firefox
// 159 on 2026-10-28 with a page on https://a.test and requests to sub.a.test,
// a second port on a.test, b.test and from plain-HTTP a.test. The two sent the
// same values on every request:
//   - Sec-Fetch-Site is the page's relation to the URL in every mode, so no
//     request with a Referer carried none. fetch() and XHR to the page's own
//     origin sent same-origin, to sub.a.test and the other port same-site,
//     and to b.test cross-site; iframes the same, and the favicon same-origin.
//   - Origin went on fetch() and XHR off the page's origin, with the page's
//     origin as its value, and not on a same-origin GET. A form POST carried
//     the page's origin, and no GET outside cors mode carried any.
//
// The session used to send the preset's none on every navigation and
// cross-site with no Origin on everything it sniffed as fetch(), whatever the
// Referer said. Each test here reads what the server received.

var pageFetchPresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

var pageFetchProtocols = []struct{ name, proto string }{{"HTTP/1.1", "HTTP/1.1"}, {"HTTP/2", "HTTP/2.0"}}

type pageFetchHit struct {
	proto                        string
	site, origin, mode, referers []string
	refused                      bool // by pageFetchCSRF, on a path under /csrf/
}

// pageFetchCSRF is Go 1.25+'s CSRF check. It refuses a request other than GET,
// HEAD or OPTIONS whose Sec-Fetch-Site is neither same-origin nor none, or,
// with no Sec-Fetch-Site, whose Origin names another host.
var pageFetchCSRF = http.NewCrossOriginProtection()

// pageFetchServer records every request by path. A path /hop/<status>/... that
// ends in /1 answers with that status and a Location ending in /2 instead. A
// path under /csrf/ answers 403 to a request pageFetchCSRF refuses.
type pageFetchServer struct {
	url  string // scheme://host:port of the server under the name requests use
	port string

	mu   sync.Mutex
	hits map[string][]pageFetchHit
}

func newPageFetchServer(t *testing.T, host string, secure bool) *pageFetchServer {
	t.Helper()
	s := &pageFetchServer{hits: map[string][]pageFetchHit{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	scheme := "http"
	if secure {
		srv.EnableHTTP2 = true
		srv.StartTLS()
		scheme = "https"
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	s.port = strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
	s.url = scheme + "://" + net.JoinHostPort(host, s.port)
	return s
}

func (s *pageFetchServer) serve(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	refused := strings.HasPrefix(r.URL.Path, "/csrf/") && pageFetchCSRF.Check(r) != nil
	s.mu.Lock()
	s.hits[r.URL.Path] = append(s.hits[r.URL.Path], pageFetchHit{
		proto:    r.Proto,
		site:     r.Header.Values("Sec-Fetch-Site"),
		origin:   r.Header.Values("Origin"),
		mode:     r.Header.Values("Sec-Fetch-Mode"),
		referers: r.Header.Values("Referer"),
		refused:  refused,
	})
	s.mu.Unlock()
	if refused {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/hop/"); ok && strings.HasSuffix(rest, "/1") {
		status, _ := strconv.Atoi(rest[:strings.IndexByte(rest, '/')])
		w.Header().Set("Location", strings.TrimSuffix(r.URL.Path, "1")+"2")
		w.WriteHeader(status)
		return
	}
	io.WriteString(w, "ok")
}

// hit returns the one request the server received on path.
func (s *pageFetchServer) hit(t *testing.T, path string) pageFetchHit {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hits[path]) != 1 {
		t.Fatalf("%s: server received %d requests, want 1", path, len(s.hits[path]))
	}
	return s.hits[path][0]
}

func newPageFetchSession(t *testing.T, preset, proto string) *Session {
	t.Helper()
	s := NewSession("", &protocol.SessionConfig{
		Preset:             preset,
		FollowRedirects:    true,
		InsecureSkipVerify: true, // httptest's certificate
		DisableHTTP3:       true, // the test servers speak TCP only
		ForceHTTP1:         proto == "HTTP/1.1",
		ForceHTTP2:         proto == "HTTP/2.0",
		ConnectTo:          map[string]string{"a.test": "127.0.0.1", "b.test": "127.0.0.1"},
	})
	t.Cleanup(func() { s.Close() })
	return s
}

// pageFetchSend sends one request and fails the test if it does not succeed.
func pageFetchSend(t *testing.T, s *Session, req *transport.Request) {
	t.Helper()
	resp, err := s.Request(context.Background(), req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	resp.Close()
}

// wantValues fails unless the server received exactly want for a header, one
// field per value; no want means the header was absent.
func wantValues(t *testing.T, what, name string, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s: %s = %q, want %q", what, name, got, want)
	}
}

func TestPageFetchHeadersFollowTheReferer(t *testing.T) {
	// The shapes a caller sends a session: a navigation, a form, a frame, an
	// API call sniffed from its Accept or body, and no-cors loads named by
	// their own Sec-Fetch-Mode. Each one builds a fresh header map.
	shapes := []struct {
		name, method, mode string // mode is the Sec-Fetch-Mode it goes out with
		headers            map[string][]string
		body               string
	}{
		{"navigation", "GET", "navigate", nil, ""},
		{"form POST", "POST", "navigate", map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}, "b=2"},
		{"iframe", "GET", "navigate", map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}}, ""},
		{"fetch GET", "GET", "cors", map[string][]string{"Accept": {"application/json"}}, ""},
		{"fetch POST", "POST", "cors", map[string][]string{"Content-Type": {"application/json"}}, "{}"},
		{"no-cors image", "GET", "no-cors", map[string][]string{"Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Dest": {"image"}}, ""},
		{"no-cors POST", "POST", "no-cors", map[string][]string{
			"Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Dest": {"empty"}, "Content-Type": {"text/plain;charset=UTF-8"}}, "b=2"},
	}
	srv := newPageFetchServer(t, "a.test", true)
	otherPort := "8443"
	if srv.port == otherPort {
		otherPort = "9443"
	}
	// Every page names its relation to srv, https://a.test:<port>, and the
	// origin its Origin header would carry.
	pages := []struct {
		name, referer, site, origin string
	}{
		{"no Referer", "", "", ""}, // the mode decides; see below
		{"same origin", srv.url + "/app/page.html?q=1", "same-origin", srv.url},
		{"same site", "https://sub.a.test:" + srv.port + "/", "same-site", "https://sub.a.test:" + srv.port},
		{"other port", "https://a.test:" + otherPort + "/", "same-site", "https://a.test:" + otherPort},
		{"cross site", "https://b.test/", "cross-site", "https://b.test"},
		{"http page", "http://a.test:" + srv.port + "/", "cross-site", "http://a.test:" + srv.port},
	}
	for _, preset := range pageFetchPresets {
		for _, p := range pageFetchProtocols {
			s := newPageFetchSession(t, preset, p.proto)
			for _, shape := range shapes {
				for _, page := range pages {
					what := strings.Join([]string{preset, p.name, shape.name, page.name}, ", ")
					path := "/" + strings.ReplaceAll(strings.Join([]string{preset, p.proto, shape.name, page.name}, "/"), " ", "-")
					headers := map[string][]string{}
					for k, v := range shape.headers {
						headers[k] = slices.Clone(v)
					}
					if page.referer != "" {
						headers["Referer"] = []string{page.referer}
					}
					pageFetchSend(t, s, &transport.Request{Method: shape.method, URL: srv.url + path, Headers: headers, Body: []byte(shape.body)})

					h := srv.hit(t, path)
					if h.proto != p.proto {
						t.Fatalf("%s: went out over %s", what, h.proto)
					}
					wantValues(t, what, "Sec-Fetch-Mode", h.mode, shape.mode)
					// With no Referer, a cors request's page is the URL's own
					// origin, and any other mode keeps the preset's site: none
					// for a navigation, cross-site for no-cors.
					site, pageOrigin := page.site, page.origin
					switch {
					case page.referer != "":
					case shape.mode == "cors":
						site, pageOrigin = "same-origin", srv.url
					case shape.mode == "navigate":
						site = "none"
					default:
						site = "cross-site"
					}
					wantValues(t, what, "Sec-Fetch-Site", h.site, site)
					// Fetch's rule: any method but GET or HEAD carries the
					// page's origin, and so does a cors GET off that origin.
					var origin []string
					if pageOrigin != "" && (shape.method == "POST" || shape.mode == "cors" && pageOrigin != srv.url) {
						origin = []string{pageOrigin}
					}
					wantValues(t, what, "Origin", h.origin, origin...)
				}
			}
		}
	}
}

func TestPageFetchHeadersLeaveTheCallersOwn(t *testing.T) {
	srv := newPageFetchServer(t, "a.test", true)
	sameSite := "https://sub.a.test:" + srv.port
	tlsOnly := true
	cases := []struct {
		name         string
		req          func(url string) *transport.Request
		site, origin []string
	}{
		{"a Sec-Fetch-Site of the caller's", func(url string) *transport.Request {
			return &transport.Request{Method: "GET", URL: url, Headers: map[string][]string{
				"Referer": {"https://b.test/"}, "Accept": {"application/json"}, "sec-fetch-site": {"same-origin"}}}
		}, []string{"same-origin"}, []string{"https://b.test"}},
		{"an Origin of the caller's", func(url string) *transport.Request {
			return &transport.Request{Method: "GET", URL: url, Headers: map[string][]string{
				"Referer": {sameSite + "/"}, "Accept": {"application/json"}, "origin": {"https://elsewhere.test"}}}
		}, []string{"same-site"}, []string{"https://elsewhere.test"}},
		{"an Origin naming the page of a fetch", func(url string) *transport.Request {
			return &transport.Request{Method: "GET", URL: url, Headers: map[string][]string{
				"Origin": {sameSite}, "Accept": {"application/json"}}}
		}, []string{"same-site"}, []string{sameSite}},
		{"an Origin naming the page of a navigation", func(url string) *transport.Request {
			return &transport.Request{Method: "GET", URL: url, Headers: map[string][]string{"Origin": {srv.url}}}
		}, []string{"same-origin"}, []string{srv.url}},
		// "null" names no origin, so the preset's own value stands.
		{"a null Origin on a fetch", func(url string) *transport.Request {
			return &transport.Request{Method: "GET", URL: url, Headers: map[string][]string{
				"Origin": {"null"}, "Accept": {"application/json"}}}
		}, []string{"cross-site"}, []string{"null"}},
		{"a null Origin on a navigation", func(url string) *transport.Request {
			return &transport.Request{Method: "GET", URL: url, Headers: map[string][]string{"Origin": {"null"}}}
		}, []string{"none"}, []string{"null"}},
		// TLS-only and ExactHeaders requests carry what the caller gave and
		// nothing else.
		{"TLS-only", func(url string) *transport.Request {
			return &transport.Request{Method: "GET", URL: url, TLSOnly: &tlsOnly, Headers: map[string][]string{
				"Referer": {"https://b.test/"}, "Accept": {"application/json"}}}
		}, nil, nil},
		{"ExactHeaders", func(url string) *transport.Request {
			return &transport.Request{Method: "GET", URL: url, ExactHeaders: []fingerprint.HeaderPair{
				{Key: "user-agent", Value: "mirror/1"}, {Key: "accept", Value: "application/json"},
				{Key: "referer", Value: "https://b.test/"}, {Key: "sec-fetch-mode", Value: "cors"}}}
		}, nil, nil},
	}
	for _, preset := range pageFetchPresets {
		for _, p := range pageFetchProtocols {
			s := newPageFetchSession(t, preset, p.proto)
			for i, c := range cases {
				what := preset + ", " + p.name + ", " + c.name
				path := "/own/" + preset + "/" + p.proto + "/" + strconv.Itoa(i)
				pageFetchSend(t, s, c.req(srv.url+path))
				h := srv.hit(t, path)
				wantValues(t, what, "Sec-Fetch-Site", h.site, c.site...)
				wantValues(t, what, "Origin", h.origin, c.origin...)
			}
		}
	}
}

// RequestStream builds its request apart from Request, so it is sent too.
func TestPageFetchHeadersOnAStream(t *testing.T) {
	srv := newPageFetchServer(t, "a.test", true)
	for _, preset := range pageFetchPresets {
		for _, p := range pageFetchProtocols {
			s := newPageFetchSession(t, preset, p.proto)
			for _, c := range []struct {
				name    string
				headers map[string][]string
				site    string
				origin  []string
			}{
				{"fetch", map[string][]string{"Referer": {"https://b.test/"}, "Accept": {"application/json"}}, "cross-site", []string{"https://b.test"}},
				{"navigation", map[string][]string{"Referer": {srv.url + "/app/"}}, "same-origin", nil},
				{"no-page-fetch", map[string][]string{"Accept": {"application/json"}}, "same-origin", nil},
			} {
				what := preset + ", " + p.name + ", " + c.name
				path := "/stream/" + preset + "/" + p.proto + "/" + c.name
				resp, err := s.RequestStream(context.Background(), &transport.Request{Method: "GET", URL: srv.url + path, Headers: c.headers})
				if err != nil {
					t.Fatalf("%s: %v", what, err)
				}
				io.Copy(io.Discard, resp)
				resp.Close()
				h := srv.hit(t, path)
				wantValues(t, what, "Sec-Fetch-Site", h.site, c.site)
				wantValues(t, what, "Origin", h.origin, c.origin...)
			}
		}
	}
}

// Outside cors mode, Fetch's default referrer policy turns the page's origin
// into "null" from an https page to a URL that is not https; Chrome 156 and
// Firefox 159 did so on such a redirect hop of a form POST. Over plain HTTP
// only Origin is checked: browsers send no Sec-Fetch-* to a URL there that is
// not potentially trustworthy, which the session does not model yet.
func TestPageFetchHeadersToAPlainHTTPURL(t *testing.T) {
	srv := newPageFetchServer(t, "a.test", false)
	httpsPage := "https://a.test/app/page.html"
	for _, preset := range pageFetchPresets {
		s := newPageFetchSession(t, preset, "HTTP/1.1")
		for _, c := range []struct {
			name, referer string
			headers       map[string][]string
			origin        []string
		}{
			{"form POST from an https page", httpsPage,
				map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}, []string{"null"}},
			{"no-cors POST from an https page", httpsPage,
				map[string][]string{"Sec-Fetch-Mode": {"no-cors"}, "Content-Type": {"text/plain;charset=UTF-8"}}, []string{"null"}},
			{"form POST from its own origin", srv.url + "/app/page.html",
				map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}, []string{srv.url}},
		} {
			what := preset + ", " + c.name
			path := "/plain/" + preset + "/" + strings.ReplaceAll(c.name, " ", "-")
			c.headers["Referer"] = []string{c.referer}
			pageFetchSend(t, s, &transport.Request{Method: "POST", URL: srv.url + path, Headers: c.headers, Body: []byte("b=2")})
			wantValues(t, what, "Origin", srv.hit(t, path).origin, c.origin...)
		}
	}
}

// The values are worked out for the request the caller made and carried onto
// its redirect hops, never worked out again from a hop's own Referer, which
// names the URL that redirected. Here the page on a.test sends each request
// to b.test, which redirects within b.test. Every browser keeps cross-site and
// the page's Origin there; a hop judged from its own Referer would say
// same-origin and drop the Origin.
func TestPageFetchHeadersRideOntoRedirectHops(t *testing.T) {
	srv := newPageFetchServer(t, "b.test", true)
	page := "https://a.test/app/page.html"
	for _, preset := range pageFetchPresets {
		for _, p := range pageFetchProtocols {
			s := newPageFetchSession(t, preset, p.proto)
			for _, c := range []struct {
				name, method, status string
				headers              map[string][]string
				origin               []string
			}{
				{"fetch GET", "GET", "302", map[string][]string{"Accept": {"application/json"}}, []string{"https://a.test"}},
				{"form POST", "POST", "307", map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}, []string{"https://a.test"}},
				{"navigation", "GET", "302", nil, nil},
			} {
				headers := map[string][]string{"Referer": {page}}
				maps.Copy(headers, c.headers)
				path := "/hop/" + c.status + "/" + preset + "/" + p.proto + "/" + strings.ReplaceAll(c.name, " ", "-") + "/"
				pageFetchSend(t, s, &transport.Request{Method: c.method, URL: srv.url + path + "1", Headers: headers, Body: []byte("b=2")})
				for _, hop := range []string{"1", "2"} {
					what := preset + ", " + p.name + ", " + c.name + ", request " + hop
					h := srv.hit(t, path+hop)
					wantValues(t, what, "Sec-Fetch-Site", h.site, "cross-site")
					wantValues(t, what, "Origin", h.origin, c.origin...)
				}
			}
		}
	}
}
