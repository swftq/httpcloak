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

// Sec-Fetch-Site is same-site when the Referer's page and the target share a
// scheme and a registrable domain. extractSite used to guess that domain from
// label lengths and took any second-level label of three characters or fewer
// for part of a two-label suffix. So it sent www.cnn.com to edition.cnn.com,
// x.com to api.x.com and a.test to sub.a.test as cross-site, and put
// a.github.io and b.github.io on one site. Host case and a default port also
// counted in the same-origin check, where a browser's URL parser drops both.
//
// The expected values are Chromium 156's. GetOriginRelation compares
// url::Origin values, then SchemefulSite, whose registrable domain comes from
// GetDomainAndRegistry with INCLUDE_PRIVATE_REGISTRIES. That lookup counts
// unknown TLDs as registries and returns nothing for an IP address or a public
// suffix, and the site then falls back to the host. Gecko 159's base domain
// (nsEffectiveTLDService, ThirdPartyUtil::GetBaseDomain) agrees on each case.
// The tests assert what the receiving server saw.

// registrableSiteServer serves HTTP/1.1 and HTTP/2 under every name the cases
// use, all reached through ConnectTo, and records each request's
// Sec-Fetch-Site by path.
type registrableSiteServer struct {
	port string

	mu    sync.Mutex
	seen  map[string][]string // path -> every Sec-Fetch-Site field
	proto map[string]string   // path -> protocol
}

var registrableSiteNames = []string{
	"www.cnn.com", "edition.cnn.com", "x.com", "api.x.com",
	"a.example.co.uk", "example.co.uk", "a.github.io", "a.test", "sub.a.test",
	"10.0.0.1", "www.example.com", "api.example.com", "www.example.com.",
}

func newRegistrableSiteServer(t *testing.T) *registrableSiteServer {
	t.Helper()
	s := &registrableSiteServer{seen: map[string][]string{}, proto: map[string]string{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen[r.URL.Path] = r.Header.Values("Sec-Fetch-Site")
		s.proto[r.URL.Path] = r.Proto
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
	s.port = u.Port()
	return s
}

// at returns https://host:port, the server's port under host.
func (s *registrableSiteServer) at(host string) string {
	return "https://" + host + ":" + s.port
}

func TestClientSecFetchSiteUsesRegistrableDomain(t *testing.T) {
	s := newRegistrableSiteServer(t)
	cases := []struct {
		name, target, referer, want string
	}{
		// A short second-level label is not part of the suffix.
		{"cnn", s.at("edition.cnn.com"), "https://www.cnn.com/", "same-site"},
		{"x", s.at("api.x.com"), "https://x.com/", "same-site"},

		// A suffix the list has.
		{"co-uk-one-domain", s.at("a.example.co.uk"), "https://b.example.co.uk/", "same-site"},
		{"co-uk-two-domains", s.at("example.co.uk"), "https://other.co.uk/", "cross-site"},
		{"co-uk-suffix", s.at("example.co.uk"), "https://co.uk/", "cross-site"},

		// A private suffix: every github.io user is a site of its own.
		{"github-io-two-users", s.at("a.github.io"), "https://b.github.io/", "cross-site"},
		{"github-io-suffix", s.at("a.github.io"), "https://github.io/", "cross-site"},

		// A TLD the list does not know takes its last label for the suffix.
		{"test-sub", s.at("sub.a.test"), "https://a.test/", "same-site"},
		{"test-two-names", s.at("a.test"), "https://b.test/", "cross-site"},

		// An IP address or localhost is a site of its own; the port never
		// matters to a site.
		{"ip-other-port", s.at("127.0.0.1"), "https://127.0.0.1/", "same-site"},
		{"ip-two-addresses", s.at("10.0.0.1"), "https://192.168.0.1/", "cross-site"},
		{"localhost-other-port", s.at("localhost"), "https://localhost/", "same-site"},
		{"localhost-ip", s.at("localhost"), s.at("127.0.0.1") + "/", "cross-site"},

		// A URL parser lowercases the host.
		{"case-origin", s.at("www.example.com"), "https://WWW.EXAMPLE.COM:" + s.port + "/", "same-origin"},
		{"case-site", s.at("api.example.com"), "https://WWW.EXAMPLE.COM/", "same-site"},

		// One trailing dot is looked past for the lookup and kept in the site.
		{"trailing-dot-site", s.at("www.example.com."), "https://api.example.com./", "same-site"},
		{"trailing-dot-other-site", s.at("www.example.com."), "https://api.example.com/", "cross-site"},
	}
	modes := []struct {
		name string
		mode FetchMode
		dest string
	}{
		{"navigate", FetchModeNavigate, ""},
		{"cors", FetchModeCORS, ""},
		{"no-cors", FetchModeNoCors, "script"},
	}
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
				opts := []Option{p.opt, WithInsecureSkipVerify(), WithPreferIPv4(), WithTimeout(10 * time.Second)}
				for _, name := range registrableSiteNames {
					opts = append(opts, WithConnectTo(name, "127.0.0.1"))
				}
				c := NewClient(preset, opts...)
				defer c.Close()

				for _, tc := range cases {
					for _, m := range modes {
						path := "/" + preset + "/" + p.name + "/" + tc.name + "/" + m.name
						req := &Request{
							Method: "GET", URL: tc.target + path, Referer: tc.referer,
							FetchMode: m.mode, FetchDest: m.dest,
						}
						if _, err := c.Do(context.Background(), req); err != nil {
							t.Fatalf("%s/%s: %v", tc.name, m.name, err)
						}
						s.mu.Lock()
						got, proto := s.seen[path], s.proto[path]
						s.mu.Unlock()
						if proto != p.proto {
							t.Fatalf("%s/%s: server saw %q, want %s", tc.name, m.name, proto, p.proto)
						}
						if len(got) != 1 || got[0] != tc.want {
							t.Errorf("%s/%s: %s from Referer %s sent Sec-Fetch-Site %q, want %q",
								tc.name, m.name, tc.target, tc.referer, got, tc.want)
						}
					}
				}
			})
		}
	}
}

// The port of an origin with none written is its scheme's default, so a
// Referer naming :443 is on the same origin as a target that names no port.
// No test server can listen on 443, so this one is checked below the wire.
func TestDetectSecFetchSiteDefaultPort(t *testing.T) {
	cases := []struct {
		target, referer, want string
	}{
		{"https://www.example.com/api", "https://www.example.com:443/page", "same-origin"},
		{"https://www.example.com:443/api", "https://www.example.com/page", "same-origin"},
		{"https://www.example.com/api", "https://www.example.com:8443/page", "same-site"},
	}
	for _, c := range cases {
		u, err := url.Parse(c.target)
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []FetchMode{FetchModeNavigate, FetchModeCORS, FetchModeNoCors} {
			if got := detectSecFetchSiteForMode(FetchSiteAuto, u, c.referer, mode); got != c.want {
				t.Errorf("%s from Referer %s, mode %d: %q, want %q", c.target, c.referer, mode, got, c.want)
			}
		}
	}
}
