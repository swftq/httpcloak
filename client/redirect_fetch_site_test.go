package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Locks the per-hop rule for Sec-Fetch-Site: the value only ever moves towards
// cross-site, same-site is judged on scheme and registrable domain (never the
// port), and none and cross-site never change. Each case is one hop; the wire
// tests run whole chains. These are the session's cases, for the same rule.
func TestRedirectFetchSiteClient(t *testing.T) {
	cases := []struct {
		name           string
		site, from, to string
		want           string
	}{
		{"same-origin stays on its origin", "same-origin", "https://example.com/a", "https://example.com/b", "same-origin"},
		{"same-origin to another host on the site", "same-origin", "https://www.example.com/", "https://api.example.com/", "same-site"},
		{"same-origin to another port", "same-origin", "https://example.com/", "https://example.com:8443/", "same-site"},
		{"same-origin to another site", "same-origin", "https://example.com/", "https://example.org/", "cross-site"},
		// Same-site is schemeful, as in Chrome's SchemefulSite: one host over
		// http and https is two sites.
		{"same-origin down to http on its host", "same-origin", "https://example.com/", "http://example.com/", "cross-site"},
		{"same-origin up to https on its host", "same-origin", "http://example.com/", "https://example.com/", "cross-site"},

		{"same-site stays same-site on the site", "same-site", "https://api.example.com/", "https://www.example.com/", "same-site"},
		{"same-site never goes back to same-origin", "same-site", "https://api.example.com/r", "https://example.com/land", "same-site"},
		{"same-site to another site", "same-site", "https://api.example.com/", "https://example.org/", "cross-site"},

		{"cross-site stays cross-site back on the page's site", "cross-site", "https://example.org/", "https://example.com/", "cross-site"},
		{"cross-site stays cross-site on its own origin", "cross-site", "https://example.org/a", "https://example.org/b", "cross-site"},
		{"none stays none across sites", "none", "https://example.com/", "https://example.org/", "none"},
		{"a value no browser sends is left alone", "bogus", "https://example.com/", "https://example.org/", "bogus"},
		{"the caller's spelling is kept when the value holds", "Same-Origin", "https://example.com/a", "https://example.com/b", "Same-Origin"},
		{"the caller's spelling is still read", "Same-Origin", "https://example.com/", "https://example.org/", "cross-site"},
		{"no value stays none", "", "https://example.com/", "https://example.org/", ""},

		// Registrable domains come from the public suffix list, private
		// suffixes included, as Chrome's INCLUDE_PRIVATE_REGISTRIES has it.
		{"two hosts under one co.uk domain", "same-origin", "https://a.example.co.uk/", "https://b.example.co.uk/", "same-site"},
		{"two co.uk domains", "same-origin", "https://example.co.uk/", "https://other.co.uk/", "cross-site"},
		{"two github.io sites", "same-origin", "https://a.github.io/", "https://b.github.io/", "cross-site"},
		{"an unknown TLD's subdomain", "same-origin", "https://a.test/", "https://sub.a.test/", "same-site"},
		{"two names under an unknown TLD", "same-origin", "https://a.test/", "https://b.test/", "cross-site"},
		{"host case is ignored", "same-origin", "https://Example.COM/", "https://www.example.com/", "same-site"},

		// A host with no registrable domain is a site of its own.
		{"localhost on two ports", "same-origin", "http://localhost:8001/", "http://localhost:8002/", "same-site"},
		{"an IP address on two ports", "same-origin", "https://127.0.0.1:8001/", "https://127.0.0.1:8002/", "same-site"},
		{"an IPv6 literal on two ports", "same-origin", "https://[::1]:8001/", "https://[::1]:8002/", "same-site"},
		{"an IP address and localhost", "same-origin", "https://127.0.0.1/", "https://localhost/", "cross-site"},
		{"two IP addresses", "same-origin", "https://127.0.0.1/", "https://127.0.0.2/", "cross-site"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := redirectFetchSiteClient(c.site, c.from, c.to); got != c.want {
				t.Errorf("redirectFetchSiteClient(%q, %q, %q) = %q, want %q", c.site, c.from, c.to, got, c.want)
			}
		})
	}
}

func TestFetchSiteFromHeader(t *testing.T) {
	cases := map[string]FetchSite{
		"none":        FetchSiteNone,
		"same-origin": FetchSiteSameOrigin,
		"Same-Site":   FetchSiteSameSite,
		"cross-site":  FetchSiteCrossSite,
		"":            FetchSiteAuto,
		"bogus":       FetchSiteAuto,
	}
	for value, want := range cases {
		if got := fetchSiteFromHeader(value); got != want {
			t.Errorf("fetchSiteFromHeader(%q) = %v, want %v", value, got, want)
		}
	}
}

// The chains below are the ones captured from Chrome 156 and Firefox 159 on
// 2026-10-28, which sent the same Sec-Fetch-Site on every one of 100 requests
// moving between a page's origin, another host on its site, another port and
// another site. Each test asserts what they sent, as the receiving server saw
// it. Names are the only way to get a cross-site hop, because two ports on one
// host are one site, so the client reaches them through WithConnectTo.
//
// The capture used a.test and sub.a.test. These names have a longer
// second-level label, because the client works out the FIRST request's value
// from its Referer with extractSite, which puts sub.a.test on a site of its
// own. The hops do not use it.
const (
	fetchSitePage  = "www.site.test"  // M, and P on a second port
	fetchSiteSub   = "api.site.test"  // S, another host on M's site
	fetchSiteOther = "www.other.test" // X, another site
)

// fetchSiteChains serves every origin a chain visits. A path
// /h/<label>/<k1>/<k2>/... answers with a 302 to origin k1 at
// /h/<label>/<k2>/..., and a path with no keys left is where the chain lands.
type fetchSiteChains struct {
	bases map[string]string // origin key -> https://host:port
	keyOf map[string]string // host:port -> origin key

	mu   sync.Mutex
	hits []fetchSiteChainHit
}

type fetchSiteChainHit struct {
	key, label string
	site       []string // every Sec-Fetch-Site field, as received
}

func newFetchSiteChains(t *testing.T) *fetchSiteChains {
	t.Helper()
	o := &fetchSiteChains{bases: map[string]string{}, keyOf: map[string]string{}}
	start := func() int {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(o.serve))
		srv.EnableHTTP2 = true
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv.Listener.Addr().(*net.TCPAddr).Port
	}
	main, other := start(), start()
	o.add("M", fetchSitePage, main)
	o.add("S", fetchSiteSub, main)
	o.add("X", fetchSiteOther, main)
	o.add("P", fetchSitePage, other)
	return o
}

func (o *fetchSiteChains) add(key, host string, port int) {
	hostport := net.JoinHostPort(host, strconv.Itoa(port))
	o.bases[key] = "https://" + hostport
	o.keyOf[hostport] = key
}

func (o *fetchSiteChains) serve(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	rest, ok := strings.CutPrefix(r.URL.Path, "/h/")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	label, keys, _ := strings.Cut(rest, "/")
	o.mu.Lock()
	o.hits = append(o.hits, fetchSiteChainHit{key: o.keyOf[r.Host], label: label, site: r.Header.Values("Sec-Fetch-Site")})
	o.mu.Unlock()
	if keys == "" {
		io.WriteString(w, "ok")
		return
	}
	next, after, _ := strings.Cut(keys, "/")
	location := o.bases[next] + "/h/" + label
	if after != "" {
		location += "/" + after
	}
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// url is where a chain through the given origins starts.
func (o *fetchSiteChains) url(label string, chain ...string) string {
	return o.bases[chain[0]] + "/h/" + strings.Join(append([]string{label}, chain[1:]...), "/")
}

// check fails the test unless the chain called label visited the origins in
// chain, in order, each sending the Sec-Fetch-Site in want ("" for none at
// all) in exactly one field.
func (o *fetchSiteChains) check(t *testing.T, label string, chain []string, want []string) {
	t.Helper()
	o.mu.Lock()
	var hops []fetchSiteChainHit
	for _, h := range o.hits {
		if h.label == label {
			hops = append(hops, h)
		}
	}
	o.mu.Unlock()
	var got []string
	for i, h := range hops {
		if i >= len(chain) || h.key != chain[i] {
			t.Fatalf("%s: request %d went to %s, want the chain %v", label, i+1, h.key, chain)
		}
		switch len(h.site) {
		case 0:
			got = append(got, "")
		case 1:
			got = append(got, h.site[0])
		default:
			t.Fatalf("%s: request %d to %s carried %d Sec-Fetch-Site fields %q", label, i+1, h.key, len(h.site), h.site)
		}
	}
	if len(hops) != len(chain) {
		t.Fatalf("%s: %d requests arrived, want %d through %v", label, len(hops), len(chain), chain)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s through %v sent Sec-Fetch-Site %q, want %q", label, chain, got, want)
	}
}

// The redirect code is the same for every preset, but each preset builds its
// own header block, so every browser family the library mimics is covered.
var fetchSitePresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

var fetchSiteProtocols = []struct {
	name  string
	force Option
}{
	{"h1", WithForceHTTP1()},
	{"h2", WithForceHTTP2()},
}

func newFetchSiteClient(t *testing.T, preset string, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{
		WithInsecureSkipVerify(), // httptest's certificate
		WithPreferIPv4(),
		WithTimeout(10 * time.Second),
		WithConnectTo(fetchSitePage, "127.0.0.1"),
		WithConnectTo(fetchSiteSub, "127.0.0.1"),
		WithConnectTo(fetchSiteOther, "127.0.0.1"),
	}, opts...)
	c := NewClient(preset, opts...)
	t.Cleanup(func() { c.Close() })
	return c
}

// Before, every hop repeated the first request's value, so a fetch() that was
// redirected to another site still said same-origin there and on the way back.
func TestClientRedirectHopFetchSite(t *testing.T) {
	type chainCase struct {
		label string
		mode  FetchMode
		page  bool // sent with the Referer of a page on M
		chain []string
		want  []string
	}
	cases := []chainCase{
		// A navigation the user typed sends none on every hop, wherever the
		// chain goes.
		{"typed", FetchModeNavigate, false, []string{"M", "X", "S", "M"}, []string{"none", "none", "none", "none"}},
		{"same", FetchModeCORS, true, []string{"M", "M"}, []string{"same-origin", "same-origin"}},
		{"sub", FetchModeCORS, true, []string{"M", "S"}, []string{"same-origin", "same-site"}},
		{"port", FetchModeCORS, true, []string{"M", "P"}, []string{"same-origin", "same-site"}},
		{"xs", FetchModeCORS, true, []string{"M", "X"}, []string{"same-origin", "cross-site"}},
		// A chain that comes back to the page's origin keeps what it reached.
		{"sub-back", FetchModeCORS, true, []string{"M", "S", "M"}, []string{"same-origin", "same-site", "same-site"}},
		{"port-back", FetchModeCORS, true, []string{"M", "P", "M"}, []string{"same-origin", "same-site", "same-site"}},
		{"xs-back", FetchModeCORS, true, []string{"M", "X", "M"}, []string{"same-origin", "cross-site", "cross-site"}},
		{"sub-xs-back", FetchModeCORS, true, []string{"M", "S", "X", "M"}, []string{"same-origin", "same-site", "cross-site", "cross-site"}},
		{"first-sub-back", FetchModeCORS, true, []string{"S", "M"}, []string{"same-site", "same-site"}},
		{"first-xs-back", FetchModeCORS, true, []string{"X", "M"}, []string{"cross-site", "cross-site"}},
		{"first-xs-same", FetchModeCORS, true, []string{"X", "X"}, []string{"cross-site", "cross-site"}},
		// A link the user clicked on the page follows the same rule as a
		// fetch(); only a typed navigation is none.
		{"link-xs-back", FetchModeNavigate, true, []string{"M", "X", "M"}, []string{"same-origin", "cross-site", "cross-site"}},
		{"link-sub-back", FetchModeNavigate, true, []string{"M", "S", "M"}, []string{"same-origin", "same-site", "same-site"}},
	}
	for _, preset := range fetchSitePresets {
		for _, p := range fetchSiteProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				o := newFetchSiteChains(t)
				c := newFetchSiteClient(t, preset, p.force)
				for _, tc := range cases {
					req := &Request{Method: "GET", URL: o.url(tc.label, tc.chain...), FetchMode: tc.mode}
					if tc.page {
						req.Referer = o.bases["M"] + "/app/page.html"
					}
					if _, err := c.Do(context.Background(), req); err != nil {
						t.Fatalf("%s: %v", tc.label, err)
					}
					o.check(t, tc.label, tc.chain, tc.want)
				}
			})
		}
	}
}

// With WithTLSOnly the client builds no Sec-Fetch-Site, so only one the caller
// set can reach the wire. It follows the same rule, under the caller's
// spelling, and a request without one sends none on any hop.
func TestClientRedirectHopFetchSiteTLSOnly(t *testing.T) {
	for _, preset := range fetchSitePresets {
		for _, p := range fetchSiteProtocols {
			t.Run(preset+"/"+p.name, func(t *testing.T) {
				o := newFetchSiteChains(t)
				c := newFetchSiteClient(t, preset, p.force, WithTLSOnly())
				chain := []string{"M", "S", "X", "M"}
				if _, err := c.Do(context.Background(), &Request{Method: "GET", URL: o.url("set", chain...),
					Headers: map[string][]string{"sec-fetch-site": {"same-origin"}}}); err != nil {
					t.Fatal(err)
				}
				o.check(t, "set", chain, []string{"same-origin", "same-site", "cross-site", "cross-site"})

				if _, err := c.Do(context.Background(), &Request{Method: "GET", URL: o.url("unset", chain...)}); err != nil {
					t.Fatal(err)
				}
				o.check(t, "unset", chain, []string{"", "", "", ""})
			})
		}
	}
}
