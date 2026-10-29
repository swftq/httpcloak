package session

import (
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// Locks the per-hop rule for Sec-Fetch-Site: the value only ever moves towards
// cross-site, same-site is judged on scheme and registrable domain (never the
// port), and none and cross-site never change. Each case is one hop; the wire
// tests run whole chains.
func TestRedirectFetchSite(t *testing.T) {
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
			if got := redirectFetchSite(c.site, c.from, c.to); got != c.want {
				t.Errorf("redirectFetchSite(%q, %q, %q) = %q, want %q", c.site, c.from, c.to, got, c.want)
			}
		})
	}
}

// The exact list is the caller's slice. It is handed back untouched when the
// hop changes nothing, and copied before a value moves, so the caller's own
// list still says what the first request sent.
func TestExactHeadersFetchSiteForHop(t *testing.T) {
	exact := []fingerprint.HeaderPair{
		{Key: "user-agent", Value: "mirror/1"},
		{Key: "sec-fetch-site", Value: "same-origin"},
		{Key: "accept", Value: "*/*"},
	}

	if got := exactHeadersFetchSiteForHop(exact, "https://a.test/r", "https://a.test/land"); &got[0] != &exact[0] {
		t.Error("a same-origin hop copied the list; nothing in it changes")
	}
	withoutPair := []fingerprint.HeaderPair{{Key: "accept", Value: "*/*"}}
	if got := exactHeadersFetchSiteForHop(withoutPair, "https://a.test/r", "https://b.test/land"); len(got) != 1 || &got[0] != &withoutPair[0] {
		t.Errorf("a list without Sec-Fetch-Site came back as %v; the hop adds none", got)
	}

	got := exactHeadersFetchSiteForHop(exact, "https://a.test/r", "https://b.test/land")
	want := []fingerprint.HeaderPair{
		{Key: "user-agent", Value: "mirror/1"},
		{Key: "sec-fetch-site", Value: "cross-site"},
		{Key: "accept", Value: "*/*"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pair %d is %v, want %v: the value moves in its own slot and spelling", i, got[i], want[i])
		}
	}
	if exact[1].Value != "same-origin" {
		t.Errorf("the caller's list now says %q; it must keep what the first request sent", exact[1].Value)
	}
}
