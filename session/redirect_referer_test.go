package session

import "testing"

// Locks Chrome's default strict-origin-when-cross-origin Referer policy for the
// redirect path (issue #70), applied the way Chrome 156 and Firefox 159 apply
// it on a hop: to the Referer the hop before carried, judged against the new
// URL. The full Referer when the new URL is on its origin, the origin alone
// (trailing slash) when it is not, nothing for an https Referer going to http.
func TestRedirectReferer(t *testing.T) {
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
			got := redirectReferer(c.referrer, c.nextURL)
			if got != c.want {
				t.Fatalf("redirectReferer(%q, %q) = %q, want %q", c.referrer, c.nextURL, got, c.want)
			}
		})
	}
}

// The hop's Referer is read from the caller's headers under whatever spelling
// they used, and the pick must not change with map iteration order.
func TestRefererHeader(t *testing.T) {
	cases := []struct {
		name      string
		headers   map[string][]string
		wantKey   string
		wantValue string
	}{
		{"none", map[string][]string{"Accept": {"*/*"}}, "", ""},
		{"canonical", map[string][]string{"Referer": {"https://a.example/"}}, "Referer", "https://a.example/"},
		{"lowercase", map[string][]string{"referer": {"https://a.example/"}}, "referer", "https://a.example/"},
		{"first value", map[string][]string{"Referer": {"https://a.example/", "https://b.example/"}}, "Referer", "https://a.example/"},
		{"canonical wins over another spelling", map[string][]string{"referer": {"https://b.example/"}, "Referer": {"https://a.example/"}}, "Referer", "https://a.example/"},
		{"lowest spelling wins otherwise", map[string][]string{"referer": {"https://b.example/"}, "REFERER": {"https://a.example/"}}, "REFERER", "https://a.example/"},
		{"empty value keeps the name", map[string][]string{"Referer": {}}, "Referer", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for range 20 { // map order is randomised; a wrong pick shows up within a few tries
				key, value := refererHeader(c.headers)
				if key != c.wantKey || value != c.wantValue {
					t.Fatalf("refererHeader(%v) = %q, %q, want %q, %q", c.headers, key, value, c.wantKey, c.wantValue)
				}
			}
		})
	}
}
