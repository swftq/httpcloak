package session

import "testing"

// Locks the default referrer policy, strict-origin-when-cross-origin, for
// warmup's subresources: the page URL minus fragment and credentials on the
// page's own origin, the page's origin (trailing slash) on any other, nothing
// from an https page to an http URL. Same rule as redirectReferer, judged
// against the page.
func TestSubresourceReferer(t *testing.T) {
	cases := []struct {
		name      string
		pageURL   string
		targetURL string
		want      string
	}{
		{"same-origin keeps full URL", "https://example.com/a/b?q=1", "https://example.com/s.css", "https://example.com/a/b?q=1"},
		{"same-origin strips fragment", "https://example.com/a?q=1#frag", "https://example.com/s.css", "https://example.com/a?q=1"},
		{"same-origin strips credentials", "https://user:pass@example.com/a", "https://example.com/s.css", "https://example.com/a"},
		{"same-origin page default port dropped", "https://example.com:443/a", "https://example.com/s.css", "https://example.com/a"},
		{"same-origin target default port written out", "https://example.com/a", "https://example.com:443/s.css", "https://example.com/a"},
		{"same-site -> origin only", "https://www.example.com/a?q=1", "https://cdn.example.com/s.css", "https://www.example.com/"},
		{"cross-site -> origin only", "https://example.com/a?q=1", "https://cdn.other.com/app.js", "https://example.com/"},
		{"other port -> origin with its port", "https://example.com:8443/a", "https://example.com/logo.png", "https://example.com:8443/"},
		{"cross-origin default https port dropped", "https://example.com:443/a", "https://other.com/f.woff2", "https://example.com/"},
		{"cross-origin strips creds+fragment keeps port", "https://user:pass@example.com:8443/a#f", "https://other.com/s.css", "https://example.com:8443/"},
		{"cross-origin host lowercased", "https://WWW.Example.COM/a", "https://other.com/s.css", "https://www.example.com/"},
		{"cross-origin IPv6 literal keeps brackets", "https://[::1]:8443/a", "https://b.test/s.css", "https://[::1]:8443/"},
		{"https page -> http same host omits", "https://example.com/a", "http://example.com/logo.png", ""},
		{"https page -> http other host omits", "https://example.com/a", "http://other.com/app.js", ""},
		{"http page same-origin keeps full URL", "http://example.com:8080/a?q=2#f", "http://example.com:8080/s.css", "http://example.com:8080/a?q=2"},
		{"http page cross-origin -> origin only", "http://example.com/a", "http://other.com/s.css", "http://example.com/"},
		{"http page -> https same host sends http origin", "http://example.com/a", "https://example.com/s.css", "http://example.com/"},
		{"not an http page omits", "about:blank", "https://example.com/s.css", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := subresourceReferer(c.pageURL, c.targetURL); got != c.want {
				t.Fatalf("subresourceReferer(%q, %q) = %q, want %q", c.pageURL, c.targetURL, got, c.want)
			}
		})
	}
}
