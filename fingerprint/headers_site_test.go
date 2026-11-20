package fingerprint

import "testing"

// calculateFetchSite took a host's last two labels for its registrable
// domain, and cut the port at the host's last colon, which also cut into an
// IPv6 address with no port. The expected values are Chromium 156's
// GetOriginRelation: url::Origin, then SchemefulSite over the public suffix
// list with private suffixes included. Session warmup's wire test covers the
// cases a test server can reach; these need port 443 or a second IPv6 address.
func TestCalculateFetchSiteRegistrableDomain(t *testing.T) {
	cases := []struct {
		referrer, target string
		want             FetchSite
	}{
		{"https://www.example.co.uk/", "https://other.co.uk/x.png", FetchSiteCrossSite},
		{"https://www.example.co.uk/", "https://co.uk/x.png", FetchSiteCrossSite},
		{"https://www.example.co.uk/", "https://cdn.example.co.uk/x.png", FetchSiteSameSite},
		{"https://a.github.io/", "https://b.github.io/x.png", FetchSiteCrossSite},
		{"https://192.168.0.1/", "https://10.0.0.1/x.png", FetchSiteCrossSite},
		{"https://[::1]/", "https://[::2]/x.png", FetchSiteCrossSite},
		{"https://[2001:db8::1]/", "https://[2001:db8::2]/x.png", FetchSiteCrossSite},
		{"https://[::1]:8443/", "https://[::1]/x.png", FetchSiteSameSite},

		// A URL parser lowercases the host and drops a default port.
		{"https://WWW.Example.com/", "https://www.example.com/x.png", FetchSiteSameOrigin},
		{"https://www.example.com:443/", "https://www.example.com/x.png", FetchSiteSameOrigin},
		{"http://www.example.com:80/", "http://www.example.com/x.png", FetchSiteSameOrigin},
		{"https://www.example.com:8443/", "https://www.example.com/x.png", FetchSiteSameSite},
	}
	for _, c := range cases {
		if got := calculateFetchSite(c.referrer, c.target); got != c.want {
			t.Errorf("calculateFetchSite(%q, %q) = %q, want %q", c.referrer, c.target, got, c.want)
		}
	}
}

func TestGetRegistrableDomainHostPort(t *testing.T) {
	cases := []struct{ host, want string }{
		{"www.example.co.uk:8443", "example.co.uk"},
		{"a.github.io", "a.github.io"},
		{"10.0.0.1:443", "10.0.0.1"},
		{"[::1]", "::1"},
		{"[::1]:8443", "::1"},
		{"WWW.EXAMPLE.COM", "example.com"},
	}
	for _, c := range cases {
		if got := getRegistrableDomain(c.host); got != c.want {
			t.Errorf("getRegistrableDomain(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}
