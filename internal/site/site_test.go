package site

import (
	"net/url"
	"testing"
)

// The expected values are Chromium 156's: SchemefulSite asks
// GetDomainAndRegistry with INCLUDE_PRIVATE_REGISTRIES, which treats an unknown
// TLD's last label as its registry and returns nothing for an IP address or a
// public suffix, and the site then falls back to the host.
func TestRegistrableDomain(t *testing.T) {
	cases := []struct{ host, want string }{
		{"www.cnn.com", "cnn.com"},
		{"edition.cnn.com", "cnn.com"},
		// A short second-level label is not a suffix unless the list says so.
		{"api.x.com", "x.com"},
		{"x.com", "x.com"},
		{"mail.abc.xyz", "abc.xyz"},
		{"a.b.example.co.uk", "example.co.uk"},
		{"shop.example.com.au", "example.com.au"},

		// Private suffixes count: each github.io user is a site.
		{"a.github.io", "a.github.io"},
		{"x.a.github.io", "a.github.io"},
		{"foo.blogspot.com", "foo.blogspot.com"},

		// A public suffix has no registrable domain and is a site of its own.
		{"co.uk", "co.uk"},
		{"github.io", "github.io"},

		// Wildcard and exception rules: *.ck makes b.ck a suffix, !www.ck
		// takes www.ck back out.
		{"a.b.ck", "a.b.ck"},
		{"x.www.ck", "www.ck"},

		// A TLD the list does not know takes its last label for the suffix.
		{"a.test", "a.test"},
		{"sub.a.test", "a.test"},
		{"sub.localhost", "sub.localhost"},

		// No registrable domain: the host is the site.
		{"localhost", "localhost"},
		{"127.0.0.1", "127.0.0.1"},
		{"10.0.0.1", "10.0.0.1"},
		{"::1", "::1"},

		// A URL parser lowercases the host.
		{"WWW.Example.CO.UK", "example.co.uk"},
		{"2001:DB8::1", "2001:db8::1"},

		// One trailing dot is looked past and kept.
		{"www.example.com.", "example.com."},
		{"example.com.", "example.com."},
		{"co.uk.", "co.uk."},
	}
	for _, c := range cases {
		if got := RegistrableDomain(c.host); got != c.want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

// Same-site is the scheme plus RegistrableDomain, so two hosts are on one site
// exactly when their registrable domains match. These pairs are the ones the
// guesses this package replaced got wrong.
func TestRegistrableDomainSites(t *testing.T) {
	cases := []struct {
		a, b string
		same bool
	}{
		{"www.cnn.com", "edition.cnn.com", true},
		{"x.com", "api.x.com", true},
		{"a.test", "sub.a.test", true},
		{"www.example.co.uk", "other.co.uk", false},
		{"www.example.co.uk", "co.uk", false},
		{"a.github.io", "b.github.io", false},
		{"a.github.io", "github.io", false},
		{"192.168.0.1", "10.0.0.1", false},
		{"localhost", "127.0.0.1", false},
		{"www.example.com.", "api.example.com.", true},
		{"www.example.com.", "api.example.com", false},
	}
	for _, c := range cases {
		if got := RegistrableDomain(c.a) == RegistrableDomain(c.b); got != c.same {
			t.Errorf("%s and %s on one site: %v, want %v", c.a, c.b, got, c.same)
		}
	}
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"https://example.com/a", "https://example.com/b?q=1", true},
		{"https://WWW.Example.com/", "https://www.example.com/", true},
		{"https://example.com:443/", "https://example.com/", true},
		{"http://example.com:80/", "http://example.com/", true},
		{"https://[::1]:8443/", "https://[::1]:8443/x", true},
		{"https://[::A]/", "https://[::a]/", true},

		{"https://example.com:8443/", "https://example.com/", false},
		{"http://example.com/", "https://example.com/", false},
		{"http://example.com:443/", "https://example.com/", false},
		{"https://www.example.com/", "https://example.com/", false},
		{"https://example.com./", "https://example.com/", false},
	}
	for _, c := range cases {
		a, err := url.Parse(c.a)
		if err != nil {
			t.Fatal(err)
		}
		b, err := url.Parse(c.b)
		if err != nil {
			t.Fatal(err)
		}
		if got := SameOrigin(a, b); got != c.want {
			t.Errorf("SameOrigin(%s, %s) = %v, want %v", c.a, c.b, got, c.want)
		}
		if got := SameOrigin(b, a); got != c.want {
			t.Errorf("SameOrigin(%s, %s) = %v, want %v", c.b, c.a, got, c.want)
		}
	}
}
