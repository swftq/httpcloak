// Package site works out whether two URLs share an origin or a site, the way
// browsers do for Sec-Fetch-Site.
//
// It exists because client.Client and the fingerprint package each guessed
// the registrable domain without the public suffix list. The client took any
// second-level label of three characters or fewer for part of a two-label
// suffix, so it sent www.cnn.com to edition.cnn.com as cross-site. The
// fingerprint package took the last two labels, so session warmup sent every
// .co.uk site to every other as same-site. Both treated a.github.io and
// b.github.io as one site.
package site

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// SameOrigin reports whether a and b have the same origin: the same scheme,
// host and port. A browser's URL parser lowercases the host and drops a
// scheme's default port, so neither makes a difference here:
// https://WWW.example.com:443/ and https://www.example.com/ are one origin, as
// they are to Chromium's url::Origin.
func SameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		port(a) == port(b)
}

// port returns u's port, or the default port of its scheme when it has none.
func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// RegistrableDomain returns the part of host that names its site: its eTLD+1
// by the public suffix list, private suffixes included, so a.github.io and
// b.github.io are two sites. A name under a TLD the list does not know takes
// its last label for the suffix, so sub.a.test is on a.test. A host with no
// registrable domain, such as an IP address, localhost or a public suffix
// itself, is a site of its own and comes back whole.
//
// That is Chromium's SchemefulSite, which asks GetDomainAndRegistry with
// INCLUDE_PRIVATE_REGISTRIES and falls back to the host, and Gecko's base
// domain agrees. Both read a host the way a URL parser leaves it, so the
// result is lowercase. Both also look a name up without one trailing dot and
// hand the dot back, so www.example.com. is on example.com., which is another
// site than example.com.
//
// host is a URL's Hostname: no port, and no brackets around an IPv6 address.
func RegistrableDomain(host string) string {
	host = strings.ToLower(host)
	if net.ParseIP(host) != nil {
		return host
	}
	name, trailingDot := strings.CutSuffix(host, ".")
	domain, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return host
	}
	if trailingDot {
		domain += "."
	}
	return domain
}
