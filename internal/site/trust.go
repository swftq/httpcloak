package site

import (
	"net/netip"
	"net/url"
	"strings"
)

// PotentiallyTrustworthy reports whether u is a potentially trustworthy URL,
// the test Fetch Metadata makes before adding any Sec-Fetch-* header and
// Chromium makes before adding any client hint: https and wss always, http
// and ws only to a host LoopbackHost accepts (Secure Contexts 3.1-3.2).
// Chromium: net::IsUrlPotentiallyTrustworthy. Gecko:
// nsMixedContentBlocker::IsPotentiallyTrustworthyOrigin. WebKit:
// SecurityOrigin::isPotentiallyTrustworthy, which takes no trailing dot after
// localhost. No other scheme reaches a request here; it and a nil URL are not
// trustworthy.
func PotentiallyTrustworthy(u *url.URL) bool {
	if u == nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "wss":
		return true
	case "http", "ws":
		return LoopbackHost(u.Hostname())
	}
	return false
}

// LoopbackHost reports whether host is a loopback host as Chrome
// (net::IsLocalhost) and Firefox (IsPotentiallyTrustworthyLoopbackHost) both
// read it: localhost or a name under .localhost, in any case and with or
// without a trailing dot, an IPv4 literal in 127.0.0.0/8, or exactly ::1.
// Neither browser counts an IPv4-mapped ::ffff:127.0.0.1, which
// net.IP.IsLoopback would.
func LoopbackHost(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4() {
			return addr.As4()[0] == 127
		}
		return addr == netip.IPv6Loopback()
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}
