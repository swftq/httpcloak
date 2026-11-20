package site

import (
	"net/url"
	"testing"
)

// The hosts both browsers count as loopback: Chromium's net::IsLocalhost and
// Firefox's IsPotentiallyTrustworthyLoopbackHost agree on every case here.
func TestLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":       true,
		"LOCALHOST":       true,
		"localhost.":      true,
		"app.localhost":   true,
		"App.LocalHost.":  true,
		"127.0.0.1":       true,
		"127.1.2.3":       true,
		"127.255.255.255": true,
		"::1":             true,

		// Both browsers read an IPv4-mapped address as IPv6, which is loopback
		// only when it is exactly ::1. net.IP.IsLoopback says yes here.
		"::ffff:127.0.0.1": false,

		"0.0.0.0":           false,
		"::":                false,
		"192.168.1.196":     false,
		"10.0.0.1":          false,
		"169.254.229.206":   false,
		"lan-origin.test":   false,
		"example.com":       false,
		"localhost.com":     false,
		"localhost.example": false,
		"notlocalhost":      false,
		"localhost..":       false,
		"":                  false,
	} {
		if got := LoopbackHost(host); got != want {
			t.Errorf("LoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// Safari 26.3 sent Sec-Fetch-* to http://localhost, ws://127.0.0.1 and
// https://192.168.1.151, and none to http:// or ws://192.168.1.151. Chrome 156
// sent none to a LAN name and a LAN address over http://, Firefox 159 none to
// a LAN name, and both sent them to localhost.
func TestPotentiallyTrustworthy(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://example.com":        true,
		"https://192.168.1.20":       true,
		"wss://example.com":          true,
		"http://localhost:8080":      true,
		"HTTP://LOCALHOST./":         true,
		"http://app.localhost/":      true,
		"http://127.0.0.1/":          true,
		"http://127.255.255.255/":    true,
		"http://[::1]:8080/":         true,
		"ws://localhost/":            true,
		"http://192.168.1.151:8001/": false,
		"http://10.0.0.1/":           false,
		"http://lan-origin.test/":    false,
		"http://localhost.com/":      false,
		"http://0.0.0.0/":            false,
		"http://[::]/":               false,
		"http://[::ffff:127.0.0.1]/": false,
		"ws://192.168.1.20/":         false,
		"ftp://localhost/":           false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := PotentiallyTrustworthy(u); got != want {
			t.Errorf("PotentiallyTrustworthy(%s) = %v, want %v", raw, got, want)
		}
	}
	if PotentiallyTrustworthy(nil) {
		t.Error("a nil URL counted as trustworthy")
	}
}
