package transport

import (
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// PageFetchHeaders is the rule; the session's wire tests send it for every
// browser family. This table covers the edges a wire test reaches only with a
// server per name: the public suffix list, IP literals, default ports, schemes
// and the gates that keep it off requests sending no Sec-Fetch-*.
func TestPageFetchHeaders(t *testing.T) {
	tr := NewTransport("chrome-latest")
	t.Cleanup(tr.Close)

	fetch := func(ref string) map[string][]string {
		return map[string][]string{"Referer": {ref}, "Accept": {"application/json"}}
	}
	form := func(ref string) map[string][]string {
		return map[string][]string{"Referer": {ref}, "Content-Type": {"application/x-www-form-urlencoded"}}
	}
	tlsOnly := true
	cases := []struct {
		name         string
		req          Request
		site, origin string
	}{
		// No page named: outside cors mode the pipeline's own values stand.
		{"navigation without a Referer", Request{URL: "https://a.test/x"}, "", ""},
		{"form POST without a Referer", Request{URL: "https://a.test/x", Method: "POST", Headers: map[string][]string{
			"Content-Type": {"application/x-www-form-urlencoded"}}}, "", ""},
		{"no-cors POST without a Referer", Request{URL: "https://a.test/x", Method: "POST", Headers: map[string][]string{
			"Sec-Fetch-Mode": {"no-cors"}, "Content-Type": {"text/plain"}}}, "", ""},
		{"websocket without a Referer", Request{URL: "https://a.test/x", Headers: map[string][]string{"Sec-Fetch-Mode": {"websocket"}}}, "", ""},
		{"empty Referer", Request{URL: "https://a.test/x", Headers: map[string][]string{"Referer": {""}}}, "", ""},
		{"Referer that is not an http URL", Request{URL: "https://a.test/x", Headers: map[string][]string{"Referer": {"android-app://com.example/"}}}, "", ""},
		{"relative Referer", Request{URL: "https://a.test/x", Headers: map[string][]string{"Referer": {"/page"}}}, "", ""},
		{"a Referer key with no values", Request{URL: "https://a.test/x", Headers: map[string][]string{"Referer": {}}}, "", ""},

		// A cors request naming no page takes its own URL's origin for one.
		{"fetch without a Referer", Request{URL: "https://a.test/x", Headers: map[string][]string{"Accept": {"application/json"}}}, "same-origin", ""},
		{"fetch HEAD without a Referer", Request{URL: "https://a.test/x", Method: "HEAD", Headers: map[string][]string{"Accept": {"application/json"}}}, "same-origin", ""},
		{"fetch POST without a Referer", Request{URL: "https://a.test/x", Method: "POST", Headers: map[string][]string{"Content-Type": {"application/json"}}}, "same-origin", "https://a.test"},
		{"DELETE without a Referer", Request{URL: "https://a.test/x", Method: "delete"}, "same-origin", "https://a.test"},
		{"fetch OPTIONS without a Referer", Request{URL: "https://a.test/x", Method: "OPTIONS", Headers: map[string][]string{"Accept": {"*/*"}}}, "same-origin", "https://a.test"},
		{"cors pinned without a Referer", Request{URL: "https://a.test/x", Method: "POST", Headers: map[string][]string{
			"sec-fetch-mode": {"CORS"}, "Content-Type": {"application/x-www-form-urlencoded"}}}, "same-origin", "https://a.test"},
		{"no Referer, URL on another port", Request{URL: "https://A.test:8443/x", Method: "POST", Headers: map[string][]string{"Content-Type": {"application/json"}}}, "same-origin", "https://a.test:8443"},
		{"no Referer, default port written", Request{URL: "https://a.test:443/x", Method: "POST", Headers: map[string][]string{"Content-Type": {"application/json"}}}, "same-origin", "https://a.test"},
		{"no Referer, plain http", Request{URL: "http://a.test:8080/x", Method: "PUT", Headers: map[string][]string{"Content-Type": {"application/json"}}}, "same-origin", "http://a.test:8080"},
		{"no Referer, IPv6", Request{URL: "https://[::1]:8443/x", Method: "POST", Headers: map[string][]string{"Content-Type": {"application/json"}}}, "same-origin", "https://[::1]:8443"},
		{"empty Referer on a fetch", Request{URL: "https://a.test/x", Headers: map[string][]string{"Referer": {""}, "Accept": {"application/json"}}}, "same-origin", ""},
		{"unusable Referer on a fetch POST", Request{URL: "https://a.test/x", Method: "POST", Headers: map[string][]string{
			"Referer": {"about:client"}, "Content-Type": {"application/json"}}}, "same-origin", "https://a.test"},
		{"caller's same-origin without a Referer", Request{URL: "https://a.test/x", Method: "POST", Headers: map[string][]string{
			"sec-fetch-site": {"Same-Origin"}, "Content-Type": {"application/json"}}}, "", "https://a.test"},
		{"caller's other site without a Referer", Request{URL: "https://a.test/x", Method: "POST", Headers: map[string][]string{
			"Sec-Fetch-Site": {"cross-site"}, "Content-Type": {"application/json"}}}, "", ""},
		{"caller's empty site without a Referer", Request{URL: "https://a.test/x", Method: "POST", Headers: map[string][]string{
			"Sec-Fetch-Site": {""}, "Content-Type": {"application/json"}}}, "", ""},

		// The relation, the same in every mode.
		{"navigation, same origin", Request{URL: "https://a.test/x", Headers: map[string][]string{"Referer": {"https://a.test/p?q=1#f"}}}, "same-origin", ""},
		{"navigation, same site", Request{URL: "https://a.test/x", Headers: map[string][]string{"referer": {"https://sub.a.test/"}}}, "same-site", ""},
		{"navigation, other port", Request{URL: "https://a.test/x", Headers: map[string][]string{"Referer": {"https://a.test:8443/"}}}, "same-site", ""},
		{"navigation, cross site", Request{URL: "https://a.test/x", Headers: map[string][]string{"Referer": {"https://b.test/"}}}, "cross-site", ""},
		{"navigation from an http page", Request{URL: "https://a.test/x", Headers: map[string][]string{"Referer": {"http://a.test/"}}}, "cross-site", ""},
		{"explicit default port", Request{URL: "https://a.test/x", Method: "POST", Headers: form("https://a.test:443/p")}, "same-origin", "https://a.test"},
		{"host case", Request{URL: "https://A.Test/x", Headers: map[string][]string{"Referer": {"HTTPS://a.TEST/p"}}}, "same-origin", ""},
		{"userinfo in the Referer", Request{URL: "https://a.test/x", Headers: map[string][]string{"Referer": {"https://u:p@a.test/p"}}}, "same-origin", ""},

		// Sites by the public suffix list, private suffixes included.
		{"two-label public suffix, same site", Request{URL: "https://shop.example.co.uk/x", Headers: fetch("https://www.example.co.uk/")}, "same-site", "https://www.example.co.uk"},
		{"two-label public suffix, cross site", Request{URL: "https://shop.example.co.uk/x", Headers: fetch("https://www.other.co.uk/")}, "cross-site", "https://www.other.co.uk"},
		{"short second-level label", Request{URL: "https://edition.cnn.com/x", Headers: fetch("https://www.cnn.com/")}, "same-site", "https://www.cnn.com"},
		{"private suffix, cross site", Request{URL: "https://alice.github.io/x", Headers: fetch("https://bob.github.io/")}, "cross-site", "https://bob.github.io"},
		{"private suffix, same site", Request{URL: "https://alice.github.io/x", Headers: fetch("https://www.alice.github.io/")}, "same-site", "https://www.alice.github.io"},
		{"localhost on two ports", Request{URL: "http://localhost:8080/x", Headers: fetch("http://localhost:3000/")}, "same-site", "http://localhost:3000"},
		{"two IPv4 addresses", Request{URL: "https://127.0.0.2/x", Headers: fetch("https://127.0.0.1/")}, "cross-site", "https://127.0.0.1"},
		{"IPv6 on two ports", Request{URL: "https://[::1]:8443/x", Headers: fetch("https://[::1]/")}, "same-site", "https://[::1]"},
		{"IPv6 same origin", Request{URL: "https://[::1]:8443/x", Headers: fetch("https://[::1]:8443/p")}, "same-origin", ""},

		// Origin, by Fetch's rule.
		{"fetch GET, same origin", Request{URL: "https://a.test/x", Headers: fetch("https://a.test/p")}, "same-origin", ""},
		{"fetch GET, same site", Request{URL: "https://a.test/x", Headers: fetch("https://sub.a.test/")}, "same-site", "https://sub.a.test"},
		{"fetch GET, other port", Request{URL: "https://a.test/x", Headers: fetch("https://a.test:8443/")}, "same-site", "https://a.test:8443"},
		{"fetch POST, same origin", Request{URL: "https://a.test/x", Method: "POST",
			Headers: map[string][]string{"Referer": {"https://a.test/p"}, "Content-Type": {"application/json"}}}, "same-origin", "https://a.test"},
		{"fetch HEAD, same origin", Request{URL: "https://a.test/x", Method: "HEAD", Headers: fetch("https://a.test/p")}, "same-origin", ""},
		{"fetch to http from an https page", Request{URL: "http://b.test/x", Headers: fetch("https://a.test/")}, "cross-site", "https://a.test"},
		{"form POST, same origin", Request{URL: "https://a.test/x", Method: "POST", Headers: form("https://a.test/p")}, "same-origin", "https://a.test"},
		{"form POST, cross site", Request{URL: "https://a.test/x", Method: "POST", Headers: form("https://b.test/")}, "cross-site", "https://b.test"},
		{"form POST to http from an https page", Request{URL: "http://a.test/x", Method: "POST", Headers: form("https://a.test/p")}, "cross-site", "null"},
		{"form POST to https from an http page", Request{URL: "https://a.test/x", Method: "POST", Headers: form("http://a.test/p")}, "cross-site", "http://a.test"},
		{"form POST within http", Request{URL: "http://a.test:8080/x", Method: "POST", Headers: form("http://a.test:8080/p")}, "same-origin", "http://a.test:8080"},
		{"no-cors GET, cross site", Request{URL: "https://a.test/x", Headers: map[string][]string{
			"Referer": {"https://b.test/"}, "Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Dest": {"image"}}}, "cross-site", ""},
		{"no-cors POST, cross site", Request{URL: "https://a.test/x", Method: "POST", Headers: map[string][]string{
			"Referer": {"https://b.test/"}, "Sec-Fetch-Mode": {"no-cors"}, "Content-Type": {"text/plain"}}}, "cross-site", "https://b.test"},
		{"iframe GET, cross site", Request{URL: "https://a.test/x", Headers: map[string][]string{
			"Referer": {"https://b.test/"}, "Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}}}, "cross-site", ""},
		{"navigate pinned over a JSON Accept", Request{URL: "https://a.test/x", Headers: map[string][]string{
			"Referer": {"https://b.test/"}, "Accept": {"application/json"}, "sec-fetch-mode": {"Navigate"}}}, "cross-site", ""},
		{"websocket, same origin", Request{URL: "https://a.test/x", Headers: map[string][]string{
			"Referer": {"https://a.test/p"}, "Sec-Fetch-Mode": {"websocket"}}}, "same-origin", "https://a.test"},

		// The caller's own values win, and an Origin can name the page.
		{"caller's Sec-Fetch-Site", Request{URL: "https://a.test/x", Headers: map[string][]string{
			"Referer": {"https://b.test/"}, "Accept": {"application/json"}, "sec-fetch-site": {"same-origin"}}}, "", "https://b.test"},
		{"caller's empty Sec-Fetch-Site", Request{URL: "https://a.test/x", Headers: map[string][]string{
			"Referer": {"https://b.test/"}, "Sec-Fetch-Site": {""}}}, "", ""},
		{"caller's Origin", Request{URL: "https://a.test/x", Headers: map[string][]string{
			"Referer": {"https://sub.a.test/"}, "Accept": {"application/json"}, "origin": {"https://elsewhere.test"}}}, "same-site", ""},
		{"Origin names the page", Request{URL: "https://a.test/x", Headers: map[string][]string{
			"Origin": {"https://sub.a.test"}, "Accept": {"application/json"}}}, "same-site", ""},
		{"Origin names the page for a navigation", Request{URL: "https://a.test/x", Headers: map[string][]string{
			"Origin": {"https://a.test"}}}, "same-origin", ""},
		{"Origin stands in for an unusable Referer", Request{URL: "https://a.test/x", Headers: map[string][]string{
			"Referer": {"about:client"}, "Origin": {"https://b.test"}}}, "cross-site", ""},
		{"Referer wins over Origin", Request{URL: "https://a.test/x", Headers: map[string][]string{
			"Referer": {"https://a.test/p"}, "Origin": {"https://b.test"}}}, "same-origin", ""},
		{"null Origin names no page", Request{URL: "https://a.test/x", Headers: map[string][]string{
			"Origin": {"null"}, "Accept": {"application/json"}}}, "", ""},

		// Requests that go out with no Sec-Fetch-* get nothing.
		{"TLS-only", Request{URL: "https://a.test/x", TLSOnly: &tlsOnly, Headers: fetch("https://b.test/")}, "", ""},
		{"ExactHeaders", Request{URL: "https://a.test/x", Headers: fetch("https://b.test/"),
			ExactHeaders: []fingerprint.HeaderPair{{Key: "referer", Value: "https://b.test/"}, {Key: "sec-fetch-mode", Value: "cors"}}}, "", ""},
		{"unparseable URL", Request{URL: "://a.test/x", Headers: fetch("https://b.test/")}, "", ""},
	}
	for _, c := range cases {
		req := c.req
		if site, origin := tr.PageFetchHeaders(&req); site != c.site || origin != c.origin {
			t.Errorf("%s: PageFetchHeaders = (%q, %q), want (%q, %q)", c.name, site, origin, c.site, c.origin)
		}
	}
}

// A preset describing a client that sends no Sec-Fetch-* gets no Origin from
// a Referer either: the pair would be headers that client never sends.
func TestPageFetchHeadersSkipsANonBrowserPreset(t *testing.T) {
	tr := NewTransport("chrome-latest")
	t.Cleanup(tr.Close)
	tr.fieldsMu.Lock()
	tr.preset = &fingerprint.Preset{
		UserAgent: "okhttp/5.1.0",
		H2Config: &fingerprint.H2FingerprintConfig{
			HPACKHeaderOrder: []string{"user-agent", "content-type", "accept-encoding"},
		},
	}
	tr.fieldsMu.Unlock()
	req := &Request{Method: "POST", URL: "https://a.test/x", Headers: map[string][]string{
		"Referer": {"https://b.test/"}, "Content-Type": {"application/json"},
	}}
	if site, origin := tr.PageFetchHeaders(req); site != "" || origin != "" {
		t.Errorf("PageFetchHeaders = (%q, %q) on a preset with no Sec-Fetch-*, want nothing", site, origin)
	}
}
