package fingerprint

import (
	"net/textproto"
	"slices"
	"testing"
)

// Safari 26.3 sent the headers of its own in 14 orders across two captures,
// and every one but two comes out of the model as captured. A 2026-10-31 line
// is in the WebSocket run of that day on macOS 26.3 (run-20261031-234946); a
// 2026-10-28 line is in the capture of that day the Safari 26 presets were
// built from, capture/ on macOS 26.3 and capture-ios/ in the iOS 26.3.1
// simulator. Neither is in the repository. A line is the first request sent
// in that order; the count is how many requests were.
//
// The two orders the model misses: the module script on iOS (3 requests,
// 2026-10-28 capture-ios/h1.log:91), accept, sec-fetch-site, origin, ...,
// where macOS sent sec-fetch-site, accept, origin, ... with the same names;
// and a bare navigation to a LAN host (1, 2026-10-31 h1.log:7450),
// user-agent, upgrade-insecure-requests, accept.
func TestCFNetworkOrderReproducesSafari26(t *testing.T) {
	tail := []string{"accept-language", "priority", "accept-encoding", "cookie", "connection"}
	for _, c := range []struct {
		what  string
		block []string
	}{
		{"fetch() POST with cache: 'no-store', 372 requests, 2026-10-31 h1.log:15, h1tls.log:115, h2first.log:129",
			[]string{"accept", "content-type", "origin", "pragma", "sec-fetch-site", "content-length",
				"sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest", "cache-control"}},
		{"navigation, subresource or plain fetch() GET with a Referer, 154, 2026-10-31 h1tls.log:99",
			[]string{"sec-fetch-dest", "user-agent", "accept", "referer", "sec-fetch-site", "sec-fetch-mode"}},
		{"fetch() GET with cache: 'no-store', 18, 2026-10-31 h1.log:4078, h2h3.log:90",
			[]string{"accept", "sec-fetch-site", "pragma", "sec-fetch-mode", "user-agent", "referer",
				"sec-fetch-dest", "cache-control"}},
		{"fetch() POST to a LAN host, which gets no Sec-Fetch-*, 13, 2026-10-31 h1.log:7460",
			[]string{"accept", "content-type", "origin", "pragma", "user-agent", "referer", "cache-control",
				"content-length"}},
		{"navigation without a Referer, 10, 2026-10-31 h1tls.log:4223",
			[]string{"sec-fetch-dest", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode"}},
		{"http:// iframe with Upgrade-Insecure-Requests and a Referer, 7, 2026-10-31 h1.log:3579",
			[]string{"accept", "sec-fetch-site", "upgrade-insecure-requests", "sec-fetch-mode", "user-agent",
				"referer", "sec-fetch-dest"}},
		{"sendBeacon, 7, 2026-10-31 h1.log:3660",
			[]string{"accept", "content-type", "origin", "sec-fetch-site", "content-length", "sec-fetch-mode",
				"user-agent", "referer", "sec-fetch-dest", "cache-control"}},
		{"fetch() with four headers of the page's, 7, 2026-10-28 capture/h1.log:140",
			[]string{"accept", "sec-fetch-site", "x-mixed-case", "x-lower-custom", "x-title-custom",
				"sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest", "x-requested-with"}},
		{"XMLHttpRequest with two headers of the page's, 7, 2026-10-28 capture/h1.log:156",
			[]string{"accept", "sec-fetch-site", "x-xhr-title", "x-xhr-lower", "sec-fetch-mode", "user-agent",
				"referer", "sec-fetch-dest"}},
		{"http:// navigation with Upgrade-Insecure-Requests, 4, 2026-10-31 h1.log:2",
			[]string{"sec-fetch-dest", "user-agent", "upgrade-insecure-requests", "accept", "sec-fetch-site",
				"sec-fetch-mode"}},
		{"module script on macOS, 4, 2026-10-28 capture/h1.log:91",
			[]string{"sec-fetch-site", "accept", "origin", "sec-fetch-mode", "user-agent", "referer",
				"sec-fetch-dest"}},
		{"favicon of a LAN page, 1, 2026-10-31 h1.log:7494",
			[]string{"referer", "accept", "user-agent"}},
	} {
		// What a request map holds: canonical names, in no particular order,
		// with Host and the headers CFNetwork adds itself among them.
		names := []string{"Host", "Accept-Language", "Priority", "Accept-Encoding", "Cookie"}
		body := ""
		for _, n := range c.block {
			if n == "content-length" {
				body = n
				continue
			}
			names = append(names, textproto.CanonicalMIMEHeaderKey(n))
		}
		slices.Sort(names)
		want := append(slices.Clone(c.block), tail...)
		for _, preset := range []string{"safari-26", "safari-26-ios"} {
			if got := Get(preset).CFNetworkHeaderOrder(names, body); !slices.Equal(got, want) {
				t.Errorf("%s, %s:\n got %v\nwant %v", preset, c.what, got, want)
			}
		}
	}
}

// A caller's names land at their hash slots like a page's, in any casing, and
// what CFNetwork adds stays in the tail even when the caller sets it.
func TestCFNetworkOrderPlacesCallerHeaders(t *testing.T) {
	p := Get("safari-26")
	nav := []string{"sec-fetch-dest", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode"}
	tail := []string{"accept-language", "priority", "accept-encoding", "cookie", "connection"}
	for _, c := range []struct {
		what  string
		names []string
		body  string
		want  []string
	}{
		{"bare navigation", nav, "", append(slices.Clone(nav), tail...)},
		{"pseudo-headers, internal keys and repeats are not headers",
			append(slices.Clone(nav), ":authority", "Header-Order:", "PHeader-Order:", "ACCEPT", "user-agent", "host"),
			"", append(slices.Clone(nav), tail...)},
		{"the tail stays the tail",
			append(slices.Clone(nav), "Cookie", "Accept-Language", "Priority", "Connection", "Accept-Encoding"),
			"", append(slices.Clone(nav), tail...)},
		{"Content-Length and Transfer-Encoding count only as the body's header",
			append(slices.Clone(nav), "Content-Length", "Transfer-Encoding"), "", append(slices.Clone(nav), tail...)},
		// The model's predictions for uncaptured shapes, the same for all
		// 14,784 insertion orders that fit the captures.
		{"Authorization goes in the block, like any header a page sets",
			append(slices.Clone(nav), "Referer", "Authorization"), "",
			append([]string{"accept", "sec-fetch-site", "sec-fetch-mode", "user-agent", "referer",
				"sec-fetch-dest", "authorization"}, tail...)},
		{"a JSON fetch() POST, uncaptured",
			append(slices.Clone(nav), "Content-Type"), "content-length",
			append([]string{"accept", "content-type", "sec-fetch-site", "sec-fetch-mode", "user-agent",
				"content-length", "sec-fetch-dest"}, tail...)},
		{"a chunked upload's Transfer-Encoding takes Content-Length's place, uncaptured",
			append(slices.Clone(nav), "Content-Type", "Origin", "Referer"), "Transfer-Encoding",
			append([]string{"accept", "content-type", "origin", "sec-fetch-site", "sec-fetch-mode", "user-agent",
				"referer", "sec-fetch-dest", "transfer-encoding"}, tail...)},
	} {
		if got := p.CFNetworkHeaderOrder(c.names, c.body); !slices.Equal(got, c.want) {
			t.Errorf("%s:\n got %v\nwant %v", c.what, got, c.want)
		}
	}
}
