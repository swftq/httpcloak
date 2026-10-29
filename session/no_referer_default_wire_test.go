package session

import (
	"slices"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/transport"
)

// What a browser sends on a fetch() or XHR from a page that sends no Referer,
// captured from Chrome 156 and Firefox 159 on 2026-10-28: from a page served
// with Referrer-Policy: no-referrer, and with fetch()'s referrerPolicy option,
// both sent the default policy's Sec-Fetch-Site and Origin, only without the
// Referer. To their own origin that was same-origin, with no Origin on a GET
// or HEAD and their origin on a POST.
//
// A session request that named no page went out cross-site with no Origin, a
// pair no browser sends, and Go 1.25+'s CrossOriginProtection refuses it on
// every method but GET, HEAD and OPTIONS. Every binding's json= POST is such a
// request. Each test here reads what a server behind that check received.

func TestNoPageFetchIsSameOrigin(t *testing.T) {
	// The API calls a caller sends a session with no Referer: sniffed from
	// their Accept, body or method, or named by Sec-Fetch-Mode, which is what
	// the bindings' fetch-mode option sets. Each builds a fresh header map.
	shapes := []struct {
		name, method string
		headers      map[string][]string
		body         string
	}{
		{"JSON GET", "GET", map[string][]string{"Accept": {"application/json"}}, ""},
		{"JSON HEAD", "HEAD", map[string][]string{"Accept": {"application/json"}}, ""},
		{"JSON POST", "POST", map[string][]string{"Content-Type": {"application/json"}}, `{"a":1}`},
		{"JSON PUT", "PUT", map[string][]string{"Content-Type": {"application/json"}}, `{"a":1}`},
		{"text PATCH", "PATCH", map[string][]string{"Content-Type": {"text/plain;charset=UTF-8"}}, "a"},
		{"DELETE", "DELETE", nil, ""},
		{"POST with no Content-Type", "POST", nil, "a"},
		{"cors GET", "GET", map[string][]string{"Sec-Fetch-Mode": {"cors"}}, ""},
		{"cors POST", "POST", map[string][]string{"sec-fetch-mode": {"cors"}, "Content-Type": {"application/x-www-form-urlencoded"}}, "a=1"},
	}
	srv := newPageFetchServer(t, "a.test", true)
	for _, preset := range pageFetchPresets {
		for _, p := range pageFetchProtocols {
			s := newPageFetchSession(t, preset, p.proto)
			for _, shape := range shapes {
				what := strings.Join([]string{preset, p.name, shape.name}, ", ")
				path := "/csrf/" + strings.ReplaceAll(strings.Join([]string{preset, p.proto, shape.name}, "/"), " ", "-")
				headers := map[string][]string{}
				for k, v := range shape.headers {
					headers[k] = slices.Clone(v)
				}
				pageFetchSend(t, s, &transport.Request{Method: shape.method, URL: srv.url + path, Headers: headers, Body: []byte(shape.body)})

				h := srv.hit(t, path)
				if h.proto != p.proto {
					t.Fatalf("%s: went out over %s", what, h.proto)
				}
				if h.refused {
					t.Errorf("%s: refused by CrossOriginProtection (Sec-Fetch-Site %q, Origin %q)", what, h.site, h.origin)
				}
				wantValues(t, what, "Sec-Fetch-Mode", h.mode, "cors")
				wantValues(t, what, "Sec-Fetch-Site", h.site, "same-origin")
				var origin []string
				if shape.method != "GET" && shape.method != "HEAD" {
					origin = []string{srv.url}
				}
				wantValues(t, what, "Origin", h.origin, origin...)
				wantValues(t, what, "Referer", h.referers)
			}
		}
	}
}

// A Sec-Fetch-Site of the caller's other than same-origin says the page is not
// on the URL's origin, which leaves nothing to take the Origin from: the
// request goes out as the caller wrote it, and the check refuses it, as it
// would a browser's. A same-origin one agrees with the default and gets the
// Origin a browser's POST carries.
func TestNoPageFetchLeavesTheCallersSite(t *testing.T) {
	srv := newPageFetchServer(t, "a.test", true)
	for _, preset := range pageFetchPresets {
		for _, p := range pageFetchProtocols {
			s := newPageFetchSession(t, preset, p.proto)
			for _, c := range []struct {
				name, site string
				origin     []string
				refused    bool
			}{
				{"same-origin", "same-origin", []string{srv.url}, false},
				{"same-site", "same-site", nil, true},
				{"cross-site", "cross-site", nil, true},
			} {
				what := strings.Join([]string{preset, p.name, c.name}, ", ")
				path := "/csrf/own-site/" + preset + "/" + p.proto + "/" + c.name
				pageFetchSend(t, s, &transport.Request{Method: "POST", URL: srv.url + path, Body: []byte(`{}`), Headers: map[string][]string{
					"Content-Type": {"application/json"}, "sec-fetch-site": {c.site}}})
				h := srv.hit(t, path)
				wantValues(t, what, "Sec-Fetch-Site", h.site, c.site)
				wantValues(t, what, "Origin", h.origin, c.origin...)
				if h.refused != c.refused {
					t.Errorf("%s: refused = %v, want %v", what, h.refused, c.refused)
				}
			}
		}
	}
}

// A redirect hop carries the first request's values as it carries the
// caller's headers, so a hop within the URL's origin keeps them, which is
// what a browser sends there. A hop to another origin needs the redirect-hop
// branches, which rework a carried Sec-Fetch-Site and Origin per hop.
func TestNoPageFetchKeepsItsValuesOnASameOriginHop(t *testing.T) {
	srv := newPageFetchServer(t, "a.test", true)
	for _, preset := range pageFetchPresets {
		for _, p := range pageFetchProtocols {
			s := newPageFetchSession(t, preset, p.proto)
			for _, c := range []struct {
				name, method, status, body string
				headers                    map[string][]string
				origin                     []string
			}{
				{"JSON GET", "GET", "302", "", map[string][]string{"Accept": {"application/json"}}, nil},
				{"JSON POST", "POST", "307", "{}", map[string][]string{"Content-Type": {"application/json"}}, []string{srv.url}},
			} {
				path := "/hop/" + c.status + "/" + preset + "/" + p.proto + "/" + strings.ReplaceAll(c.name, " ", "-") + "/"
				pageFetchSend(t, s, &transport.Request{Method: c.method, URL: srv.url + path + "1", Headers: c.headers, Body: []byte(c.body)})
				for _, hop := range []string{"1", "2"} {
					what := preset + ", " + p.name + ", " + c.name + ", request " + hop
					h := srv.hit(t, path+hop)
					wantValues(t, what, "Sec-Fetch-Site", h.site, "same-origin")
					wantValues(t, what, "Origin", h.origin, c.origin...)
				}
			}
		}
	}
}
