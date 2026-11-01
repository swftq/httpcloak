package session

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// Safari 26 lays out the headers a request carries itself by the
// CoreFoundation dictionary that holds them, so a request laid out with the
// three Sec-Fetch-* and one laid out without them differ in more than those
// three. Over plain HTTP to a host that is not loopback none of them goes out.
// These are the plain-HTTP requests of the capture run-20261031-234946, sent
// through a session to its own two hosts, localhost and 192.168.1.151, which
// ConnectTo sends to a loopback listener, and compared name for name with what
// Safari 26.3 sent, and one more that was not captured:
//   - its fetch() POST with cache: 'no-store' to the LAN address, as all 13
//     there went out (h1.log:7460-7475), and the same POST to localhost
//     (h1.log:15-33). Without the three, Content-Length goes after
//     Cache-Control; with them, between Sec-Fetch-Site and Sec-Fetch-Mode;
//   - its favicon on the LAN address (h1.log:7494-7504), which over TLS to the
//     same address went out in the navigation order with its three Sec-Fetch-*
//     (h1tls.log:3830-3843);
//   - its navigation to the LAN address (h1.log:7450-7459), which kept the
//     order its names take beside the three, so Upgrade-Insecure-Requests went
//     right after User-Agent;
//   - a navigation to localhost, typed (h1.log:2-14) and cross-site with a
//     cookie (7900-7913), Upgrade-Insecure-Requests right after User-Agent;
//   - a frame's navigation with a Referer (h1.log:3579-3593, as 3643-3657 and
//     3726-3740), Upgrade-Insecure-Requests right after Sec-Fetch-Site;
//   - the same frame's navigation to the LAN address, which was not captured:
//     laid out with the three Sec-Fetch-* and stripped of them, it has
//     Upgrade-Insecure-Requests right after Accept.
//
// The session adds Upgrade-Insecure-Requests to the navigations itself.
// Safari's values, its Accept-Language and its cookies among them, are not
// compared. Chrome on iOS runs on the same WebKit and was not captured; its
// presets from 148 on take the same model.
func TestSessionWebKit26PlainHTTPLayout(t *testing.T) {
	srv := startEncodingCapture(t)
	connectTo := map[string]string{"localhost": "127.0.0.1", "192.168.1.151": "127.0.0.1"}
	lan := "http://192.168.1.151:" + srv.port
	local := "http://localhost:" + srv.port
	cookie := []string{"a=1; b=1; c=1"}
	// What a caller sets to send the page's fetch(): the request's own
	// Sec-Fetch-*, which the session takes off again on the LAN address, and
	// the headers the page's fetch() carried.
	fetchPost := func(page string) map[string][]string {
		return map[string][]string{
			"Sec-Fetch-Mode": {"cors"}, "Sec-Fetch-Dest": {"empty"}, "Sec-Fetch-Site": {"same-origin"},
			"Accept": {"*/*"}, "Content-Type": {"text/plain"}, "Origin": {page}, "Pragma": {"no-cache"},
			"Cache-Control": {"no-cache"}, "Referer": {page + "/"}, "Cookie": cookie,
		}
	}
	cases := []struct {
		name, method, base string
		headers            map[string][]string
		body               []byte
		want               string
	}{
		{"fetch() POST to the LAN address, h1.log:7460-7475", "POST", lan, fetchPost(lan), []byte("report"),
			"host accept content-type origin pragma user-agent referer cache-control content-length " +
				"accept-language priority accept-encoding cookie connection"},
		{"fetch() POST to localhost, h1.log:15-33", "POST", local, fetchPost(local), []byte("report"),
			"host accept content-type origin pragma sec-fetch-site content-length sec-fetch-mode user-agent " +
				"referer sec-fetch-dest cache-control accept-language priority accept-encoding cookie connection"},
		{"favicon on the LAN address, h1.log:7494-7504", "GET", lan, map[string][]string{
			"Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Dest": {"image"}, "Sec-Fetch-Site": {"same-origin"},
			"Accept": {"*/*"}, "Referer": {lan + "/"}, "Cookie": cookie}, nil,
			"host referer accept user-agent accept-language priority accept-encoding cookie connection"},
		{"navigation to the LAN address, h1.log:7450-7459", "GET", lan, nil, nil,
			"host user-agent upgrade-insecure-requests accept accept-language priority accept-encoding connection"},
		{"typed navigation to localhost, h1.log:2-14", "GET", local, nil, nil,
			"host sec-fetch-dest user-agent upgrade-insecure-requests accept sec-fetch-site sec-fetch-mode " +
				"accept-language priority accept-encoding connection"},
		{"frame's navigation with a Referer, h1.log:3579-3593", "GET", local, map[string][]string{
			"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}, "Sec-Fetch-Site": {"same-origin"},
			"Referer": {local + "/"}, "Cookie": cookie}, nil,
			"host accept sec-fetch-site upgrade-insecure-requests sec-fetch-mode user-agent referer sec-fetch-dest " +
				"accept-language priority accept-encoding cookie connection"},
		{"frame's navigation with a Referer to the LAN address, not captured", "GET", lan, map[string][]string{
			"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}, "Sec-Fetch-Site": {"same-origin"},
			"Referer": {lan + "/"}, "Cookie": cookie}, nil,
			"host accept upgrade-insecure-requests user-agent referer " +
				"accept-language priority accept-encoding cookie connection"},
	}
	for _, preset := range []string{"safari-26", "safari-26-ios", "chrome-148-ios", "chrome-155-ios"} {
		if m := fingerprint.Get(preset).H2HeaderOrderModel(); m != fingerprint.HeaderOrderModelCFNetwork {
			t.Fatalf("%s: header order model %q", preset, m)
		}
		s := NewSession("", &protocol.SessionConfig{Preset: preset, ConnectTo: connectTo})
		for i, c := range cases {
			path := "/layout/" + preset + "/" + strconv.Itoa(i)
			sendAndClose(t, s, &transport.Request{Method: c.method, URL: c.base + path, Headers: c.headers, Body: c.body})
			req := srv.request(path)
			if req == nil {
				t.Fatalf("%s, %s: no request arrived", preset, c.name)
			}
			if got := strings.Join(req.names(), " "); got != c.want {
				t.Errorf("%s, %s:\n got %s\nwant %s", preset, c.name, got, c.want)
			}
		}
		s.Close()
	}
}

// cfnetworkWireOrder is the HTTP/1.1 order a preset on the cfnetwork model
// gives a request that carries names, lowercased: Host first, where the writer
// puts it, then the layout of the rest, with Content-Length framing the body
// when it is among them.
func cfnetworkWireOrder(p *fingerprint.Preset, names []string) []string {
	body := ""
	if slices.Contains(names, "content-length") {
		body = "content-length"
	}
	var out []string
	if slices.Contains(names, "host") {
		out = append(out, "host")
	}
	for _, n := range p.CFNetworkHeaderOrder(names, body) {
		if slices.Contains(names, n) {
			out = append(out, n)
		}
	}
	return out
}
