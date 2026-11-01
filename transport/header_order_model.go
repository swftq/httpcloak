package transport

import (
	"cmp"
	"slices"
	"strings"

	http "github.com/sardanioss/http"
)

// requestHeaderNames lists, lowercased, the names a request will carry over
// protocol: the ones the preset pipeline put in header, and every caller
// header with a value, which mergeCallerHeaders adds after it. Repeats, Host
// and the internal ordering keys may be among them;
// fingerprint.Preset.CFNetworkHeaderOrder drops them. An empty User-Agent,
// which TLS-only mode sets to keep the encoders' default out and a caller can
// set too, is left out on HTTP/2 and HTTP/3, whose encoders drop it; HTTP/1.1
// writes it as "User-Agent: ". HTTP3Transport.RoundTrip sends the headers it
// is given and writes no User-Agent of the preset's over it, so HTTP/3 is laid
// out as HTTP/2 is.
func requestHeaderNames(header http.Header, userHeaders map[string][]string, protocol string) []string {
	dropUA := protocol != "h1" && userAgentValue(header, userHeaders) == ""
	names := make([]string, 0, len(header)+len(userHeaders))
	add := func(name string) {
		if name = lowerHeaderName(name); !dropUA || name != "user-agent" {
			names = append(names, name)
		}
	}
	for name := range header {
		add(name)
	}
	for name, values := range userHeaders {
		if len(values) > 0 {
			add(name)
		}
	}
	return names
}

// cfnetworkHeaderNames is requestHeaderNames for a preset on the cfnetwork
// model, minus the headers stripUntrustworthyMetadata will take off a request
// that is not a navigation.
//
// Over plain HTTP to a host that is not loopback no Sec-Fetch-* or sec-ch-*
// header goes out, and Safari never adds one there, so its table holds fewer
// names and lays them out another way. Safari 26.3 sent all 13 of its fetch()
// POSTs to a LAN address over plain HTTP in the order the cfnetwork layout
// gives the names they carried (run-20261031-234946 h1.log:7460-7475):
// Content-Length after Cache-Control, where the same POST to localhost, laid
// out with the three Sec-Fetch-* among its names, has it between Sec-Fetch-Site
// and Sec-Fetch-Mode (h1.log:15-33). Its favicon there did the same
// (h1.log:7494). Its one navigation there did not: it went out User-Agent,
// Upgrade-Insecure-Requests, Accept (h1.log:7450-7459), the order those three
// take beside the three Sec-Fetch-* with the three taken out, where the layout
// of the three alone puts Upgrade-Insecure-Requests first. So a navigation
// keeps every name here, and loses the stripped ones after the layout. Only a
// top-level navigation to such a host was captured; a frame's is taken to go
// the same way.
func cfnetworkHeaderNames(httpReq *http.Request, wire *presetWireHeaders, userHeaders map[string][]string, protocol string, tlsOnly bool) []string {
	names := requestHeaderNames(httpReq.Header, userHeaders, protocol)
	if !stripsUntrustworthyMetadata(httpReq.URL, wire, tlsOnly, false) {
		return names
	}
	mode := cmp.Or(headerVal(userHeaders, "Sec-Fetch-Mode"), headerVal(httpReq.Header, "Sec-Fetch-Mode"))
	if strings.EqualFold(mode, "navigate") {
		return names
	}
	return slices.DeleteFunc(names, func(n string) bool {
		return isSecFetchHeader(n) || isClientHintHeader(n)
	})
}

// userAgentValue is the User-Agent a request goes out with: the caller's
// first value when it sets one, since mergeCallerHeaders writes the caller's
// values over the pipeline's, and the pipeline's otherwise.
func userAgentValue(header http.Header, userHeaders map[string][]string) string {
	for name, values := range userHeaders {
		if len(values) > 0 && strings.EqualFold(name, "User-Agent") {
			return values[0]
		}
	}
	if values := header["User-Agent"]; len(values) > 0 {
		return values[0]
	}
	return ""
}

// bodyHeader names the header that frames req's body over protocol,
// "content-length" or "transfer-encoding", or "" when none goes out. Each
// protocol's writer decides it for itself, and this follows each one's rule:
//
//   - HTTP/1.1, writeRequest and writeHeadersInOrder: a sized body gets its
//     Content-Length; http.NoBody, which an empty sized body becomes, gets
//     Content-Length: 0 on any method, a GET included; a body of unknown
//     length gets the caller's Content-Length when the caller sets one, and
//     otherwise goes out chunked, with Transfer-Encoding. Safari sends
//     neither a body on a GET nor a Content-Length a page set, so there the
//     model puts what this writer sends where CFNetwork puts that header.
//   - HTTP/2, sardanioss/net's actualContentLength (http2) and then
//     shouldSendReqContentLength (internal/httpcommon): a body of known
//     length gets a Content-Length, an empty body gets one on POST, PUT and
//     PATCH only, and a body of unknown length, which goes out in bare DATA
//     frames, gets none.
//   - HTTP/3, the two functions of those names in the http3/request_writer.go
//     of the sardanioss/quic-go that go.mod pins: as HTTP/2, except that its
//     actualContentLength counts http.NoBody as a body of unknown length, so
//     an empty POST, PUT or PATCH gets none. The writer puts content-length
//     after every other field, wherever the order places it.
func bodyHeader(req *http.Request, userHeaders map[string][]string, protocol string) string {
	if protocol == "h1" {
		sized := req.Header.Get("Content-Length") != "" || headerVal(userHeaders, "Content-Length") != ""
		switch {
		case req.Body != nil && req.Body != http.NoBody && req.ContentLength <= 0 && !sized:
			return "transfer-encoding"
		case sized || req.ContentLength > 0 || (req.ContentLength == 0 && req.Body != nil):
			return "content-length"
		}
		return ""
	}
	n := req.ContentLength
	switch {
	case req.Body == nil, req.Body == http.NoBody && protocol != "h3":
		n = 0
	case n == 0:
		n = -1
	}
	if n != 0 {
		if n > 0 {
			return "content-length"
		}
		return ""
	}
	switch req.Method {
	case "POST", "PUT", "PATCH":
		return "content-length"
	}
	return ""
}
