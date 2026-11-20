package fingerprint

import (
	"slices"
	"strings"

	"github.com/sardanioss/httpcloak/internal/cflayout"
)

// webKitInsertion is the order the headers WebKit sets itself go into a
// request's header dictionary, fitted to the Safari 26.3 captures. Only names
// that compete for a bucket depend on it. Of the 39,916,800 orders of these
// 11 names, 14,784 reproduce the 12 captured orders the model fits, and all of
// them give the same order for the 13 uncaptured sets checked, such as a JSON
// POST without a cache option, but not for every set. For a fetch() GET with
// cache: 'no-store', or a hard-reload navigation, without a Referer, this
// order puts pragma first, which 2,688 of them do and 12,096 do not.
var webKitInsertion = []string{
	"referer", "pragma", "accept", "content-type", "origin",
	"upgrade-insecure-requests", "sec-fetch-mode", "sec-fetch-dest",
	"sec-fetch-site", "cache-control", "user-agent",
}

// cfnetworkTail is what CFNetwork writes after the dictionary. Every captured
// Safari 26.3 request ends with accept-language, priority and accept-encoding,
// then cookie when it has one, then connection on HTTP/1.1.
var cfnetworkTail = []string{"accept-language", "priority", "accept-encoding", "cookie", "connection"}

// CFNetworkHeaderOrder returns the header order Safari 26 gives a request that
// carries the named headers. bodyHeader is the one that frames its body,
// "content-length" or "transfer-encoding", or "" when it sends neither. On a
// preset whose H2HeaderOrderModel is HeaderOrderModelCFNetwork, a Session or
// Transport takes it in place of the preset's list for every request, while
// client.Client keeps the list; see H2FingerprintConfig.HeaderOrderModel.
//
// Safari sends the headers a request carries itself in the iteration order of
// the CoreFoundation dictionary that holds them, keyed by the lowercased name
// (cflayout.Layout), and then the ones CFNetwork adds, cfnetworkTail. The
// dictionary gets the browser's own headers first, in webKitInsertion's order,
// then the page's, here sorted, then the body's. A header the caller sets
// counts as one the page set. Host, and the pseudo-headers and internal
// ordering keys, which contain a colon, are not in the dictionary, a name from
// the tail stays in the tail even when the caller sets it, and Content-Length
// and Transfer-Encoding count only as bodyHeader says. CFNetwork adds one or
// the other for the body, so a chunked upload's Transfer-Encoding goes into the
// dictionary when a Content-Length would, last, and lands where the hash puts
// its own name, which is not always where a Content-Length lands. That is a
// prediction: no capture holds a chunked upload from Safari.
//
// So a request that carries only a navigation's own headers comes out in the
// navigation order, sec-fetch-dest, user-agent, accept, sec-fetch-site,
// sec-fetch-mode, with a referer right after accept or, on http://,
// upgrade-insecure-requests right before it. Of the captured requests whose
// order was logged, every navigation, frame, stylesheet, classic script, image
// and favicon over HTTPS did, and so did every plain fetch() GET. Any other
// header but pragma, even as the sixth, goes inside that block where the hash
// puts it: a CORS GET with an Origin and no Referer sends sec-fetch-dest,
// user-agent, accept, sec-fetch-site, origin, sec-fetch-mode. A sixth pragma
// comes first instead and puts accept before user-agent. With seven names or
// more the table has 13 buckets, or 23 from twelve on, and the order is
// another: a fetch() POST with cache: 'no-store' sends accept, content-type,
// origin, pragma, sec-fetch-site, content-length, sec-fetch-mode, user-agent,
// referer, sec-fetch-dest, cache-control. Two captures of Safari 26.3, on
// macOS 26.3 and in the iOS 26.3.1 simulator, hold 608 page requests, WebSocket
// handshakes aside, whose header order was logged, in 13 sets of headers, sent
// in 14 orders, and this reproduces 12 of the orders and 604 of the requests.
// It misses a module script on iOS, which put accept before sec-fetch-site
// where macOS put it after with the same names, and one navigation to a LAN
// host.
//
// The order depends on every name the request carries, so it has to be
// computed after the last header is added or removed.
func (p *Preset) CFNetworkHeaderOrder(names []string, bodyHeader string) []string {
	own := make(map[string]bool, len(names))
	for _, n := range names {
		n = strings.ToLower(n)
		if n == "" || n == "host" || n == "content-length" || n == "transfer-encoding" ||
			strings.IndexByte(n, ':') >= 0 || slices.Contains(cfnetworkTail, n) {
			continue
		}
		own[n] = true
	}
	insertion := make([]string, 0, len(own)+1)
	for _, n := range webKitInsertion {
		if own[n] {
			insertion = append(insertion, n)
			delete(own, n)
		}
	}
	page := make([]string, 0, len(own))
	for n := range own {
		page = append(page, n)
	}
	slices.Sort(page)
	insertion = append(insertion, page...)
	if bodyHeader != "" {
		insertion = append(insertion, strings.ToLower(bodyHeader))
	}
	return append(cflayout.Layout(insertion), cfnetworkTail...)
}
