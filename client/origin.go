package client

import (
	"strings"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// redirectOriginClient is what a request's Origin header depends on, carried
// from hop to hop of a redirect chain. It is session.redirectOrigin, copied
// like the helpers in client.go so that this package does not import session.
// Keep the two in step. The client also asks it for the request a chain
// starts with, where the session leaves Origin to the caller, and it adds
// Fetch's websocket rule, which the session's redirects never reach.
//
// Fetch never copies Origin onto a hop. HTTP-redirect fetch appends the new URL
// to the request's URL list and runs main fetch again, which appends Origin for
// the new request from scratch. So a request's Origin follows from the
// request's origin and mode, its method and the URLs the chain has passed
// through. Chrome 156 and Firefox 159 did exactly this for fetch(), XHR,
// no-cors fetch(), iframes, navigations and form POSTs redirected with 302,
// 303, 307 and 308 within one origin, to another origin and back, and from
// https to http:
//   - A cors request carries Origin once any URL in the chain is off the
//     request's origin (Fetch's response tainting "cors"), whatever its method,
//     and before that only when the method is not GET or HEAD. So a fetch() GET
//     to its own origin sends none and gains Origin when redirected away, and
//     the GET after a fetch() POST's 303 carries it only off that origin.
//   - Any other request carries Origin only when its method is not GET or
//     HEAD: a form or no-cors POST sends the page's origin, and a
//     navigation's or iframe's GET hops send none, as does the GET after a
//     form POST's 303.
//   - The value is "null" once a hop has left a URL off the request's origin
//     for another origin: Fetch's redirect-taint, and WebKit's opaque origin in
//     SubresourceLoader.
//   - Outside cors mode it is also "null" on a hop from an https origin to a
//     URL that is not https, by Fetch's default referrer policy.
//   - A websocket handshake always carries Origin.
//
// Chromium differs outside cors mode. Its network stack sets an Origin the
// request carries to "null" on every redirect to another origin, so a form or
// no-cors POST answered with 307 or 308 sends "null" from its first hop off
// the page's origin, where Firefox and Fetch keep the page's origin. Only
// Chromium presets do that; see chromiumPresetClient.
type redirectOriginClient struct {
	// mode is the Sec-Fetch-Mode the request went out with. A request that
	// went out with none, a TLS-only one for instance, does not say which
	// browser request it is, so mode is "" and every hop carries the caller's
	// Origin unchanged.
	mode string
	// origin is the request's origin, serialized, or as the caller set it.
	origin   string
	chromium bool

	tainted bool // a hop has left a URL off origin for another origin
	crossed bool // a hop has gone to another origin than the URL it left
	cors    bool // a URL in the chain is off origin: response tainting "cors"
}

// newRedirectOriginClient starts the Origin state for a request to firstURL in
// mode, from a page on origin, with the preset's browser deciding the
// non-cors rule.
func newRedirectOriginClient(mode, origin, firstURL string, preset *fingerprint.Preset) *redirectOriginClient {
	return &redirectOriginClient{
		mode:     mode,
		origin:   origin,
		chromium: chromiumPresetClient(preset),
		cors:     mode == "cors" && !sameOriginClient(origin, firstURL),
	}
}

// chainOriginClient starts the Origin state of the redirect chain begun by a
// request that went out as httpReq to reqURL. The request's origin is the
// Origin it went out with, the caller's or the one requestOriginClient chose,
// else its Referer's origin, else its URL's.
func chainOriginClient(httpReq *http.Request, reqURL string, preset *fingerprint.Preset) *redirectOriginClient {
	origin := httpReq.Header.Get("Origin")
	if origin == "" {
		origin = serializeOriginClient(httpReq.Header.Get("Referer"))
	}
	if origin == "" {
		origin = serializeOriginClient(reqURL)
	}
	return newRedirectOriginClient(strings.ToLower(httpReq.Header.Get("Sec-Fetch-Mode")), origin, reqURL, preset)
}

// next moves the chain on by the hop from the URL that answered with a
// redirect to the URL it named, taken with method, and returns the Origin
// that hop carries; ok is false when it carries none. Meaningless when mode
// is "".
func (ro *redirectOriginClient) next(from, to, method string) (origin string, ok bool) {
	if !sameOriginClient(from, to) {
		ro.crossed = true
		if !sameOriginClient(ro.origin, from) {
			ro.tainted = true
		}
	}
	if ro.mode == "cors" && !sameOriginClient(ro.origin, to) {
		ro.cors = true
	}
	return ro.originFor(to, method)
}

// originFor returns the Origin a request to u taken with method carries in the
// chain's current state; ok is false when it carries none.
func (ro *redirectOriginClient) originFor(u, method string) (origin string, ok bool) {
	serialized := ro.origin
	if ro.tainted {
		serialized = "null"
	}
	method = strings.ToUpper(method)
	switch {
	case ro.cors || ro.mode == "websocket":
		return serialized, true
	case method == "" || method == "GET" || method == "HEAD":
		return "", false
	case ro.mode == "cors":
		return serialized, true
	case ro.chromium:
		// Chromium's network stack keeps the Origin a request carries and
		// sets it to "null" on a redirect to another origin.
		if ro.crossed {
			return "null", true
		}
		return ro.origin, true
	case isHTTPSClient(ro.origin) && !isHTTPSClient(u):
		return "null", true
	}
	return serialized, true
}

// requestOriginClient returns the Origin a browser sends on the request a
// chain starts with, given what httpReq goes out with once the caller's
// headers are in: its Sec-Fetch-Mode, Referer and method. ok is false when it
// sends none. mode is the mode the headers were built for, which stands in
// for a Sec-Fetch-Mode set empty.
//
// The page is the Referer's origin. Without a Referer the request names no
// page, so only a cors or websocket request guesses one, the target's own
// origin. A cors request then goes out same-origin (see
// detectSecFetchSiteForMode) and carries Origin only with a method other than
// GET or HEAD, as Chrome 156 and Firefox 159 sent it from a page that sends no
// Referer; one whose Sec-Fetch-Site the caller set elsewhere keeps the
// target's origin, as before.
func requestOriginClient(httpReq *http.Request, preset *fingerprint.Preset, mode FetchMode, reqURL string) (origin string, ok bool) {
	wireMode := strings.ToLower(httpReq.Header.Get("Sec-Fetch-Mode"))
	if wireMode == "" {
		switch mode {
		case FetchModeCORS:
			wireMode = "cors"
		case FetchModeNoCors:
			wireMode = "no-cors"
		default:
			wireMode = "navigate"
		}
	}
	page := serializeOriginClient(httpReq.Header.Get("Referer"))
	if page == "" {
		switch wireMode {
		case "cors":
			m := strings.ToUpper(httpReq.Method)
			if strings.EqualFold(httpReq.Header.Get("Sec-Fetch-Site"), "same-origin") && (m == "" || m == "GET" || m == "HEAD") {
				return "", false
			}
			return serializeOriginClient(reqURL), true
		case "websocket":
			return serializeOriginClient(reqURL), true
		}
		return "", false
	}
	return newRedirectOriginClient(wireMode, page, reqURL, preset).originFor(reqURL, httpReq.Method)
}

// chromiumPresetClient reports whether the preset is desktop or Android
// Chrome. The TLS identity is the signal, as it is for session's
// chromiumPreset: Firefox, Safari and Chrome on iOS, which runs on WebKit,
// all present another.
func chromiumPresetClient(p *fingerprint.Preset) bool {
	return p != nil && p.ClientHelloID.Client == "Chrome"
}

// serializeOriginClient returns the origin of u the way an Origin header
// carries it, scheme and host lowercased with the port only when it is not the
// scheme's default, or "" when u is not an http or https URL. A copy of
// session.serializeOrigin.
func serializeOriginClient(u string) string {
	scheme, host, port := parseOriginClient(u)
	if (scheme != "http" && scheme != "https") || host == "" {
		return ""
	}
	if strings.Contains(host, ":") { // IPv6 literal needs brackets
		host = "[" + host + "]"
	}
	origin := scheme + "://" + host
	if !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		origin += ":" + port
	}
	return origin
}

// isHTTPSClient reports whether u, a URL or a serialized origin, is https.
func isHTTPSClient(u string) bool {
	scheme, _, _ := parseOriginClient(u)
	return scheme == "https"
}
