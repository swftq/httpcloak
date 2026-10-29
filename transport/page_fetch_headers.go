package transport

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// PageFetchHeaders returns the Sec-Fetch-Site and Origin a browser sends on
// req, worked out from the page the request came from. Either is "" when the
// request should go out with what the header pipeline writes on its own.
//
// Chromium, Gecko and WebKit derive both headers from the request's initiator,
// the page that sent it, and the Referer names that page: its own URL on its
// own origin, and its origin elsewhere, under the default referrer policy. So
// the page is the Referer's origin, or, when there is no Referer to read, the
// Origin the caller set, unless that is "null". Chrome 156 and Firefox 159
// sent no request with a Referer beside Sec-Fetch-Site: none, and a CORS
// request's Origin was the Referer's origin wherever a redirect had not made
// it "null".
//
//   - Sec-Fetch-Site is the page's relation to the URL, the same way in every
//     mode: same-origin, same-site (one scheme and registrable domain, any
//     port), or cross-site.
//   - Origin follows Fetch's "append a request Origin header" under the
//     default policy, strict-origin-when-cross-origin. A cors request carries
//     the page's origin when the URL is on another origin, and otherwise only
//     with a method other than GET or HEAD. Any other request carries it only
//     with such a method, as "null" from an https page to a URL that is not
//     https. Origin is never worked out when the caller set one, so a page
//     named by the caller's Origin only ever gives Sec-Fetch-Site.
//
// The mode is the one the request goes out with: the caller's Sec-Fetch-Mode,
// else cors for a request sniffXHRMode reads as fetch-shaped, else the
// preset's own.
//
// Nothing is worked out for a header the caller set, in any spelling, or for a
// request that goes out with no Sec-Fetch-* at all: one under ExactHeaders, a
// TLS-only one, or one on a preset that sends none.
//
// A cors request that names no page takes its own URL's origin for the page,
// so it goes out same-origin, with Origin only on a method other than GET or
// HEAD. That is a fetch() from a page that sends no Referer: Chrome 156 and
// Firefox 159, on a page served with Referrer-Policy: no-referrer, sent the
// default policy's values without the Referer, and to their own origin that
// was the pair above. The cross-site with no Origin the pipeline writes there
// is a pair no browser sends, and Go's CrossOriginProtection refuses it on any
// method but GET, HEAD and OPTIONS. An Origin of "null" or a Sec-Fetch-Site
// other than same-origin from the caller keeps the pipeline's values (see
// takesItsOwnOrigin). So does any other mode with no page: none for a
// navigation, cross-site for no-cors.
//
// The session writes the results into the first request's headers, so a
// redirect hop carries them on as it carries the caller's own.
func (t *Transport) PageFetchHeaders(req *Request) (site, origin string) {
	if len(req.ExactHeaders) > 0 {
		return "", ""
	}
	tlsOnly := t.tlsOnly
	if req.TLSOnly != nil {
		tlsOnly = *req.TLSOnly
	}
	preset := t.getPreset()
	if tlsOnly || preset == nil {
		return "", ""
	}
	wire := t.wireHeaders(preset)
	if !wire.sendsSecFetch {
		return "", ""
	}
	target, ok := parsePageOrigin(req.URL)
	if !ok {
		return "", ""
	}
	mode := pageFetchMode(wire, req)
	page, ok := pageOf(req.Headers)
	if !ok {
		if !takesItsOwnOrigin(req.Headers, mode) {
			return "", ""
		}
		page = target
	}
	if _, set := setByCaller(req.Headers, "Sec-Fetch-Site"); !set {
		site = page.relationTo(target)
	}
	if _, set := setByCaller(req.Headers, "Origin"); !set {
		origin = requestOrigin(page, target, mode, req.Method)
	}
	return site, origin
}

// takesItsOwnOrigin reports whether a request that names no page, sent with
// headers h in mode, takes its own URL's origin for one. That is a cors
// request with no Origin from the caller and no Sec-Fetch-Site other than
// same-origin. An Origin of "null" names an opaque page, and any other site
// puts the page somewhere the request does not say.
func takesItsOwnOrigin(h map[string][]string, mode string) bool {
	if mode != "cors" {
		return false
	}
	if _, set := setByCaller(h, "Origin"); set {
		return false
	}
	site, set := setByCaller(h, "Sec-Fetch-Site")
	return !set || strings.EqualFold(strings.TrimSpace(site), "same-origin")
}

// pageOrigin is an origin as Fetch compares them: scheme, host and port, with
// the port filled in from the scheme when the URL leaves it out.
type pageOrigin struct {
	scheme, host, port string
}

// parsePageOrigin returns the origin of raw, an http or https URL or a
// serialized origin. ok is false for anything else, "null" included.
func parsePageOrigin(raw string) (o pageOrigin, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return pageOrigin{}, false
	}
	o = pageOrigin{scheme: u.Scheme, host: strings.ToLower(u.Hostname()), port: u.Port()}
	if o.port == "" {
		o.port = "80"
		if o.scheme == "https" {
			o.port = "443"
		}
	}
	return o, true
}

// String serializes o the way an Origin header carries it, with the port only
// when it is not the scheme's default.
func (o pageOrigin) String() string {
	host := o.host
	if strings.Contains(host, ":") { // IPv6 literal needs brackets
		host = "[" + host + "]"
	}
	if (o.scheme == "https" && o.port == "443") || (o.scheme == "http" && o.port == "80") {
		return o.scheme + "://" + host
	}
	return o.scheme + "://" + host + ":" + o.port
}

// relationTo returns the Sec-Fetch-Site a request from a page on o sends to a
// URL on target. A site is schemeful, as Chromium's SchemefulSite and WebKit's
// isSameSiteAs have it: one host over http and https is two sites, and two
// ports on one host are one.
func (o pageOrigin) relationTo(target pageOrigin) string {
	switch {
	case o == target:
		return "same-origin"
	case o.scheme == target.scheme && registrableDomainOf(o.host) == registrableDomainOf(target.host):
		return "same-site"
	}
	return "cross-site"
}

// registrableDomainOf returns host's registrable domain, the eTLD+1 by the
// public suffix list with private suffixes such as github.io included, as
// Chromium counts it for a site. A host with none, an IP address, localhost or
// a public suffix itself, is a site of its own. host must be lowercase.
func registrableDomainOf(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// pageOf returns the origin of the page a request with headers h came from:
// the Referer's, else that of the caller's Origin. ok is false when neither
// names one, as with no Referer and an Origin of "null".
func pageOf(h map[string][]string) (page pageOrigin, ok bool) {
	if ref, set := setByCaller(h, "Referer"); set {
		if page, ok = parsePageOrigin(ref); ok {
			return page, true
		}
	}
	if o, set := setByCaller(h, "Origin"); set {
		return parsePageOrigin(o)
	}
	return pageOrigin{}, false
}

// setByCaller returns the first value of the header h holds under name, in
// any spelling, and whether h holds it at all. A name with no values does not
// count, because mergeCallerHeaders skips it, while an empty value does: it
// goes on the wire.
func setByCaller(h map[string][]string, name string) (value string, set bool) {
	for k, v := range h {
		if len(v) > 0 && strings.EqualFold(k, name) {
			return v[0], true
		}
	}
	return "", false
}

// pageFetchMode returns the Sec-Fetch-Mode req goes out with on a preset that
// writes Sec-Fetch-*, lowercased: the caller's own, else cors for a request
// sniffXHRMode reads as fetch-shaped, which is what applyPresetHeaders writes
// then, else the preset's.
func pageFetchMode(wire *presetWireHeaders, req *Request) string {
	if v := headerVal(req.Headers, "Sec-Fetch-Mode"); v != "" {
		return strings.ToLower(v)
	}
	if statedCORS(req.Initiator, req.Headers) || sniffXHRMode(req.Method, req.Headers) {
		return "cors"
	}
	for _, p := range wire.pairs {
		if p.key == "Sec-Fetch-Mode" {
			return strings.ToLower(p.value)
		}
	}
	return ""
}

// requestOrigin returns the Origin a request from page to target carries in
// mode, sent with method, or "" for none. It is Fetch's "append a request
// Origin header" for a request whose origin is page, under the default
// referrer policy:
//   - A cors request to another origin has response tainting "cors", and a
//     websocket one always carries it, so both send the page's origin whatever
//     the method.
//   - Any other request sends it only with a method other than GET or HEAD, as
//     "null" when the policy would not reveal the page: from an https page to
//     a URL that is not https, outside cors mode.
func requestOrigin(page, target pageOrigin, mode, method string) string {
	switch method = strings.ToUpper(method); {
	case mode == "websocket", mode == "cors" && page != target:
		return page.String()
	case method == "" || method == "GET" || method == "HEAD":
		return ""
	case mode != "cors" && page.scheme == "https" && target.scheme != "https":
		return "null"
	}
	return page.String()
}
