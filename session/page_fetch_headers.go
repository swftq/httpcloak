package session

import "github.com/sardanioss/httpcloak/transport"

// pinPageFetchHeaders writes into req's headers the Sec-Fetch-Site and Origin
// that the page its Referer names implies, where the transport then reads them
// as the caller's own; see transport.PageFetchHeaders. A Referer used to
// change neither, so a navigation went out with Sec-Fetch-Site: none beside
// it and a request sniffed as fetch() with cross-site and no Origin, whatever
// the page.
//
// It runs once, on the request the caller made, before the first attempt. A
// redirect hop must not work them out again from its own Referer: a browser
// takes a hop's values from the page and the whole chain, which the hop's
// Referer does not say. Pinned, they ride onto the hop as the caller's
// headers do.
func (s *Session) pinPageFetchHeaders(req *transport.Request) {
	if s.transport == nil {
		return
	}
	site, origin := s.transport.PageFetchHeaders(req)
	if site != "" {
		req.Headers["Sec-Fetch-Site"] = []string{site}
	}
	if origin != "" {
		req.Headers["Origin"] = []string{origin}
	}
}
