package transport

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/qpack"
	"github.com/sardanioss/quic-go"
)

// layoutShape is a request of a kind Safari 26.3 sends, built the way a caller
// reproduces it: the Sec-Fetch-* of its kind and the headers the page set.
// want is its header names in Safari's wire order, without Host and
// Connection; dest is its final Sec-Fetch-Dest.
type layoutShape struct {
	name    string
	method  string
	dest    string
	headers map[string][]string
	body    []byte
	want    []string
}

const layoutPage, layoutOrigin = "https://example.test/", "https://example.test"

// layoutHeaders is the Sec-Fetch-* of a request of the given mode and dest,
// plus more.
func layoutHeaders(mode, dest string, more map[string][]string) map[string][]string {
	h := map[string][]string{"Sec-Fetch-Mode": {mode}, "Sec-Fetch-Dest": {dest}, "Sec-Fetch-Site": {"same-origin"}}
	for k, v := range more {
		h[k] = v
	}
	return h
}

// layoutWant is a block of a request's own names followed by the headers
// CFNetwork adds, the cookie only when it has one.
func layoutWant(block []string, cookie bool) []string {
	out := append(slices.Clone(block), "accept-language", "priority", "accept-encoding")
	if cookie {
		out = append(out, "cookie")
	}
	return out
}

func layoutShapes() []layoutShape {
	cookie := []string{"a=1; b=2"}
	return []layoutShape{
		{"fetch() POST with cache: 'no-store'", "POST", "empty",
			layoutHeaders("cors", "empty", map[string][]string{"Content-Type": {"text/plain"}, "Origin": {layoutOrigin},
				"Referer": {layoutPage}, "Pragma": {"no-cache"}, "Cache-Control": {"no-cache"}, "Cookie": cookie}),
			[]byte("report"),
			layoutWant([]string{"accept", "content-type", "origin", "pragma", "sec-fetch-site", "content-length",
				"sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest", "cache-control"}, true)},
		{"fetch() GET with cache: 'no-store'", "GET", "empty",
			layoutHeaders("cors", "empty", map[string][]string{"Referer": {layoutPage}, "Pragma": {"no-cache"},
				"Cache-Control": {"no-cache"}, "Cookie": cookie}),
			nil,
			layoutWant([]string{"accept", "sec-fetch-site", "pragma", "sec-fetch-mode", "user-agent", "referer",
				"sec-fetch-dest", "cache-control"}, true)},
		{"sendBeacon", "POST", "empty",
			layoutHeaders("no-cors", "empty", map[string][]string{"Content-Type": {"text/plain;charset=UTF-8"},
				"Origin": {layoutOrigin}, "Referer": {layoutPage}, "Cache-Control": {"max-age=0"},
				"Priority": {"u=7, i"}, "Cookie": cookie}),
			[]byte("beacon"),
			layoutWant([]string{"accept", "content-type", "origin", "sec-fetch-site", "content-length",
				"sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest", "cache-control"}, true)},
		{"plain fetch() GET", "GET", "empty",
			layoutHeaders("cors", "empty", map[string][]string{"Referer": {layoutPage}, "Cookie": cookie}),
			nil,
			layoutWant([]string{"sec-fetch-dest", "user-agent", "accept", "referer", "sec-fetch-site",
				"sec-fetch-mode"}, true)},
		{"XMLHttpRequest with two headers of the page's", "GET", "empty",
			layoutHeaders("cors", "empty", map[string][]string{"Referer": {layoutPage}, "x-xhr-lower": {"4"},
				"X-Xhr-Title": {"5"}}),
			nil,
			layoutWant([]string{"accept", "sec-fetch-site", "x-xhr-title", "x-xhr-lower", "sec-fetch-mode",
				"user-agent", "referer", "sec-fetch-dest"}, false)},
		{"fetch() with four headers of the page's", "GET", "empty",
			layoutHeaders("cors", "empty", map[string][]string{"Referer": {layoutPage}, "x-lower-custom": {"1"},
				"X-Title-Custom": {"2"}, "X-MiXeD-CaSe": {"3"}, "X-Requested-With": {"XMLHttpRequest"}}),
			nil,
			layoutWant([]string{"accept", "sec-fetch-site", "x-mixed-case", "x-lower-custom", "x-title-custom",
				"sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest", "x-requested-with"}, false)},
		{"http:// iframe with Upgrade-Insecure-Requests and a Referer", "GET", "iframe",
			layoutHeaders("navigate", "iframe", map[string][]string{"Upgrade-Insecure-Requests": {"1"},
				"Referer": {layoutPage}}),
			nil,
			layoutWant([]string{"accept", "sec-fetch-site", "upgrade-insecure-requests", "sec-fetch-mode",
				"user-agent", "referer", "sec-fetch-dest"}, false)},
		{"bare GET", "GET", "document", nil, nil,
			layoutWant([]string{"sec-fetch-dest", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode"}, false)},
		// Not captured: a sixth name that is not a navigation's puts the
		// request in the same table as a navigation, but not in its order.
		{"CORS GET with an Origin and no Referer, uncaptured", "GET", "empty",
			layoutHeaders("cors", "empty", map[string][]string{"Sec-Fetch-Site": {"cross-site"},
				"Origin": {layoutOrigin}}),
			nil,
			layoutWant([]string{"sec-fetch-dest", "user-agent", "accept", "sec-fetch-site", "origin",
				"sec-fetch-mode"}, false)},
	}
}

// layoutCapture sends requests through a real Transport to a local server over
// HTTP/2, plain HTTP/1.1 or HTTP/3 and reads back the header names in wire
// order.
type layoutCapture struct {
	h2 *h2CaptureServer
	h1 *h1OrderCapture
	h3 *h3OrderCapture
}

func newLayoutCapture(t *testing.T) *layoutCapture {
	return &layoutCapture{h2: startH2CaptureServer(t), h1: newH1OrderCapture(t)}
}

// send returns the names sh put on the wire; see do.
func (c *layoutCapture) send(t *testing.T, preset, proto string, sh layoutShape) (names []string, values map[string]string) {
	t.Helper()
	return c.do(t, preset, proto, sh.name, &Request{Method: sh.method, Headers: sh.headers, Body: sh.body})
}

// do sends req and returns the names it put on the wire, without
// pseudo-headers, Host and Connection, and a run of one name, cookie crumbs,
// once. values are the HTTP/2 field values, nil over the other protocols.
func (c *layoutCapture) do(t *testing.T, preset, proto, what string, req *Request) (names []string, values map[string]string) {
	t.Helper()
	tr := NewTransport(preset)
	defer tr.Close()
	var wire []string
	switch proto {
	case "h2", "h3":
		tr.SetInsecureSkipVerify(true)
		addr := c.h2.addr
		if proto == "h3" {
			if c.h3 == nil {
				c.h3 = startH3OrderCapture(t)
			}
			tr.SetProtocol(ProtocolHTTP3)
			addr = c.h3.addr
		} else {
			tr.SetProtocol(ProtocolHTTP2)
		}
		req.URL = "https://" + addr + "/layout"
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp, err := tr.Do(ctx, req)
		cancel()
		if err != nil {
			t.Fatalf("%s %s %s: %v", preset, proto, what, err)
		}
		resp.Close()
		timeout := time.After(5 * time.Second)
		if proto == "h3" {
			select {
			case wire = <-c.h3.captures:
			case <-timeout:
				t.Fatalf("%s %s %s: no HEADERS frame captured", preset, proto, what)
			}
		} else {
			select {
			case got := <-c.h2.captures:
				wire, values = got.HeaderOrder, got.Headers
			case <-timeout:
				t.Fatalf("%s %s %s: no HEADERS frame captured", preset, proto, what)
			}
		}
	case "h1":
		req.URL = c.h1.url
		wire = c.h1.do(t, tr, req)
	}
	for _, n := range wire {
		if strings.HasPrefix(n, ":") || len(names) > 0 && names[len(names)-1] == n {
			continue
		}
		names = append(names, n)
	}
	return names, values
}

// Safari 26.3 sends the headers a request carries itself in the order of the
// CoreFoundation dictionary that holds them, then Accept-Language, Priority,
// Accept-Encoding and Cookie. Each shape but the last of layoutShapes is one
// it was captured sending, on macOS 26.3 and in the iOS 26.3.1 simulator,
// over HTTP/1.1 and HTTP/2; see fingerprint's
// TestCFNetworkOrderReproducesSafari26 for the log lines. A request carrying
// only a navigation's own headers, with a Referer or without, comes out in the
// navigation order the presets always sent (the plain fetch() GET and the bare
// GET). Any other header moves it into an order they never sent before
// header_order_model, even as the sixth (the CORS GET with an Origin).
//
// The HTTP/1.1 capture is plain HTTP, where the transport gives a WebKit
// navigation Upgrade-Insecure-Requests. The bare GET carries it there, right
// after User-Agent, where Safari 26.3 sent it on its own http:// navigation
// (run-20261031-234946 h1.log:2-14).
func TestWebKitHeaderLayoutOnTheWire(t *testing.T) {
	c := newLayoutCapture(t)
	for _, preset := range []string{"safari-26", "safari-26-ios"} {
		for _, proto := range []string{"h2", "h1"} {
			for _, sh := range layoutShapes() {
				got, values := c.send(t, preset, proto, sh)
				want := sh.want
				if proto == "h1" && sh.name == "bare GET" {
					want = layoutWant([]string{"sec-fetch-dest", "user-agent", "upgrade-insecure-requests", "accept",
						"sec-fetch-site", "sec-fetch-mode"}, false)
				}
				if !slices.Equal(got, want) {
					t.Errorf("%s %s, %s:\n got %s\nwant %s", preset, proto, sh.name,
						strings.Join(got, ", "), strings.Join(want, ", "))
				}
				// A beacon's own values are the caller's to set; the layout
				// only gives them their places.
				if v, ok := sh.headers["Priority"]; ok && values != nil && values["priority"] != v[0] {
					t.Errorf("%s %s, %s: priority %q, want the caller's %q", preset, proto, sh.name, values["priority"], v[0])
				}
			}
		}

		// Each protocol's writer decides for itself whether an empty
		// User-Agent and the header that frames the body go out, and the
		// layout is of the names that do. None of these was captured; every
		// insertion order that fits the captures predicts the same orders.
		//
		// TLS-only adds none of the preset's headers and sets User-Agent to
		// "", which HTTP/2 and HTTP/3 drop and HTTP/1.1 writes as
		// "User-Agent: ". A caller's empty User-Agent goes the same way.
		// HTTP3Transport.RoundTrip sends the headers it is given, so HTTP/3
		// gets no User-Agent back and is laid out as HTTP/2 is.
		tlsOnly := true
		bare := func() *Request {
			return &Request{Method: "GET", TLSOnly: &tlsOnly, Headers: layoutHeaders("cors", "empty",
				map[string][]string{"Accept": {"*/*"}, "Referer": {layoutPage}, "X-Foo": {"1"}})}
		}
		emptyUA := func() *Request {
			return &Request{Method: "GET", Headers: layoutHeaders("cors", "empty",
				map[string][]string{"User-Agent": {""}, "Referer": {layoutPage}})}
		}
		bareWant := []string{"sec-fetch-dest", "x-foo", "accept", "referer", "sec-fetch-site", "sec-fetch-mode"}
		emptyUAWant := layoutWant([]string{"sec-fetch-dest", "accept", "referer", "sec-fetch-site", "sec-fetch-mode"}, false)
		// A POST with no body sends content-length: 0 on HTTP/2 and HTTP/1.1.
		// The HTTP/3 writer sends none, and with a body it puts content-length
		// after every other field.
		post := func(body []byte) func() *Request {
			return func() *Request {
				return &Request{Method: "POST", Body: body, Headers: layoutHeaders("cors", "empty",
					map[string][]string{"Content-Type": {"application/json"}})}
			}
		}
		emptyPost := layoutWant([]string{"accept", "content-type", "sec-fetch-site", "sec-fetch-mode", "user-agent",
			"content-length", "sec-fetch-dest"}, false)
		// A body the transport cannot size goes out chunked on HTTP/1.1, its
		// Transfer-Encoding where a Content-Length would be, and in bare DATA
		// frames on HTTP/2.
		upload := func() *Request {
			return &Request{Method: "POST", BodyReader: unsizedReader{bytes.NewReader([]byte("streamed"))},
				Headers: layoutHeaders("cors", "empty", map[string][]string{"Content-Type": {"text/plain"},
					"Origin": {layoutOrigin}, "Referer": {layoutPage}, "Cookie": {"a=1"}})}
		}
		// The HTTP/1.1 writer also sends Content-Length: 0 for an empty sized
		// body on a GET, and the caller's own Content-Length for a body it
		// cannot size. A page cannot make Safari send either; the layout puts
		// it where CFNetwork puts a Content-Length.
		emptyGet := func() *Request {
			return &Request{Method: "GET", BodyReader: bytes.NewReader(nil), Headers: layoutHeaders("cors", "empty",
				map[string][]string{"Referer": {layoutPage}})}
		}
		sizedUpload := func() *Request {
			return &Request{Method: "POST", BodyReader: unsizedReader{bytes.NewReader([]byte("streamed"))},
				Headers: layoutHeaders("cors", "empty", map[string][]string{"Content-Type": {"text/plain"},
					"Content-Length": {"8"}})}
		}
		for _, pc := range []struct {
			name, proto string
			req         func() *Request
			want        []string
		}{
			{"TLS-only, the caller's headers and no User-Agent", "h2", bare, bareWant},
			{"TLS-only, the caller's headers and no User-Agent", "h3", bare, bareWant},
			{"a caller's empty User-Agent", "h2", emptyUA, emptyUAWant},
			{"a caller's empty User-Agent", "h3", emptyUA, emptyUAWant},
			{"a caller's empty User-Agent", "h1", emptyUA, layoutWant([]string{"sec-fetch-dest", "user-agent",
				"accept", "referer", "sec-fetch-site", "sec-fetch-mode"}, false)},
			{"TLS-only, the caller's headers and no User-Agent", "h1", bare,
				[]string{"accept", "sec-fetch-site", "sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest",
					"x-foo"}},
			{"POST with no body", "h2", post(nil), emptyPost},
			{"POST with no body", "h1", post(nil), emptyPost},
			{"POST with no body", "h3", post(nil), layoutWant([]string{"sec-fetch-dest", "user-agent", "accept",
				"content-type", "sec-fetch-site", "sec-fetch-mode"}, false)},
			{"POST with a body", "h3", post([]byte(`{"k":1}`)), append(layoutWant([]string{"accept",
				"content-type", "sec-fetch-site", "sec-fetch-mode", "user-agent", "sec-fetch-dest"}, false),
				"content-length")},
			{"upload of unknown length", "h1", upload, layoutWant([]string{"accept", "content-type", "origin",
				"sec-fetch-site", "sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest", "transfer-encoding"},
				true)},
			{"upload of unknown length", "h2", upload, layoutWant([]string{"accept", "content-type", "origin",
				"sec-fetch-site", "sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest"}, true)},
			{"GET with an empty sized body", "h1", emptyGet, layoutWant([]string{"accept", "sec-fetch-site",
				"sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest", "content-length"}, false)},
			{"upload of unknown length the caller sizes", "h1", sizedUpload, layoutWant([]string{"accept",
				"content-type", "sec-fetch-site", "sec-fetch-mode", "user-agent", "content-length", "sec-fetch-dest"},
				false)},
		} {
			if got, _ := c.do(t, preset, pc.proto, pc.name, pc.req()); !slices.Equal(got, pc.want) {
				t.Errorf("%s %s, %s:\n got %s\nwant %s", preset, pc.proto, pc.name,
					strings.Join(got, ", "), strings.Join(pc.want, ", "))
			}
		}
	}
}

// unsizedReader hides the reader it wraps, so the transport cannot learn the
// body's length from its type.
type unsizedReader struct{ io.Reader }

// Every preset without header_order_model keeps sending its listed order for
// the same shapes, byte for byte what it sent before the key existed: the
// names the order lists in its order, then the rest sorted, and a
// Content-Length it does not list last.
func TestOtherPresetsKeepTheirListedOrder(t *testing.T) {
	c := newLayoutCapture(t)
	for _, preset := range []string{"chrome-148-windows", "firefox-148-windows", "safari-18", "chrome-147-ios"} {
		p := fingerprint.Get(preset)
		if p.H2HeaderOrderModel() != fingerprint.HeaderOrderModelList {
			t.Fatalf("%s: header order model %q", preset, p.H2HeaderOrderModel())
		}
		for _, proto := range []string{"h2", "h1"} {
			for _, sh := range layoutShapes() {
				got, _ := c.send(t, preset, proto, sh)
				if want := listedOrder(p.H2HeaderOrderFor(sh.dest), got); !slices.Equal(got, want) {
					t.Errorf("%s %s, %s:\n got %s\nwant %s", preset, proto, sh.name,
						strings.Join(got, ", "), strings.Join(want, ", "))
				}
			}
		}
	}
}

// listedOrder puts names in the order a listed preset gives them: the ones
// order names first, in its order, then the others sorted, with an unlisted
// content-length after everything, where both encoders write it. When order
// carries fingerprint.OtherHeaders, the sorted others go where it stands, as
// CompleteHeaderOrder puts them.
func listedOrder(order, names []string) []string {
	var out, rest []string
	marker := -1
	for _, n := range order {
		if n == fingerprint.OtherHeaders {
			if marker < 0 {
				marker = len(out)
			}
			continue
		}
		if slices.Contains(names, n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	unlistedLength := false
	for _, n := range names {
		switch {
		case slices.Contains(out, n):
		case n == "content-length":
			unlistedLength = true
		default:
			rest = append(rest, n)
		}
	}
	slices.Sort(rest)
	if marker >= 0 {
		out = slices.Insert(out, marker, rest...)
	} else {
		out = append(out, rest...)
	}
	if unlistedLength {
		out = append(out, "content-length")
	}
	return out
}

// h3OrderCapture is an HTTP/3 server that records the field names of each
// request it reads, in wire order. It is the snapshot's bare QUIC server
// (listenBareH3, serveBareH3) with a request handler that decodes the fields
// with sardanioss/qpack.
type h3OrderCapture struct {
	addr     string
	captures chan []string
}

func startH3OrderCapture(t *testing.T) *h3OrderCapture {
	t.Helper()
	ln := listenBareH3(t, wireCert(t))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		ln.Close()
	})
	s := &h3OrderCapture{addr: ln.Addr().String(), captures: make(chan []string, 16)}
	serveBareH3(ctx, ln, nil, func(uni *quic.ReceiveStream) { io.Copy(io.Discard, uni) }, s.serve)
	return s
}

// serve reads a request stream to its end, records the names its HEADERS
// frame carries and answers 200.
func (s *h3OrderCapture) serve(st *quic.Stream) {
	defer st.Close()
	r := &quicReader{r: st}
	var names []string
	for {
		ft := r.varint()
		p := r.take(int(r.varint()))
		if r.err != nil {
			break
		}
		if ft != 0x01 { // only HEADERS carries fields
			continue
		}
		next := qpack.NewDecoder().Decode(p)
		for {
			f, err := next()
			if err != nil {
				break
			}
			if !strings.HasPrefix(f.Name, ":") {
				names = append(names, f.Name)
			}
		}
	}
	s.captures <- names
	st.Write([]byte{0x01, 0x03, 0x00, 0x00, 0xd9}) // HEADERS :status 200
}
