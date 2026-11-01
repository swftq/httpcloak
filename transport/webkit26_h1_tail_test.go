package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// webKit26TailShape is one request shape and what Safari 26's tail makes of it.
type webKit26TailShape struct {
	name    string
	req     func() Request
	cookie  bool     // a Cookie goes out
	early   []string // fields that must come before Accept-Language
	conn    string   // the Connection line
	chunked bool     // the body has no length, so HTTP/1.1 sends it chunked
}

func webKit26TailShapes() []webKit26TailShape {
	const (
		ref    = "https://example.test/page"
		origin = "https://example.test"
		cookie = "sid=abc123; pref=dark"
	)
	h := func(kv ...string) map[string][]string {
		m := map[string][]string{"Cookie": {cookie}}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = []string{kv[i+1]}
		}
		return m
	}
	return []webKit26TailShape{
		{name: "navigation", conn: "Connection: keep-alive",
			req: func() Request { return Request{Method: "GET"} }},
		{name: "navigation with Cookie and Referer", cookie: true, conn: "Connection: keep-alive",
			req: func() Request { return Request{Method: "GET", Headers: h("Referer", ref)} }},
		{name: "fetch JSON POST", cookie: true, conn: "Connection: keep-alive",
			early: []string{"Content-Type", "Content-Length", "Origin"},
			req: func() Request {
				return Request{Method: "POST", Body: []byte(`{"a":1}`), Headers: h("Referer", ref,
					"Origin", origin, "Content-Type", "application/json")}
			}},
		{name: "form POST", cookie: true, conn: "Connection: keep-alive",
			early: []string{"Content-Type", "Content-Length", "Origin"},
			req: func() Request {
				return Request{Method: "POST", Body: []byte("b=2"), Headers: h("Referer", ref, "Origin", origin,
					"Content-Type", "application/x-www-form-urlencoded", "Sec-Fetch-Site", "same-origin")}
			}},
		{name: "caller headers", cookie: true, conn: "Connection: keep-alive",
			early: []string{"Cache-Control", "X-Requested-With"},
			req: func() Request {
				return Request{Method: "GET", Headers: h("X-Requested-With", "XMLHttpRequest", "Cache-Control", "no-cache")}
			}},
		{name: "Connection: close", cookie: true, conn: "Connection: close",
			req: func() Request { return Request{Method: "GET", Headers: h("Connection", "close")} }},
		{name: "chunked upload", cookie: true, conn: "Connection: keep-alive", chunked: true,
			early: []string{"Content-Type", "Transfer-Encoding"},
			req: func() Request {
				// A reader whose length the request cannot know.
				return Request{Method: "POST", BodyReader: io.MultiReader(strings.NewReader("chunk")),
					Headers: h("Content-Type", "application/octet-stream")}
			}},
	}
}

// checkWebKit26H1Tail reports where an HTTP/1.1 head, as header lines in wire
// order, differs from the tail Safari 26 sent for the shape.
func checkWebKit26H1Tail(t *testing.T, label string, lines []string, s webKit26TailShape) {
	t.Helper()
	names := make([]string, len(lines))
	for i, l := range lines {
		names[i] = lineName(l)
	}
	tail := []string{"Accept-Language", "Priority", "Accept-Encoding"}
	if s.cookie {
		tail = append(tail, "Cookie")
	}
	tail = append(tail, "Connection")
	n := len(names)
	if n == 0 || !strings.EqualFold(names[0], "Host") {
		t.Errorf("%s: Host is not first: %q", label, lines)
	}
	if n < len(tail) || !equalFoldAll(names[n-len(tail):], tail) {
		t.Errorf("%s: the head does not end %q: %q", label, tail, lines)
	} else if lines[n-1] != s.conn {
		t.Errorf("%s: the last line is %q, want %q", label, lines[n-1], s.conn)
	}
	count := func(name string) int {
		c := 0
		for _, got := range names {
			if strings.EqualFold(got, name) {
				c++
			}
		}
		return c
	}
	if c := count("Connection"); c != 1 {
		t.Errorf("%s: %d Connection lines, want 1: %q", label, c, lines)
	}
	cookies := 0
	if s.cookie {
		cookies = 1
	}
	if c := count("Cookie"); c != cookies {
		t.Errorf("%s: %d Cookie lines, want %d: %q", label, c, cookies, lines)
	}
	index := func(name string) int {
		return slices.IndexFunc(names, func(got string) bool { return strings.EqualFold(got, name) })
	}
	al := index("Accept-Language")
	for _, e := range s.early {
		if i := index(e); i < 0 || i > al {
			t.Errorf("%s: %s at %d, want it before Accept-Language at %d: %q", label, e, i, al, lines)
		}
	}
}

// Safari 26.3 ended every ordinary HTTP/1.1 request of a capture on macOS 26.3
// (run-20261031-234946) with Accept-Language, Priority, Accept-Encoding, the
// Cookie when it had one, and Connection, and sent nothing after Connection:
// 288 of 288, 211 plain and 77 over TLS. The 286 that had a Cookie carried one
// Cookie field, always right before Connection. Every other field came first:
// the body's headers on all 270 requests that had a body, all of them fetch()
// and sendBeacon() calls, and Cache-Control, the field the table does not name
// that turned up most, right before Accept-Language on 259. The WebKit 26
// presets wrote Connection right after Host, which is Chrome's place, and the
// body's headers and the caller's own after Cookie.
//
// Headers set by a page went first too. In the capture of 2026-10-28, a fetch()
// with four and an XMLHttpRequest with two sent every one of them ahead of
// Accept-Language, among Safari's own headers, and ended Accept-Language,
// Priority, Accept-Encoding, Connection, on macOS (h1.log:140 and :156,
// h1tls.log:199 and :215) and in the iOS 26.3.1 simulator (h1.log:152 and :168,
// h1tls.log:187 and :203).
//
// Each shape goes through a real transport, plain and over TLS. The caller
// headers shape asks that much of its two, not where among Safari's own headers
// each one goes. No form POST or chunked upload was captured, so those cases
// hold the captured tail and no more. The chunked upload is there because the
// writer puts a Transfer-Encoding that the order does not place after
// everything, Connection included.
func TestWebKit26HTTP1EndsWithCookieThenConnection(t *testing.T) {
	plainURL, plainHeads := serveH1HeadLines(t, nil)
	tlsURL, tlsHeads := serveH1HeadLines(t, &tls.Config{
		Certificates: []tls.Certificate{wireCert(t)}, NextProtos: []string{"http/1.1"}})
	send := func(t *testing.T, preset string, req Request, overTLS bool) {
		t.Helper()
		tr := NewTransport(preset)
		defer tr.Close()
		if overTLS {
			tr.SetProtocol(ProtocolHTTP1)
			tr.SetInsecureSkipVerify(true)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := tr.Do(ctx, &req)
		if err != nil {
			t.Fatalf("%s %s: %v", preset, req.URL, err)
		}
		resp.Close()
	}

	for _, preset := range webKit26Presets {
		for _, s := range webKit26TailShapes() {
			req := s.req()
			req.URL = plainURL
			send(t, preset, req, false)
			checkWebKit26H1Tail(t, preset+" plain "+s.name, <-plainHeads, s)

			req = s.req()
			req.URL = tlsURL
			send(t, preset, req, true)
			checkWebKit26H1Tail(t, preset+" TLS "+s.name, <-tlsHeads, s)
		}
	}

	// The navigation of run-20261031-234946 h1tls.log:100-112, with a Referer
	// and cookies, field for field. Over TLS, because Safari adds
	// Upgrade-Insecure-Requests to a plain-HTTP navigation.
	want := []string{"Host", "Sec-Fetch-Dest", "User-Agent", "Accept", "Referer", "Sec-Fetch-Site",
		"Sec-Fetch-Mode", "Accept-Language", "Priority", "Accept-Encoding", "Cookie", "Connection"}
	for _, preset := range webKit26Presets {
		send(t, preset, Request{Method: "GET", URL: tlsURL, Headers: map[string][]string{
			"Referer":        {"https://example.test/page"},
			"Sec-Fetch-Site": {"cross-site"},
			"Cookie":         {"sid=abc123; pref=dark"},
		}}, true)
		lines := <-tlsHeads
		names := make([]string, len(lines))
		for i, l := range lines {
			names[i] = lineName(l)
		}
		if !equalFoldAll(names, want) {
			t.Errorf("%s: navigation with a Referer and cookies:\n got  %q\n want %q", preset, names, want)
		}
	}
}

// HTTP/2 carries no Connection, and the same order puts the body's headers and
// the caller's before accept-language and the cookie last, as on all 153
// ordinary HTTP/2 requests of run-20261031-234946 (122 with a body). Cookie
// crumbs are counted, not assumed to be one field.
func TestWebKit26HTTP2EndsWithCookie(t *testing.T) {
	h2URL, blocks := serveH2HeaderNames(t)
	for _, preset := range webKit26Presets {
		for _, s := range webKit26TailShapes() {
			if s.chunked {
				continue // HTTP/2 frames the body itself
			}
			req := s.req()
			req.URL = h2URL
			tr := NewTransport(preset)
			tr.SetProtocol(ProtocolHTTP2)
			tr.SetInsecureSkipVerify(true)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := tr.Do(ctx, &req)
			cancel()
			if err != nil {
				t.Fatalf("%s %s: %v", preset, s.name, err)
			}
			resp.Close()
			tr.Close()

			names := <-blocks
			label := preset + " " + s.name
			end := len(names)
			for end > 0 && names[end-1] == "cookie" {
				end--
			}
			crumbs := len(names) - end
			if s.cookie != (crumbs > 0) {
				t.Errorf("%s: %d cookie fields at the end of %q", label, crumbs, names)
			}
			if slices.Contains(names[:end], "cookie") {
				t.Errorf("%s: a cookie field before the end of %q", label, names)
			}
			if end < 3 || !slices.Equal(names[end-3:end], []string{"accept-language", "priority", "accept-encoding"}) {
				t.Errorf("%s: the block does not end accept-language, priority, accept-encoding[, cookie]: %q", label, names)
			}
			al := slices.Index(names, "accept-language")
			for _, e := range s.early {
				if i := slices.Index(names, strings.ToLower(e)); i < 0 || i > al {
					t.Errorf("%s: %s at %d, want it before accept-language at %d: %q", label, e, i, al, names)
				}
			}
		}
	}
}

// Nothing else moves. The Chromium presets and the WebKit presets before 26
// keep Connection right after Host, where Chrome sends it, for every shape,
// and a caller's own Connection keeps that place too. Firefox 159's place is
// pinned by TestFirefoxHeaderOrder.
func TestHTTP1ConnectionStaysAfterHostOutsideWebKit26(t *testing.T) {
	url, heads := serveH1HeadLines(t, nil)
	for _, preset := range []string{"chrome-155-windows", "chrome-155-android",
		"safari-18", "safari-18-ios", "safari-17-ios", "chrome-143-ios", "chrome-146-ios", "chrome-147-ios"} {
		for _, s := range webKit26TailShapes() {
			req := s.req()
			req.URL = url
			tr := NewTransport(preset)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := tr.Do(ctx, &req)
			cancel()
			if err != nil {
				t.Fatalf("%s %s: %v", preset, s.name, err)
			}
			resp.Close()
			tr.Close()
			if lines := <-heads; len(lines) < 2 || lineName(lines[0]) != "Host" || lines[1] != s.conn {
				t.Errorf("%s %s: want Host, then %q: %q", preset, s.name, s.conn, lines)
			}
		}
	}
}

// serveH1HeadLines answers HTTP/1.1, over TLS when cfg is set, and sends each
// request's header lines, in the order they arrived, down the channel. It
// reads a body framed by Content-Length or sent chunked.
func serveH1HeadLines(t *testing.T, cfg *tls.Config) (string, <-chan []string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	scheme := "http"
	if cfg != nil {
		ln = tls.NewListener(ln, cfg)
		scheme = "https"
	}
	t.Cleanup(func() { ln.Close() })
	heads := make(chan []string, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					if _, err := br.ReadString('\n'); err != nil { // request line
						return
					}
					var lines []string
					length, chunked := 0, false
					for {
						l, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if l = strings.TrimRight(l, "\r\n"); l == "" {
							break
						}
						lines = append(lines, l)
						name, value, _ := strings.Cut(l, ":")
						switch value = strings.TrimSpace(value); {
						case strings.EqualFold(name, "Content-Length"):
							length, _ = strconv.Atoi(value)
						case strings.EqualFold(name, "Transfer-Encoding"):
							chunked = strings.EqualFold(value, "chunked")
						}
					}
					if chunked {
						for {
							size, err := br.ReadString('\n')
							if err != nil {
								return
							}
							n, err := strconv.ParseInt(strings.TrimSpace(size), 16, 64)
							if err != nil {
								return
							}
							if _, err := io.CopyN(io.Discard, br, n+2); err != nil { // the chunk and its CRLF
								return
							}
							if n == 0 {
								break
							}
						}
					} else if _, err := io.CopyN(io.Discard, br, int64(length)); err != nil {
						return
					}
					heads <- lines
					io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
				}
			}(c)
		}
	}()
	return scheme + "://" + ln.Addr().String() + "/", heads
}
