package client

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Safari 26.3 ended every ordinary HTTP/1.1 request of a capture on macOS 26.3
// with Accept-Language, Priority, Accept-Encoding, the Cookie when it had one,
// and Connection, with nothing after it, and sent the body's headers and every
// other field before Accept-Language. transport's
// TestWebKit26HTTP1EndsWithCookieThenConnection has the counts. client.Client
// shares the HTTP/1.1 writer and orders every request by the preset's table,
// so its WebKit 26 presets must end each request that way too, with the Cookie
// from its jar. The headers that Auth and a pre-request hook add are the
// exception: they come after the request is ordered and still go after
// Connection, so no case sets either. It speaks HTTPS only, and reads every
// body into memory before sending it, so it has no chunked upload to test.
func TestClientWebKit26HTTP1EndsWithCookieThenConnection(t *testing.T) {
	ln := priorityTLSListener(t, "http/1.1")
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
					length := 0
					for {
						l, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if l = strings.TrimRight(l, "\r\n"); l == "" {
							break
						}
						lines = append(lines, l)
						if name, value, _ := strings.Cut(l, ":"); strings.EqualFold(name, "Content-Length") {
							length, _ = strconv.Atoi(strings.TrimSpace(value))
						}
					}
					if _, err := io.CopyN(io.Discard, br, int64(length)); err != nil {
						return
					}
					heads <- lines
					io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
				}
			}(c)
		}
	}()
	target := "https://" + ln.Addr().String() + "/"
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}

	keepAlive := "Connection: keep-alive"
	cases := []struct {
		name  string
		req   func() *Request
		early []string // fields that must come before Accept-Language
		conn  string   // the Connection line
	}{
		{"GET with cookies", func() *Request { return &Request{Method: "GET", URL: target} }, nil, keepAlive},
		{"POST with a body", func() *Request {
			return &Request{Method: "POST", URL: target, Body: strings.NewReader(`{"a":1}`),
				Headers: map[string][]string{"Content-Type": {"application/json"}}}
		}, []string{"Content-Type", "Content-Length", "Origin"}, keepAlive},
		{"Connection: close", func() *Request {
			return &Request{Method: "GET", URL: target, Headers: map[string][]string{"Connection": {"close"}}}
		}, nil, "Connection: close"},
		{"caller header", func() *Request {
			return &Request{Method: "GET", URL: target, Headers: map[string][]string{
				"X-Requested-With": {"XMLHttpRequest"}, "Cache-Control": {"no-cache"}}}
		}, []string{"Cache-Control", "X-Requested-With"}, keepAlive},
	}

	tail := []string{"Accept-Language", "Priority", "Accept-Encoding", "Cookie", "Connection"}
	for _, preset := range []string{"safari-26", "safari-26-ios", "chrome-148-ios", "chrome-155-ios"} {
		c := NewClient(preset, WithForceHTTP1(), WithInsecureSkipVerify())
		c.EnableCookies()
		c.Cookies().SetCookies(u, []*Cookie{
			{Name: "sid", Value: "abc123", Domain: "127.0.0.1", Path: "/"},
			{Name: "pref", Value: "dark", Domain: "127.0.0.1", Path: "/"},
		})
		for _, cs := range cases {
			label := preset + " " + cs.name
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, err := c.Do(ctx, cs.req())
			cancel()
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			lines := <-heads
			names := make([]string, len(lines))
			for i, l := range lines {
				names[i], _, _ = strings.Cut(l, ":")
			}
			index := func(name string) int {
				return slices.IndexFunc(names, func(got string) bool { return strings.EqualFold(got, name) })
			}
			n := len(names)
			if n == 0 || !strings.EqualFold(names[0], "Host") {
				t.Errorf("%s: Host is not first: %q", label, lines)
			}
			if n < len(tail) || !slices.EqualFunc(names[n-len(tail):], tail, strings.EqualFold) {
				t.Errorf("%s: the head does not end %q: %q", label, tail, lines)
			} else if lines[n-1] != cs.conn {
				t.Errorf("%s: the last line is %q, want %q", label, lines[n-1], cs.conn)
			}
			if i := index("Connection"); i != n-1 {
				t.Errorf("%s: Connection at %d of %d: %q", label, i, n, lines)
			}
			if i := index("Cookie"); i != n-2 {
				t.Errorf("%s: Cookie at %d of %d: %q", label, i, n, lines)
			}
			al := index("Accept-Language")
			for _, e := range cs.early {
				if i := index(e); i < 0 || i > al {
					t.Errorf("%s: %s at %d, want it before Accept-Language at %d: %q", label, e, i, al, lines)
				}
			}
		}
		c.Close()
	}
}
