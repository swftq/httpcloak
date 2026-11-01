package session

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// Safari 26.3 ended every ordinary HTTP/1.1 request of a capture on macOS 26.3
// with Accept-Language, Priority, Accept-Encoding, the Cookie when it had one,
// and Connection, with nothing after it, and sent the body's headers and every
// other field before Accept-Language. transport's
// TestWebKit26HTTP1EndsWithCookieThenConnection has the counts. Through a
// session the Cookie comes from the jar and the caller's headers from the
// request, and the WebKit 26 presets must still end each request that way,
// plain and over TLS.
func TestSessionWebKit26HTTP1EndsWithCookieThenConnection(t *testing.T) {
	keepAlive := "Connection: keep-alive"
	cases := []struct {
		name  string
		req   func(url string) *transport.Request
		early []string // fields that must come before Accept-Language
		conn  string   // the Connection line
	}{
		{"GET with cookies", func(url string) *transport.Request {
			return &transport.Request{Method: "GET", URL: url}
		}, nil, keepAlive},
		{"POST with a body", func(url string) *transport.Request {
			return &transport.Request{Method: "POST", URL: url, Body: []byte(`{"a":1}`), Headers: map[string][]string{
				"Content-Type": {"application/json"}, "Origin": {"https://example.test"}}}
		}, []string{"Content-Type", "Content-Length", "Origin"}, keepAlive},
		{"chunked upload", func(url string) *transport.Request {
			// A reader whose length the request cannot know.
			return &transport.Request{Method: "POST", URL: url, BodyReader: io.MultiReader(strings.NewReader("chunk")),
				Headers: map[string][]string{"Content-Type": {"application/octet-stream"}}}
		}, []string{"Content-Type", "Transfer-Encoding"}, keepAlive},
		{"Connection: close", func(url string) *transport.Request {
			return &transport.Request{Method: "GET", URL: url, Headers: map[string][]string{"Connection": {"close"}}}
		}, nil, "Connection: close"},
		{"caller header", func(url string) *transport.Request {
			return &transport.Request{Method: "GET", URL: url, Headers: map[string][]string{
				"X-Requested-With": {"XMLHttpRequest"}, "Cache-Control": {"no-cache"}}}
		}, []string{"Cache-Control", "X-Requested-With"}, keepAlive},
	}

	tail := []string{"Accept-Language", "Priority", "Accept-Encoding", "Cookie", "Connection"}
	for _, overTLS := range []bool{false, true} {
		url, heads := startTailLineServer(t, overTLS)
		for _, preset := range []string{"safari-26", "safari-26-ios", "chrome-148-ios", "chrome-155-ios"} {
			s := NewSession("", &protocol.SessionConfig{Preset: preset, ForceHTTP1: true, InsecureSkipVerify: true})
			s.SetCookie("sid", "abc123", "127.0.0.1", "/", false, false, "", 0, nil)
			s.SetCookie("pref", "dark", "127.0.0.1", "/", false, false, "", 0, nil)
			for _, c := range cases {
				label := preset + " " + url[:strings.Index(url, ":")] + " " + c.name
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, err := s.Request(ctx, c.req(url))
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
				} else if lines[n-1] != c.conn {
					t.Errorf("%s: the last line is %q, want %q", label, lines[n-1], c.conn)
				}
				if i := index("Connection"); i != n-1 {
					t.Errorf("%s: Connection at %d of %d: %q", label, i, n, lines)
				}
				if i := index("Cookie"); i != n-2 {
					t.Errorf("%s: Cookie at %d of %d: %q", label, i, n, lines)
				}
				al := index("Accept-Language")
				for _, e := range c.early {
					if i := index(e); i < 0 || i > al {
						t.Errorf("%s: %s at %d, want it before Accept-Language at %d: %q", label, e, i, al, lines)
					}
				}
			}
			s.Close()
		}
	}
}

// startTailLineServer answers HTTP/1.1, over TLS when overTLS is set, and sends
// each request's header lines, in the order they arrived, down the channel. It
// reads a body framed by Content-Length or sent chunked.
func startTailLineServer(t *testing.T, overTLS bool) (string, <-chan []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	scheme := "http"
	if overTLS {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		ln = tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			NextProtos:   []string{"http/1.1"},
		})
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
