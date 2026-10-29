package session

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// Chrome parses Accept-CH only on the response to an outermost main-frame
// navigation. Cloudflare's challenge iframe answers with Accept-CH and
// Critical-CH naming five high-entropy hints, and Chrome sent none of them to
// that host afterwards, on any frame-side request; the session sent all five.
// A fetch's response is the same: it can ask, and nothing is learned.
func TestAcceptCHIsLearnedOnlyFromANavigation(t *testing.T) {
	iframe := map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}, "Sec-Fetch-Site": {"cross-site"}}
	fetch := map[string][]string{"Accept": {"application/json"}}

	for _, c := range []struct {
		name    string
		first   map[string][]string // the request whose response carries Accept-CH
		learned bool
	}{
		{"navigation", nil, true},
		{"iframe", iframe, false},
		{"fetch", fetch, false},
	} {
		srv := newAcceptCHCapture(t, "Sec-CH-UA-Arch, Sec-CH-UA-Platform-Version")
		s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest", ForceHTTP1: true})

		srv.send(t, s, c.first, true)
		// The next request is a navigation either way, so only what was
		// learned from the first response decides whether it carries hints.
		lines := srv.send(t, s, nil, false)
		s.Close()

		hasArch := false
		for _, l := range lines {
			if strings.HasPrefix(strings.ToLower(l), "sec-ch-ua-arch:") {
				hasArch = true
			}
		}
		if hasArch != c.learned {
			t.Errorf("Accept-CH on the %s's response: learned %v, want %v\n%s", c.name, hasArch, c.learned, strings.Join(lines, "\n"))
		}
	}
}

// acceptCHCapture is a plain HTTP/1.1 server that answers with Accept-CH when
// asked to and hands back each request's header lines.
type acceptCHCapture struct {
	url      string
	acceptCH string
	reqs     chan []string
	advert   chan bool
}

func newAcceptCHCapture(t *testing.T, acceptCH string) *acceptCHCapture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &acceptCHCapture{
		url:      "http://" + ln.Addr().String() + "/",
		acceptCH: acceptCH,
		reqs:     make(chan []string, 4),
		advert:   make(chan bool, 4),
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *acceptCHCapture) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		if _, err := br.ReadString('\n'); err != nil { // request line
			return
		}
		var lines []string
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if l = strings.TrimRight(l, "\r\n"); l == "" {
				break
			}
			lines = append(lines, l)
		}
		s.reqs <- lines
		extra := ""
		if <-s.advert {
			extra = "Accept-CH: " + s.acceptCH + "\r\n"
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\n"+extra+"Content-Length: 2\r\n\r\nok")
	}
}

// send makes one GET and returns the header lines the server read for it.
// advertise says whether the response carries Accept-CH.
func (s *acceptCHCapture) send(t *testing.T, sess *Session, headers map[string][]string, advertise bool) []string {
	t.Helper()
	s.advert <- advertise
	resp, err := sess.Request(context.Background(), &transport.Request{Method: "GET", URL: s.url, Headers: headers})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Close()
	return <-s.reqs
}
