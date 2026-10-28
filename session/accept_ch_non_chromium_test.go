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

// Only Chromium implements UA client hints. Firefox 159, loading a page whose
// response carried Accept-CH naming three high-entropy hints, sent no sec-ch-*
// header on that page's requests or after them; Safari implements none either,
// and Chrome on iOS runs on WebKit. The Firefox, Safari and iOS Chrome presets
// send no sec-ch-ua, yet answered Accept-CH with sec-ch-ua-arch, -bitness,
// -model, -platform-version and -wow64, filled in from platform defaults.
func TestAcceptCHIsIgnoredWithoutUAClientHints(t *testing.T) {
	for _, c := range []struct {
		preset string
		hints  bool // whether the request after Accept-CH carries high-entropy hints
	}{
		{"chrome-latest", true},
		{"firefox-latest", false},
		{"safari-latest", false},
		{"chrome-latest-ios", false},
	} {
		srv := newAcceptCHAdvertiser(t, "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-WoW64")
		s := NewSession("", &protocol.SessionConfig{Preset: c.preset, ForceHTTP1: true})
		srv.send(t, s, true)
		next := srv.send(t, s, false)
		s.Close()

		var sent []string
		for _, l := range next {
			name, _, _ := strings.Cut(l, ":")
			if name = strings.ToLower(strings.TrimSpace(name)); strings.HasPrefix(name, "sec-ch-") {
				sent = append(sent, name)
			}
		}
		if c.hints {
			if !strings.Contains(strings.Join(sent, " "), "sec-ch-ua-arch") {
				t.Errorf("%s: no high-entropy hints after Accept-CH: %v", c.preset, sent)
			}
		} else if len(sent) > 0 {
			t.Errorf("%s: sent %v after Accept-CH; the browser sends no UA client hints", c.preset, sent)
		}
	}
}

// acceptCHAdvertiser is a plain HTTP/1.1 server that answers with Accept-CH when
// asked to and hands back each request's header lines.
type acceptCHAdvertiser struct {
	url      string
	acceptCH string
	reqs     chan []string
	advert   chan bool
}

func newAcceptCHAdvertiser(t *testing.T, acceptCH string) *acceptCHAdvertiser {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &acceptCHAdvertiser{
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

func (s *acceptCHAdvertiser) serve(c net.Conn) {
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

// send makes one navigation and returns the header lines the server read for
// it. advertise says whether the response carries Accept-CH.
func (s *acceptCHAdvertiser) send(t *testing.T, sess *Session, advertise bool) []string {
	t.Helper()
	s.advert <- advertise
	resp, err := sess.Request(context.Background(), &transport.Request{Method: "GET", URL: s.url})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Close()
	return <-s.reqs
}
