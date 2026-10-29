package session

import (
	"bufio"
	"context"
	"io"
	"maps"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// Chrome keeps each host's Accept-CH in the profile, as a durable
// CLIENT_HINTS content setting, so a host that asked before gets the
// high-entropy hints on the first request after a restart. A saved session
// kept its cookies and TLS tickets and dropped what hosts had asked for, so the
// first request after a load went without the hints and the second carried
// them: a first request unlike the ones after it.
func TestSavedSessionKeepsAcceptCH(t *testing.T) {
	srv := newCHStateServer(t, "Sec-CH-UA-Arch, Sec-CH-UA-Platform-Version")
	s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest", ForceHTTP1: true})
	srv.send(t, s, true)
	data, err := s.Marshal()
	s.Close()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := UnmarshalSession(data)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if got, want := restored.AcceptCH(srv.host), []string{"sec-ch-ua-arch", "sec-ch-ua-platform-version"}; !slices.Equal(got, want) {
		t.Errorf("restored AcceptCH = %q, want %q", got, want)
	}
	sent := highEntropyHints(srv.send(t, restored, false))
	if _, ok := sent["sec-ch-ua-arch"]; !ok {
		t.Errorf("first request after a load carries no sec-ch-ua-arch: %v", sent)
	}
	if _, ok := sent["sec-ch-ua-platform-version"]; !ok {
		t.Errorf("first request after a load carries no sec-ch-ua-platform-version: %v", sent)
	}
}

// A session rebuilt from state kept elsewhere, cookies in a caller's own store
// say, can be told what a host asked for, and asked what it learned. What
// ClientHintsFor reports is what goes on the wire, because the injector reads
// the same map.
func TestSetAcceptCHSeedsTheFirstRequest(t *testing.T) {
	srv := newCHStateServer(t, "")
	s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest", ForceHTTP1: true})
	defer s.Close()

	if got := s.AcceptCH(srv.host); got != nil {
		t.Fatalf("fresh session: AcceptCH = %q, want nil", got)
	}
	s.SetAcceptCH(srv.url, []string{"Sec-CH-UA-Arch", " sec-ch-ua-bitness ", ""})
	if got, want := s.AcceptCH(srv.host), []string{"sec-ch-ua-arch", "sec-ch-ua-bitness"}; !slices.Equal(got, want) {
		t.Errorf("AcceptCH = %q, want %q", got, want)
	}
	reported := s.ClientHintsFor(srv.host)
	if len(reported) != 2 {
		t.Errorf("ClientHintsFor = %v, want sec-ch-ua-arch and sec-ch-ua-bitness", reported)
	}
	if sent := highEntropyHints(srv.send(t, s, false)); !maps.Equal(sent, reported) {
		t.Errorf("first request sent %v, ClientHintsFor said %v", sent, reported)
	}

	s.SetHighEntropyClientHintsEnabled(false)
	if got := s.ClientHintsFor(srv.host); got != nil {
		t.Errorf("high-entropy hints off: ClientHintsFor = %v, want nil", got)
	}
	s.SetHighEntropyClientHintsEnabled(true)

	s.SetAcceptCH(srv.host, nil)
	if got := s.AcceptCH(srv.host); got != nil {
		t.Errorf("after forgetting the host: AcceptCH = %q, want nil", got)
	}
	if sent := highEntropyHints(srv.send(t, s, false)); len(sent) != 0 {
		t.Errorf("after forgetting the host the request sent %v", sent)
	}
}

// highEntropyHints picks the sec-ch-ua-* headers other than the low-entropy
// trio out of a request's header lines, lowercase name to value.
func highEntropyHints(lines []string) map[string]string {
	out := map[string]string{}
	for _, l := range lines {
		name, value, _ := strings.Cut(l, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		switch {
		case !strings.HasPrefix(name, "sec-ch-ua-"), name == "sec-ch-ua-mobile", name == "sec-ch-ua-platform":
			continue
		}
		out[name] = strings.TrimSpace(value)
	}
	return out
}

// chStateServer is a plain HTTP/1.1 server that answers with Accept-CH when
// asked to and hands back each request's header lines.
type chStateServer struct {
	url, host string
	acceptCH  string
	reqs      chan []string
	advert    chan bool
}

func newCHStateServer(t *testing.T, acceptCH string) *chStateServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &chStateServer{
		url:      "http://" + ln.Addr().String() + "/",
		host:     "127.0.0.1",
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

func (s *chStateServer) serve(c net.Conn) {
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
func (s *chStateServer) send(t *testing.T, sess *Session, advertise bool) []string {
	t.Helper()
	s.advert <- advertise
	resp, err := sess.Request(context.Background(), &transport.Request{Method: "GET", URL: s.url})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Close()
	return <-s.reqs
}
