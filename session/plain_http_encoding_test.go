package session

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// Over plain HTTP, Chrome 156 and Firefox 159 sent gzip, deflate to a page on
// a LAN address and to everything it loaded from there, and their full list to
// localhost from the same page; Safari 26.3 sent gzip, deflate on every
// plain-HTTP request, localhost included. The session sent each preset's full
// list on every http:// request.
//
// ConnectTo puts a real name on the wire while the socket stays on loopback,
// the way the browser captures mapped one.

// plainEncodingHosts are the hosts each preset is sent to, and whether
// Chrome and Firefox count them as loopback.
var plainEncodingHosts = []struct {
	host     string
	loopback bool
}{
	{"lan-origin.test", false},
	{"192.168.1.20", false},
	{"127.0.0.1", true},
	{"localhost", true},
	{"[::1]", true},
}

var plainEncodingConnectTo = map[string]string{
	"lan-origin.test": "127.0.0.1",
	"192.168.1.20":    "127.0.0.1",
	"localhost":       "127.0.0.1",
	"::1":             "127.0.0.1",
}

// webkitPreset reports whether a preset is Safari or Chrome on iOS, which runs
// on WebKit's network stack.
func webkitPreset(name string) bool {
	return strings.Contains(name, "safari") || strings.Contains(name, "ios")
}

// presetEncoding is the Accept-Encoding the preset's header order carries,
// which is what the session sends over TLS.
func presetEncoding(p *fingerprint.Preset) string {
	for _, h := range p.HeaderOrder {
		if strings.EqualFold(h.Key, "accept-encoding") {
			return h.Value
		}
	}
	return ""
}

func TestSessionPlainHTTPAcceptEncoding(t *testing.T) {
	srv := startEncodingCapture(t)
	for _, name := range fingerprint.Available() {
		p := fingerprint.Get(name)
		full := presetEncoding(p)
		if full == "" {
			t.Fatalf("%s: no accept-encoding in the header order", name)
		}
		s := NewSession("", &protocol.SessionConfig{Preset: name, ConnectTo: plainEncodingConnectTo})
		for i, h := range plainEncodingHosts {
			path := "/" + name + "/" + strconv.Itoa(i)
			srv.get(t, s, "http://"+h.host+":"+srv.port+path, nil)
			want := "gzip, deflate"
			if h.loopback && !webkitPreset(name) {
				want = full
			}
			if got := srv.encoding(path); got != want {
				t.Errorf("%s to http://%s: Accept-Encoding %q, want %q", name, h.host, got, want)
			}
		}
		s.Close()
	}
}

// Each hop of a redirect chain takes the rule for its own URL, not for the
// one that started the chain.
func TestSessionPlainHTTPAcceptEncodingPerRedirectHop(t *testing.T) {
	srv := startEncodingCapture(t)
	for _, name := range []string{"chrome-latest", "firefox-latest", "safari-latest"} {
		full := presetEncoding(fingerprint.Get(name))
		s := NewSession("", &protocol.SessionConfig{
			Preset:          name,
			ConnectTo:       plainEncodingConnectTo,
			FollowRedirects: true,
		})
		srv.get(t, s, "http://localhost:"+srv.port+"/redirect/lan-origin.test/"+name+"/a", nil)
		srv.get(t, s, "http://lan-origin.test:"+srv.port+"/redirect/localhost/"+name+"/b", nil)
		s.Close()

		loopback := full
		if webkitPreset(name) {
			loopback = "gzip, deflate"
		}
		for path, want := range map[string]string{
			"/redirect/lan-origin.test/" + name + "/a": loopback,
			"/" + name + "/a":                          "gzip, deflate",
			"/redirect/localhost/" + name + "/b":       "gzip, deflate",
			"/" + name + "/b":                          loopback,
		} {
			if got := srv.encoding(path); got != want {
				t.Errorf("%s %s: Accept-Encoding %q, want %q", name, path, got, want)
			}
		}
	}
}

// A caller's Accept-Encoding still goes out as given.
func TestSessionPlainHTTPAcceptEncodingCallerWins(t *testing.T) {
	srv := startEncodingCapture(t)
	s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest", ConnectTo: plainEncodingConnectTo})
	defer s.Close()
	srv.get(t, s, "http://lan-origin.test:"+srv.port+"/caller", map[string][]string{"Accept-Encoding": {"br"}})
	if got := srv.encoding("/caller"); got != "br" {
		t.Errorf("Accept-Encoding %q, want the caller's %q", got, "br")
	}
}

// encodingCapture is a plain HTTP/1.1 server that keeps the Accept-Encoding
// line of every request head as it arrived, by request path. A path of
// /redirect/<host>/<rest> answers 302 to http://<host>:<port>/<rest>.
type encodingCapture struct {
	port string

	mu   sync.Mutex
	seen map[string]string
}

func startEncodingCapture(t *testing.T) *encodingCapture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s := &encodingCapture{port: port, seen: map[string]string{}}
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

func (s *encodingCapture) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return
		}
		path, ae := f[1], "(none)"
		for {
			h, err := r.ReadString('\n')
			if err != nil {
				return
			}
			h = strings.TrimRight(h, "\r\n")
			if h == "" {
				break
			}
			if k, v, ok := strings.Cut(h, ":"); ok && strings.EqualFold(k, "Accept-Encoding") {
				ae = strings.TrimSpace(v)
			}
		}
		s.mu.Lock()
		s.seen[path] = ae
		s.mu.Unlock()

		if rest, ok := strings.CutPrefix(path, "/redirect/"); ok {
			host, next, _ := strings.Cut(rest, "/")
			io.WriteString(c, "HTTP/1.1 302 Found\r\nLocation: http://"+host+":"+s.port+"/"+next+"\r\nContent-Length: 0\r\n\r\n")
			continue
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	}
}

func (s *encodingCapture) get(t *testing.T, sess *Session, url string, headers map[string][]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := sess.Request(ctx, &transport.Request{Method: "GET", URL: url, Headers: headers})
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp.Close()
}

func (s *encodingCapture) encoding(path string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.seen[path]; ok {
		return v
	}
	return "(no request)"
}
