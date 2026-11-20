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

// encodingCapture is a plain HTTP/1.1 server that keeps every request as it
// arrived, by request path: the method, each header line in order and casing,
// and the body. A path given a reply with respond answers with it, a path of
// /redirect/<host>/<rest> answers 302 to http://<host>:<port>/<rest>, and any
// other gets an empty 200.
type encodingCapture struct {
	port string

	mu      sync.Mutex
	seen    map[string]*capturedRequest
	replies map[string]cannedReply
}

// capturedRequest is one request as encodingCapture read it off the wire.
type capturedRequest struct {
	method string
	lines  [][2]string // each header line's name and value, in wire order
	body   string
}

// value returns the first value sent under name, matched in any case.
func (r *capturedRequest) value(name string) (string, bool) {
	for _, l := range r.lines {
		if strings.EqualFold(l[0], name) {
			return l[1], true
		}
	}
	return "", false
}

// names returns the header names in wire order, lowercased.
func (r *capturedRequest) names() []string {
	out := make([]string, len(r.lines))
	for i, l := range r.lines {
		out[i] = strings.ToLower(l[0])
	}
	return out
}

// cannedReply is the response respond sets up for one path.
type cannedReply struct {
	status string   // what follows the version on the status line: "302 Found"
	header []string // "Name: value" lines; Content-Length is added
	body   string
}

func startEncodingCapture(t *testing.T) *encodingCapture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s := &encodingCapture{port: port, seen: map[string]*capturedRequest{}, replies: map[string]cannedReply{}}
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
		path, req, length := f[1], &capturedRequest{method: f[0]}, 0
		for {
			h, err := r.ReadString('\n')
			if err != nil {
				return
			}
			h = strings.TrimRight(h, "\r\n")
			if h == "" {
				break
			}
			k, v, _ := strings.Cut(h, ":")
			v = strings.TrimSpace(v)
			req.lines = append(req.lines, [2]string{k, v})
			if strings.EqualFold(k, "Content-Length") {
				length, _ = strconv.Atoi(v)
			}
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(r, body); err != nil {
			return
		}
		req.body = string(body)
		s.mu.Lock()
		s.seen[path] = req
		reply, canned := s.replies[path]
		s.mu.Unlock()

		if canned {
			head := "HTTP/1.1 " + reply.status + "\r\n"
			for _, h := range reply.header {
				head += h + "\r\n"
			}
			io.WriteString(c, head+"Content-Length: "+strconv.Itoa(len(reply.body))+"\r\n\r\n"+reply.body)
			continue
		}
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
	sendAndClose(t, sess, &transport.Request{Method: "GET", URL: url, Headers: headers})
}

// sendAndClose sends req through sess and closes the response.
func sendAndClose(t *testing.T, sess *Session, req *transport.Request) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := sess.Request(ctx, req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	resp.Close()
}

// respond makes the capture answer path with reply.
func (s *encodingCapture) respond(path string, reply cannedReply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replies[path] = reply
}

// request returns what arrived for path, or nil.
func (s *encodingCapture) request(path string) *capturedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[path]
}

func (s *encodingCapture) encoding(path string) string {
	req := s.request(path)
	if req == nil {
		return "(no request)"
	}
	if v, ok := req.value("Accept-Encoding"); ok {
		return v
	}
	return "(none)"
}
