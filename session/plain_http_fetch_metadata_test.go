package session

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// Browsers send no Sec-Fetch-* and no client hints to a URL that is not
// potentially trustworthy, which over http:// is any host but a loopback one.
// Safari 26.3 sent none on any of its 19 requests to http://192.168.1.151 and
// all three Sec-Fetch-* to localhost. Chrome 156 sent none to a page's own LAN
// name and LAN address, Firefox 159 none to its LAN name, and Chrome no
// sec-ch-ua there, while every request from the same page to localhost
// carried them. On a redirect from https:// down to such a host both dropped
// them on that hop, and sent them again on the hop back up. The session sent
// them to every URL.

// metadataHosts are the hosts each request goes to, and whether a URL with
// http:// to that host is potentially trustworthy.
var metadataHosts = []struct {
	host        string
	trustworthy bool
}{
	{"lan-origin.test", false},
	{"192.168.1.20", false},
	{"127.0.0.1", true},
	{"localhost", true},
	{"[::1]", true},
	{"app.localhost", true},
}

// metadataConnectTo is plainEncodingConnectTo plus the names only these tests
// use. The https origin is a.test, and http://a.test is the same host over
// plain HTTP.
var metadataConnectTo = func() map[string]string {
	m := map[string]string{"app.localhost": "127.0.0.1", "a.test": "127.0.0.1"}
	for k, v := range plainEncodingConnectTo {
		m[k] = v
	}
	return m
}()

// metadataTrio is the client-hint set every Chromium preset sends.
var metadataTrio = []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}

// secMetadataName reports whether a header name is one browsers keep off a
// URL that is not potentially trustworthy: any sec-fetch-* or sec-ch-* name.
func secMetadataName(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "sec-fetch-") || strings.HasPrefix(n, "sec-ch-")
}

// secMetadataLines returns the sec-fetch-* and sec-ch-* lines of req, as sent.
func secMetadataLines(req *capturedRequest) []string {
	var out []string
	for _, l := range req.lines {
		if secMetadataName(l[0]) {
			out = append(out, l[0]+": "+l[1])
		}
	}
	return out
}

// secMetadataKeys returns the sec-fetch-* and sec-ch-* names in h.
func secMetadataKeys(h http.Header) []string {
	var out []string
	for k := range h {
		if secMetadataName(k) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// sendsClientHints reports whether the preset's emit set has the sec-ch-ua
// trio, which is true of the Chromium presets.
func sendsClientHints(p *fingerprint.Preset) bool {
	for _, h := range p.HeaderOrder {
		if strings.EqualFold(h.Key, "sec-ch-ua") {
			return true
		}
	}
	return false
}

// Every preset, every request shape: nothing from either family reaches a LAN
// name or address, and the rest of the request is the one localhost gets, in
// the same order. Loopback hosts keep both, as before.
func TestSessionPlainHTTPFetchMetadata(t *testing.T) {
	srv := startEncodingCapture(t)
	shapes := []struct {
		name    string
		method  string
		headers map[string][]string
		body    []byte
	}{
		{"navigation", "GET", nil, nil},
		{"fetch", "POST", map[string][]string{"Content-Type": {"application/json"}}, []byte(`{"q":1}`)},
		// What the bindings' fetch_mode "cors" adds to the caller's headers.
		{"fetch_mode", "GET", map[string][]string{"Sec-Fetch-Mode": {"cors"}, "Sec-Fetch-Dest": {"empty"}}, nil},
		{"image", "GET", map[string][]string{"Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Dest": {"image"}}, nil},
	}
	for _, name := range fingerprint.Available() {
		p := fingerprint.Get(name)
		if !slices.ContainsFunc(p.HeaderOrder, func(h fingerprint.HeaderPair) bool {
			return strings.HasPrefix(strings.ToLower(h.Key), "sec-fetch-")
		}) {
			t.Fatalf("%s: no sec-fetch-* in the header order", name)
		}
		hints := sendsClientHints(p)
		s := NewSession("", &protocol.SessionConfig{Preset: name, ConnectTo: metadataConnectTo})
		for _, sh := range shapes {
			prefix := "/" + name + "/" + sh.name + "/"
			for i, h := range metadataHosts {
				sendAndClose(t, s, &transport.Request{
					Method:  sh.method,
					URL:     "http://" + h.host + ":" + srv.port + prefix + strconv.Itoa(i),
					Headers: sh.headers,
					Body:    sh.body,
				})
			}
			local := srv.request(prefix + "3") // localhost
			for i, h := range metadataHosts {
				req := srv.request(prefix + strconv.Itoa(i))
				if req == nil || local == nil {
					t.Fatalf("%s %s: a request did not arrive", name, sh.name)
				}
				if h.trustworthy {
					var missing []string
					for _, want := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
						if _, ok := req.value(want); !ok {
							missing = append(missing, want)
						}
					}
					if hints {
						for _, want := range metadataTrio {
							if _, ok := req.value(want); !ok {
								missing = append(missing, want)
							}
						}
					}
					if len(missing) > 0 {
						t.Errorf("%s %s to http://%s: no %s", name, sh.name, h.host, strings.Join(missing, ", "))
					}
					continue
				}
				if sec := secMetadataLines(req); len(sec) > 0 {
					t.Errorf("%s %s to http://%s: sent %s", name, sh.name, h.host, strings.Join(sec, "; "))
					continue
				}
				want := slices.DeleteFunc(local.names(), secMetadataName)
				if got := req.names(); !slices.Equal(got, want) {
					t.Errorf("%s %s to http://%s: header order\n got %v\nwant %v", name, sh.name, h.host, got, want)
				}
			}
		}
		s.Close()
	}
}

// The streaming path builds its request on its own, so it is checked on its
// own: RequestStream over plain HTTP.
func TestSessionPlainHTTPFetchMetadataStream(t *testing.T) {
	srv := startEncodingCapture(t)
	for _, name := range []string{"chrome-latest", "firefox-latest", "safari-latest"} {
		s := NewSession("", &protocol.SessionConfig{Preset: name, ConnectTo: metadataConnectTo})
		for _, host := range []string{"lan-origin.test", "localhost"} {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := s.RequestStream(ctx, &transport.Request{
				Method: "GET",
				URL:    "http://" + host + ":" + srv.port + "/stream/" + name + "/" + host,
			})
			if err != nil {
				cancel()
				t.Fatalf("%s RequestStream to %s: %v", name, host, err)
			}
			io.Copy(io.Discard, resp)
			resp.Close()
			cancel()
		}
		s.Close()

		lan, local := srv.request("/stream/"+name+"/lan-origin.test"), srv.request("/stream/"+name+"/localhost")
		if lan == nil || local == nil {
			t.Fatalf("%s: a streamed request did not arrive", name)
		}
		if sec := secMetadataLines(lan); len(sec) > 0 {
			t.Errorf("%s RequestStream to http://lan-origin.test: sent %s", name, strings.Join(sec, "; "))
		}
		if _, ok := local.value("Sec-Fetch-Mode"); !ok {
			t.Errorf("%s RequestStream to http://localhost: no Sec-Fetch-Mode", name)
		}
	}
}

// Each redirect hop is judged by its own URL. A hop from https:// down to a
// LAN host goes without, the hop back up sends them again, and a hop over to
// localhost keeps them, the way Chrome 156 and Firefox 159 followed such
// chains. The https hops run over HTTP/2 and over HTTP/1.1.
func TestSessionFetchMetadataPerRedirectHop(t *testing.T) {
	plain := startEncodingCapture(t)
	tls := startTLSMetadataServer(t)
	httpURL := func(host, path string) string { return "http://" + host + ":" + plain.port + path }
	httpsURL := func(path string) string { return "https://a.test:" + tls.port + path }

	for _, name := range []string{"chrome-latest", "firefox-latest", "safari-latest", "ios-chrome-latest"} {
		hints := sendsClientHints(fingerprint.Get(name))
		// missing lists which of the Sec-Fetch-* and, on Chromium, the client
		// hints are absent from a request that should carry them.
		missing := func(value func(string) (string, bool)) []string {
			var out []string
			names := []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"}
			if hints {
				names = append(names, metadataTrio...)
			}
			for _, n := range names {
				if _, ok := value(n); !ok {
					out = append(out, n)
				}
			}
			return out
		}

		for _, forceH1 := range []bool{false, true} {
			proto, wantProto := "h2", "HTTP/2.0"
			if forceH1 {
				proto, wantProto = "h1", "HTTP/1.1"
			}
			s := NewSession("", &protocol.SessionConfig{
				Preset:             name,
				ConnectTo:          metadataConnectTo,
				InsecureSkipVerify: true,
				DisableHTTP3:       true,
				ForceHTTP1:         forceH1,
				FollowRedirects:    true,
			})
			p := "/" + name + "/" + proto

			// (a) https://a.test 302 -> http://lan-origin.test
			tls.respond(p+"/a/1", cannedReply{status: "302 Found", header: []string{"Location: " + httpURL("lan-origin.test", p+"/a/2")}})
			sendAndClose(t, s, &transport.Request{Method: "GET", URL: httpsURL(p + "/a/1")})
			// (b) http://lan-origin.test 302 -> https://a.test
			plain.respond(p+"/b/1", cannedReply{status: "302 Found", header: []string{"Location: " + httpsURL(p+"/b/2")}})
			sendAndClose(t, s, &transport.Request{Method: "GET", URL: httpURL("lan-origin.test", p+"/b/1")})
			// (d) a fetch() POST with the caller's own Sec-Fetch-Mode and
			// Sec-Fetch-Site, 307 https -> http -> https.
			tls.respond(p+"/d/1", cannedReply{status: "307 Temporary Redirect", header: []string{"Location: " + httpURL("lan-origin.test", p+"/d/2")}})
			plain.respond(p+"/d/2", cannedReply{status: "307 Temporary Redirect", header: []string{"Location: " + httpsURL(p+"/d/3")}})
			sendAndClose(t, s, &transport.Request{
				Method: "POST",
				URL:    httpsURL(p + "/d/1"),
				Headers: map[string][]string{
					"Content-Type":   {"application/json"},
					"Sec-Fetch-Mode": {"cors"},
					"Sec-Fetch-Site": {"same-origin"},
				},
				Body: []byte(`{"q":1}`),
			})
			s.Close()

			for _, path := range []string{p + "/a/1", p + "/b/2", p + "/d/1", p + "/d/3"} {
				req, ok := tls.request(path)
				if !ok {
					t.Fatalf("%s %s: no request reached https://a.test%s", name, proto, path)
				}
				if req.proto != wantProto {
					t.Errorf("%s %s: https://a.test%s went over %s", name, proto, path, req.proto)
				}
				if m := missing(func(n string) (string, bool) {
					v := req.header.Get(n)
					return v, v != ""
				}); len(m) > 0 {
					t.Errorf("%s %s: https://a.test%s has no %s", name, proto, path, strings.Join(m, ", "))
				}
			}
			for _, path := range []string{p + "/a/2", p + "/b/1", p + "/d/2"} {
				req := plain.request(path)
				if req == nil {
					t.Fatalf("%s %s: no request reached http://lan-origin.test%s", name, proto, path)
				}
				if sec := secMetadataLines(req); len(sec) > 0 {
					t.Errorf("%s %s: http://lan-origin.test%s sent %s", name, proto, path, strings.Join(sec, "; "))
				}
			}

			// The POST keeps its body and Content-Type on the plain hop, and
			// the hop back up sends the caller's Sec-Fetch-Mode again: the
			// strip took it off the wire, not off the request the session
			// carries from hop to hop.
			if req := plain.request(p + "/d/2"); req != nil {
				if ct, _ := req.value("Content-Type"); req.method != "POST" || req.body != `{"q":1}` || ct != "application/json" {
					t.Errorf("%s %s: plain hop of the POST: %s, body %q, Content-Type %q", name, proto, req.method, req.body, ct)
				}
			}
			if req, ok := tls.request(p + "/d/3"); ok {
				if got := req.header.Get("Sec-Fetch-Mode"); got != "cors" || req.body != `{"q":1}` {
					t.Errorf("%s %s: last hop of the POST: Sec-Fetch-Mode %q, body %q", name, proto, got, req.body)
				}
			}
		}

		// (c) http://lan-origin.test 302 -> http://localhost
		s := NewSession("", &protocol.SessionConfig{Preset: name, ConnectTo: metadataConnectTo, FollowRedirects: true})
		plain.get(t, s, httpURL("lan-origin.test", "/redirect/localhost/"+name+"/c"), nil)
		s.Close()
		first, hop := plain.request("/redirect/localhost/"+name+"/c"), plain.request("/"+name+"/c")
		if first == nil || hop == nil {
			t.Fatalf("%s: a request of the chain to http://localhost did not arrive", name)
		}
		if sec := secMetadataLines(first); len(sec) > 0 {
			t.Errorf("%s: http://lan-origin.test before the hop to localhost sent %s", name, strings.Join(sec, "; "))
		}
		if m := missing(hop.value); len(m) > 0 {
			t.Errorf("%s: the hop to http://localhost has no %s", name, strings.Join(m, ", "))
		}
	}
}

// Hints a host asked for in Accept-CH stay off that same host over plain
// HTTP, along with the trio, and come back on its https:// URL.
func TestSessionPlainHTTPClientHints(t *testing.T) {
	plain := startEncodingCapture(t)
	tls := startTLSMetadataServer(t)
	tls.respond("/ch/1", cannedReply{status: "200 OK", header: []string{"Accept-CH: Sec-CH-UA-Arch, Sec-CH-UA-Full-Version-List"}})

	s := NewSession("", &protocol.SessionConfig{
		Preset:             "chrome-latest",
		ConnectTo:          metadataConnectTo,
		InsecureSkipVerify: true,
		DisableHTTP3:       true,
	})
	defer s.Close()
	plain.get(t, s, "https://a.test:"+tls.port+"/ch/1", nil)
	plain.get(t, s, "http://a.test:"+plain.port+"/ch/2", nil)
	plain.get(t, s, "https://a.test:"+tls.port+"/ch/3", nil)

	plainReq := plain.request("/ch/2")
	if plainReq == nil {
		t.Fatal("no request reached http://a.test/ch/2")
	}
	if sec := secMetadataLines(plainReq); len(sec) > 0 {
		t.Errorf("http://a.test after its Accept-CH: sent %s", strings.Join(sec, "; "))
	}
	req, ok := tls.request("/ch/3")
	if !ok {
		t.Fatal("no request reached https://a.test/ch/3")
	}
	for _, want := range append(metadataTrio, "sec-ch-ua-arch", "sec-ch-ua-full-version-list") {
		if req.header.Get(want) == "" {
			t.Errorf("https://a.test after its Accept-CH: no %s (sent %v)", want, secMetadataKeys(req.header))
		}
	}
}

// Warmup writes each subresource's Sec-Fetch-* as caller headers, so the
// strip has to catch those too.
func TestWarmupPlainHTTPFetchMetadata(t *testing.T) {
	srv := startEncodingCapture(t)
	page := `<!doctype html><html><head><link rel="stylesheet" href="style.css">` +
		`<script src="app.js"></script></head><body><img src="img.png"></body></html>`
	for _, name := range []string{"chrome-latest", "firefox-latest", "safari-latest"} {
		s := NewSession("", &protocol.SessionConfig{Preset: name, ConnectTo: metadataConnectTo})
		for _, host := range []string{"lan-origin.test", "localhost"} {
			dir := "/warmup/" + name + "/" + host + "/"
			srv.respond(dir+"page", cannedReply{status: "200 OK", header: []string{"Content-Type: text/html; charset=utf-8"}, body: page})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := s.Warmup(ctx, "http://"+host+":"+srv.port+dir+"page"); err != nil {
				cancel()
				t.Fatalf("%s Warmup of http://%s: %v", name, host, err)
			}
			cancel()
			for _, res := range []string{"page", "style.css", "app.js", "img.png"} {
				req := srv.request(dir + res)
				if req == nil {
					t.Errorf("%s Warmup of http://%s: %s was not fetched", name, host, res)
					continue
				}
				if host == "localhost" {
					for _, want := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
						if _, ok := req.value(want); !ok {
							t.Errorf("%s Warmup of http://localhost: %s has no %s", name, res, want)
						}
					}
					continue
				}
				if sec := secMetadataLines(req); len(sec) > 0 {
					t.Errorf("%s Warmup of http://%s: %s sent %s", name, host, res, strings.Join(sec, "; "))
				}
			}
		}
		s.Close()
	}
}

// tlsMetadataServer is the https://a.test origin: an httptest TLS server that
// speaks HTTP/2 and HTTP/1.1. It keeps each request's protocol, headers and
// body by path, answers a path given a reply with respond, and any other with
// an empty 200.
type tlsMetadataServer struct {
	port string

	mu      sync.Mutex
	seen    map[string]tlsMetadataRequest
	replies map[string]cannedReply
}

type tlsMetadataRequest struct {
	proto  string
	header http.Header
	body   string
}

func startTLSMetadataServer(t *testing.T) *tlsMetadataServer {
	t.Helper()
	s := &tlsMetadataServer{seen: map[string]tlsMetadataRequest{}, replies: map[string]cannedReply{}}
	srv := httptest.NewUnstartedServer(s)
	srv.EnableHTTP2 = true
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, s.port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	return s
}

func (s *tlsMetadataServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.seen[r.URL.Path] = tlsMetadataRequest{proto: r.Proto, header: r.Header.Clone(), body: string(body)}
	reply, canned := s.replies[r.URL.Path]
	s.mu.Unlock()
	if !canned {
		return
	}
	for _, h := range reply.header {
		k, v, _ := strings.Cut(h, ":")
		w.Header().Set(k, strings.TrimSpace(v))
	}
	code, _ := strconv.Atoi(reply.status[:3])
	w.WriteHeader(code)
	io.WriteString(w, reply.body)
}

func (s *tlsMetadataServer) respond(path string, reply cannedReply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replies[path] = reply
}

func (s *tlsMetadataServer) request(path string) (tlsMetadataRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.seen[path]
	return req, ok
}
