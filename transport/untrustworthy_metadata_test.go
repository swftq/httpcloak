package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// Browsers send no Sec-Fetch-* and no client hints to a URL that is not
// potentially trustworthy. Safari 26.3 sent none on any of its 19 requests to
// http://192.168.1.151 and all three Sec-Fetch-* to localhost; Chrome 156 sent
// none to a LAN name and a LAN address, Firefox 159 none to a LAN name, and
// Chrome no sec-ch-ua there, while every request from the same page to
// localhost carried them. ConnectTo puts the LAN name on the wire while the
// socket stays on loopback.

// trustHosts are the hosts each request goes to, and whether a URL with
// http:// to that host is potentially trustworthy.
var trustHosts = []struct {
	host        string
	trustworthy bool
}{
	{"lan-origin.test", false},
	{"192.168.1.20", false},
	{"localhost", true},
	{"127.0.0.1", true},
	{"[::1]", true},
	{"app.localhost", true},
}

var trustConnectTo = map[string]string{
	"lan-origin.test": "127.0.0.1",
	"192.168.1.20":    "127.0.0.1",
	"localhost":       "127.0.0.1",
	"::1":             "127.0.0.1",
	"app.localhost":   "127.0.0.1",
}

// isSecMetadataName reports whether a header name is one browsers keep off a
// URL that is not potentially trustworthy: any sec-fetch-* or sec-ch-* name.
func isSecMetadataName(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "sec-fetch-") || strings.HasPrefix(n, "sec-ch-")
}

func TestUntrustworthyURLGetsNoSecHeaders(t *testing.T) {
	srv := startTrustCapture(t)
	shapes := []struct {
		name    string
		method  string
		headers map[string][]string
		body    []byte
	}{
		{"navigation", "GET", nil, nil},
		// A JSON POST sniffs as a fetch(): cors, empty, Accept */* and no
		// Upgrade-Insecure-Requests.
		{"fetch", "POST", map[string][]string{"Content-Type": {"application/json"}}, []byte(`{"q":1}`)},
		// Lowercase keys, as the bindings and most callers pass them.
		{"image", "GET", map[string][]string{"sec-fetch-mode": {"no-cors"}, "sec-fetch-dest": {"image"}}, nil},
	}
	for _, name := range []string{"chrome-latest", "android-chrome-latest", "firefox-latest", "safari-latest", "ios-chrome-latest"} {
		chromium := presetNames(fingerprint.Get(name))["sec-ch-ua"]
		tr := NewTransport(name)
		for host, to := range trustConnectTo {
			tr.SetConnectTo(host, to)
		}
		for _, stream := range []bool{false, true} {
			path := "Do"
			if stream {
				path = "DoStream"
			}
			for _, sh := range shapes {
				prefix := "/" + name + "/" + path + "/" + sh.name + "/"
				for i, h := range trustHosts {
					srv.send(t, tr, stream, &Request{
						Method:  sh.method,
						URL:     "http://" + h.host + ":" + srv.port + prefix + strconv.Itoa(i),
						Headers: sh.headers,
						Body:    sh.body,
					})
				}
				local := srv.head(t, prefix+"2") // localhost
				for i, h := range trustHosts {
					head := srv.head(t, prefix+strconv.Itoa(i))
					what := fmt.Sprintf("%s %s %s to http://%s", name, path, sh.name, h.host)
					if h.trustworthy {
						for _, want := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
							if _, ok := head.value(want); !ok {
								t.Errorf("%s: no %s", what, want)
							}
						}
						if chromium {
							for _, want := range []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"} {
								if _, ok := head.value(want); !ok {
									t.Errorf("%s: no %s", what, want)
								}
							}
						}
						continue
					}
					if sec := head.secMetadata(); len(sec) > 0 {
						t.Errorf("%s: sent %s", what, strings.Join(sec, ", "))
						continue
					}
					// Everything else keeps the shape the removed headers gave it:
					// the same names in the same order as to localhost, with the
					// same values apart from Host and the plain-HTTP
					// Accept-Encoding. A preset on the cfnetwork model lays a
					// request other than a navigation out from the names it
					// carries there, as Safari 26.3 did (cfnetworkHeaderNames),
					// so its order is the model's for those names.
					want := slices.DeleteFunc(local.names(), isSecMetadataName)
					if p := fingerprint.Get(name); p.H2HeaderOrderModel() == fingerprint.HeaderOrderModelCFNetwork && sh.name != "navigation" {
						want = cfnetworkWireOrder(p, want)
					}
					if got := head.names(); !slices.Equal(got, want) {
						t.Errorf("%s: header order\n got %v\nwant %v", what, got, want)
						continue
					}
					for _, l := range head {
						if strings.EqualFold(l[0], "Host") || strings.EqualFold(l[0], "Accept-Encoding") {
							continue
						}
						if lv, _ := local.value(l[0]); lv != l[1] {
							t.Errorf("%s: %s %q, to localhost %q", what, l[0], l[1], lv)
						}
					}
					if sh.name == "fetch" {
						if v, _ := head.value("Accept"); v != "*/*" {
							t.Errorf("%s: Accept %q, want */*", what, v)
						}
						if _, ok := head.value("Upgrade-Insecure-Requests"); ok {
							t.Errorf("%s: sent Upgrade-Insecure-Requests", what)
						}
						// A preset that sends the priority header over HTTP/1.1,
						// Firefox here, shows in its value which destination the
						// priority was read from.
						nav := srv.head(t, "/"+name+"/"+path+"/navigation/"+strconv.Itoa(i))
						if v, ok := head.value("Priority"); ok {
							if nv, _ := nav.value("Priority"); v == nv {
								t.Errorf("%s: priority %q, the navigation's", what, v)
							}
						}
					}
				}
			}
		}
		tr.Close()
	}
}

// The caller composes the header set of an ExactHeaders or a TLS-only request,
// so both go out as built, and a preset with no Sec-Fetch-* at all describes a
// client that is not a browser, so it is left alone too.
func TestUntrustworthyURLStripExemptions(t *testing.T) {
	srv := startTrustCapture(t)
	lan := "http://lan-origin.test:" + srv.port

	tr := NewTransport("chrome-latest")
	tr.SetConnectTo("lan-origin.test", "127.0.0.1")
	defer tr.Close()

	exact := []fingerprint.HeaderPair{
		{Key: "sec-fetch-mode", Value: "cors"},
		{Key: "sec-ch-ua", Value: `"Chromium";v="155"`},
		{Key: "sec-fetch-dest", Value: "empty"},
	}
	srv.send(t, tr, false, &Request{Method: "GET", URL: lan + "/exact", ExactHeaders: exact})
	var got []fingerprint.HeaderPair
	for _, l := range srv.head(t, "/exact") {
		if !strings.EqualFold(l[0], "Host") {
			got = append(got, fingerprint.HeaderPair{Key: l[0], Value: l[1]})
		}
	}
	if !slices.Equal(got, exact) {
		t.Errorf("ExactHeaders: sent %v, want %v", got, exact)
	}

	tlsOnly := true
	srv.send(t, tr, false, &Request{Method: "GET", URL: lan + "/tls-only", TLSOnly: &tlsOnly,
		Headers: map[string][]string{"Sec-Fetch-Mode": {"cors"}}})
	if v, _ := srv.head(t, "/tls-only").value("Sec-Fetch-Mode"); v != "cors" {
		t.Errorf("TLS-only: Sec-Fetch-Mode %q, want the caller's cors", v)
	}

	// based_on chrome-latest, with every sec-fetch-* entry dropped from its
	// order, which is its emit set.
	base := fingerprint.Get("chrome-latest")
	var order []map[string]string
	var chUA string
	for _, h := range base.HeaderOrder {
		switch {
		case strings.HasPrefix(strings.ToLower(h.Key), "sec-fetch-"):
			continue
		case strings.EqualFold(h.Key, "sec-ch-ua"):
			chUA = h.Value
		}
		order = append(order, map[string]string{"key": h.Key, "value": h.Value})
	}
	if chUA == "" {
		t.Fatal("chrome-latest lists no sec-ch-ua")
	}
	js, err := json.Marshal(map[string]any{"version": 1, "preset": map[string]any{
		"name": "trust-no-sec-fetch", "based_on": "chrome-latest",
		"headers": map[string]any{"order": order},
	}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := fingerprint.LoadAndBuildPresetFromJSON(js)
	if err != nil {
		t.Fatal(err)
	}
	if err := fingerprint.RegisterStrict(p.Name, p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fingerprint.Unregister(p.Name) })

	custom := NewTransport(p.Name)
	custom.SetConnectTo("lan-origin.test", "127.0.0.1")
	defer custom.Close()
	srv.send(t, custom, false, &Request{Method: "GET", URL: lan + "/custom",
		Headers: map[string][]string{"Sec-Fetch-Mode": {"navigate"}}})
	head := srv.head(t, "/custom")
	if v, _ := head.value("Sec-Fetch-Mode"); v != "navigate" {
		t.Errorf("preset without Sec-Fetch-*: Sec-Fetch-Mode %q, want the caller's navigate", v)
	}
	if v, _ := head.value("sec-ch-ua"); v != chUA {
		t.Errorf("preset without Sec-Fetch-*: sec-ch-ua %q, want its own %q", v, chUA)
	}
}

// cfnetworkWireOrder is the HTTP/1.1 order a preset on the cfnetwork model
// gives a request that carries names, lowercased: Host first, where the writer
// puts it, then the layout of the rest, with Content-Length framing the body
// when it is among them.
func cfnetworkWireOrder(p *fingerprint.Preset, names []string) []string {
	body := ""
	if slices.Contains(names, "content-length") {
		body = "content-length"
	}
	var out []string
	if slices.Contains(names, "host") {
		out = append(out, "host")
	}
	for _, n := range p.CFNetworkHeaderOrder(names, body) {
		if slices.Contains(names, n) {
			out = append(out, n)
		}
	}
	return out
}

// presetNames is the set of lowercase header names in the preset's emit set.
func presetNames(p *fingerprint.Preset) map[string]bool {
	names := map[string]bool{}
	for _, h := range p.HeaderOrder {
		names[strings.ToLower(h.Key)] = true
	}
	return names
}

// trustHead is one request head as it arrived: each header line's name and
// value, in wire order and casing.
type trustHead [][2]string

func (h trustHead) value(name string) (string, bool) {
	for _, l := range h {
		if strings.EqualFold(l[0], name) {
			return l[1], true
		}
	}
	return "", false
}

// names returns the header names in wire order, lowercased.
func (h trustHead) names() []string {
	out := make([]string, len(h))
	for i, l := range h {
		out[i] = strings.ToLower(l[0])
	}
	return out
}

// secMetadata returns the sec-fetch-* and sec-ch-* lines, as sent.
func (h trustHead) secMetadata() []string {
	var out []string
	for _, l := range h {
		if isSecMetadataName(l[0]) {
			out = append(out, l[0]+": "+l[1])
		}
	}
	return out
}

// trustCapture is a plain HTTP/1.1 server that keeps every request head by
// request path and answers each request with an empty 200.
type trustCapture struct {
	port string

	mu    sync.Mutex
	heads map[string]trustHead
}

func startTrustCapture(t *testing.T) *trustCapture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	c := &trustCapture{port: port, heads: map[string]trustHead{}}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go c.serve(conn)
		}
	}()
	return c
}

func (c *trustCapture) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return
		}
		var head trustHead
		length := 0
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			l = strings.TrimRight(l, "\r\n")
			if l == "" {
				break
			}
			k, v, _ := strings.Cut(l, ":")
			v = strings.TrimSpace(v)
			head = append(head, [2]string{k, v})
			if strings.EqualFold(k, "Content-Length") {
				length, _ = strconv.Atoi(v)
			}
		}
		if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
			return
		}
		c.mu.Lock()
		c.heads[f[1]] = head
		c.mu.Unlock()
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	}
}

// send makes req through Do, or through DoStream when stream is set.
func (c *trustCapture) send(t *testing.T, tr *Transport, stream bool, req *Request) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if stream {
		resp, err := tr.DoStream(ctx, req)
		if err != nil {
			t.Fatalf("DoStream %s %s: %v", req.Method, req.URL, err)
		}
		io.Copy(io.Discard, resp)
		resp.Close()
		return
	}
	resp, err := tr.Do(ctx, req)
	if err != nil {
		t.Fatalf("Do %s %s: %v", req.Method, req.URL, err)
	}
	resp.Close()
}

func (c *trustCapture) head(t *testing.T, path string) trustHead {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	h, ok := c.heads[path]
	if !ok {
		t.Fatalf("no request reached %s", path)
	}
	return h
}
