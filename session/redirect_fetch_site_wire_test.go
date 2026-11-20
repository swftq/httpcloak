package session

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// The chains here are the ones captured from Chrome 156 and Firefox 159 on
// 2026-10-28, moving between a.test, sub.a.test, b.test, a second port on
// a.test and plain-HTTP a.test, all resolved to 127.0.0.1. The two browsers
// sent the same Sec-Fetch-Site on every one of the 100 requests captured. Each
// test asserts what they sent, as the receiving server saw it. The session
// reaches the same names through ConnectTo; names are the only way to get a
// cross-site hop, because two ports on one host are one site.

var fetchSiteNames = []string{"a.test", "sub.a.test", "b.test"}

// fetchSiteOrigins serves every origin a chain visits. A path
// /h/<label>/<k1>/<k2>/... answers with a 302 to origin k1 at
// /h/<label>/<k2>/..., and a path with no keys left is where the chain lands.
type fetchSiteOrigins struct {
	bases map[string]string // origin key -> scheme://host:port
	keyOf map[string]string // host:port -> origin key

	mu   sync.Mutex
	hits []fetchSiteHit
}

type fetchSiteHit struct {
	key, label, proto string
	site              []string // every Sec-Fetch-Site field, as received
}

// newFetchSiteOrigins starts the origins of the capture:
//
//	M  https://a.test      the page that started each request
//	S  https://sub.a.test  same site, another host
//	X  https://b.test      another site
//	P  https://a.test      same host, another port
//	D  http://a.test       plain HTTP
func newFetchSiteOrigins(t *testing.T) *fetchSiteOrigins {
	t.Helper()
	o := &fetchSiteOrigins{bases: map[string]string{}, keyOf: map[string]string{}}
	start := func(secure bool) int {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(o.serve))
		if secure {
			srv.EnableHTTP2 = true
			srv.StartTLS()
		} else {
			srv.Start()
		}
		t.Cleanup(srv.Close)
		return srv.Listener.Addr().(*net.TCPAddr).Port
	}
	main, other, plain := start(true), start(true), start(false)
	o.add("M", "https", "a.test", main)
	o.add("S", "https", "sub.a.test", main)
	o.add("X", "https", "b.test", main)
	o.add("P", "https", "a.test", other)
	o.add("D", "http", "a.test", plain)
	return o
}

func (o *fetchSiteOrigins) add(key, scheme, host string, port int) {
	hostport := net.JoinHostPort(host, strconv.Itoa(port))
	o.bases[key] = scheme + "://" + hostport
	o.keyOf[hostport] = key
}

func (o *fetchSiteOrigins) serve(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	rest, ok := strings.CutPrefix(r.URL.Path, "/h/")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	label, keys, _ := strings.Cut(rest, "/")
	o.mu.Lock()
	o.hits = append(o.hits, fetchSiteHit{
		key: o.keyOf[r.Host], label: label, proto: r.Proto, site: r.Header.Values("Sec-Fetch-Site"),
	})
	o.mu.Unlock()
	if keys == "" {
		io.WriteString(w, "ok")
		return
	}
	next, after, _ := strings.Cut(keys, "/")
	location := o.bases[next] + "/h/" + label
	if after != "" {
		location += "/" + after
	}
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// url is where a chain through the given origins starts.
func (o *fetchSiteOrigins) url(label string, chain ...string) string {
	return o.bases[chain[0]] + "/h/" + strings.Join(append([]string{label}, chain[1:]...), "/")
}

// hops returns the requests of one chain, in the order they arrived.
func (o *fetchSiteOrigins) hops(label string) []fetchSiteHit {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []fetchSiteHit
	for _, h := range o.hits {
		if h.label == label {
			out = append(out, h)
		}
	}
	return out
}

func newFetchSiteSession(t *testing.T, preset string, forceHTTP1 bool) *Session {
	t.Helper()
	connectTo := map[string]string{}
	for _, name := range fetchSiteNames {
		connectTo[name] = "127.0.0.1"
	}
	s := NewSession("", &protocol.SessionConfig{
		Preset:             preset,
		FollowRedirects:    true,
		InsecureSkipVerify: true, // httptest's certificate
		DisableHTTP3:       true, // the test origins speak TCP only
		ForceHTTP1:         forceHTTP1,
		ConnectTo:          connectTo,
	})
	t.Cleanup(func() { s.Close() })
	return s
}

// The rule lives in the session, but each preset builds its own header block
// and the sniffing that fills in a preset's default, so every browser family
// the library mimics runs the chains, over HTTP/2 and HTTP/1.1. WebKit was not
// captured. Its SubresourceLoader works the value out hop by hop the way the
// session does, for navigations and subresources alike.
var fetchSitePresets = []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"}

func TestRedirectHopSecFetchSite(t *testing.T) {
	fetch := func(site string) map[string][]string {
		return map[string][]string{
			"Sec-Fetch-Site": {site}, "Sec-Fetch-Mode": {"cors"}, "Sec-Fetch-Dest": {"empty"}, "Accept": {"*/*"},
		}
	}
	navigate := map[string][]string{
		"Sec-Fetch-Site": {"same-origin"}, "Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"document"},
	}
	cases := []struct {
		label   string
		chain   []string // the origin each request went to, in order
		headers map[string][]string
		want    []string // per request; "" is not checked
	}{
		// A typed navigation sends none on every hop, even through b.test.
		{"typed", []string{"M", "X", "S", "M"}, nil, []string{"none", "none", "none", "none"}},

		// fetch() from the page on M. The value only ever moves towards
		// cross-site, so a chain that comes back to M keeps what it reached.
		{"fetch-sub", []string{"M", "S"}, fetch("same-origin"), []string{"same-origin", "same-site"}},
		{"fetch-port", []string{"M", "P"}, fetch("same-origin"), []string{"same-origin", "same-site"}},
		{"fetch-xs", []string{"M", "X"}, fetch("same-origin"), []string{"same-origin", "cross-site"}},
		{"fetch-sub-back", []string{"M", "S", "M"}, fetch("same-origin"), []string{"same-origin", "same-site", "same-site"}},
		{"fetch-port-back", []string{"M", "P", "M"}, fetch("same-origin"), []string{"same-origin", "same-site", "same-site"}},
		{"fetch-xs-back", []string{"M", "X", "M"}, fetch("same-origin"), []string{"same-origin", "cross-site", "cross-site"}},
		{"fetch-sub-xs-back", []string{"M", "S", "X", "M"}, fetch("same-origin"),
			[]string{"same-origin", "same-site", "cross-site", "cross-site"}},

		// fetch() from the page on M whose first request already left M.
		{"fetch-first-sub-back", []string{"S", "M"}, fetch("same-site"), []string{"same-site", "same-site"}},
		{"fetch-first-xs-back", []string{"X", "M"}, fetch("cross-site"), []string{"cross-site", "cross-site"}},
		{"fetch-first-xs-same", []string{"X", "X"}, fetch("cross-site"), []string{"cross-site", "cross-site"}},

		// The caller spelled the name in lowercase. The hop still sends one
		// Sec-Fetch-Site, with the new value.
		{"fetch-xs-lowercase", []string{"M", "X"}, map[string][]string{
			"sec-fetch-site": {"same-origin"}, "sec-fetch-mode": {"cors"}, "sec-fetch-dest": {"empty"}, "accept": {"*/*"},
		}, []string{"same-origin", "cross-site"}},

		// Script navigations from the page.
		{"nav-xs-back", []string{"M", "X", "M"}, navigate, []string{"same-origin", "cross-site", "cross-site"}},
		{"nav-sub-back", []string{"M", "S", "M"}, navigate, []string{"same-origin", "same-site", "same-site"}},

		// Down to plain HTTP and back. Neither browser sent any Sec-Fetch-*
		// to http://a.test, which is not potentially trustworthy, while the
		// session still sends the header there, so that hop is not checked.
		// Back on https both sent cross-site: http and https are two sites.
		{"nav-down-up", []string{"M", "D", "M"}, navigate, []string{"same-origin", "", "cross-site"}},
	}

	for _, preset := range fetchSitePresets {
		for _, forceHTTP1 := range []bool{false, true} {
			wantProto := "HTTP/2.0"
			if forceHTTP1 {
				wantProto = "HTTP/1.1"
			}
			t.Run(preset+"/"+wantProto, func(t *testing.T) {
				o := newFetchSiteOrigins(t)
				s := newFetchSiteSession(t, preset, forceHTTP1)
				for _, c := range cases {
					if _, err := s.Request(context.Background(), &transport.Request{
						Method: "GET", URL: o.url(c.label, c.chain...), Headers: c.headers,
					}); err != nil {
						t.Fatalf("%s: %v", c.label, err)
					}
					hops := o.hops(c.label)
					if len(hops) != len(c.chain) {
						t.Errorf("%s: the origins saw %d requests, want %d", c.label, len(hops), len(c.chain))
						continue
					}
					for i, h := range hops {
						if h.key != c.chain[i] {
							t.Fatalf("%s: request %d reached %s, want %s", c.label, i, h.key, c.chain[i])
						}
						if len(h.site) > 1 {
							t.Errorf("%s: request %d carried %d Sec-Fetch-Site fields %q", c.label, i, len(h.site), h.site)
						}
						if c.want[i] == "" {
							continue
						}
						got := ""
						if len(h.site) > 0 {
							got = h.site[0]
						}
						if got != c.want[i] {
							t.Errorf("%s: request %d to %s sent Sec-Fetch-Site %q, want %q (chain %v, want %q)",
								c.label, i, h.key, got, c.want[i], c.chain, c.want)
						}
					}
				}
				if got := o.hops("fetch-xs-back")[1].proto; got != wantProto {
					t.Fatalf("the hops went out over %s, want %s", got, wantProto)
				}
			})
		}
	}
}

// rawFetchSiteOrigin answers plain HTTP/1.1 for every name on one port, with
// the same /h/ paths as fetchSiteOrigins, and records each request's header
// lines as written: the name's spelling and the order are part of what an
// exact header list promises.
type rawFetchSiteOrigin struct {
	bases map[string]string
	keyOf map[string]string

	mu   sync.Mutex
	hits []rawFetchSiteHit
}

type rawFetchSiteHit struct {
	key   string
	pairs []string // "Name: value" as written, without Host and Connection
}

func newRawFetchSiteOrigin(t *testing.T) *rawFetchSiteOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	o := &rawFetchSiteOrigin{bases: map[string]string{}, keyOf: map[string]string{}}
	for key, host := range map[string]string{"A": "a.test", "B": "b.test"} {
		o.bases[key] = "http://" + net.JoinHostPort(host, port)
		o.keyOf[net.JoinHostPort(host, port)] = key
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go o.serve(conn)
		}
	}()
	return o
}

func (o *rawFetchSiteOrigin) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}
	var host string
	var pairs []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, _ := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		switch {
		case strings.EqualFold(name, "Host"):
			host = value
		case strings.EqualFold(name, "Connection"):
		default:
			pairs = append(pairs, name+": "+value)
		}
	}
	o.mu.Lock()
	o.hits = append(o.hits, rawFetchSiteHit{key: o.keyOf[host], pairs: pairs})
	o.mu.Unlock()

	_, keys, _ := strings.Cut(strings.TrimPrefix(fields[1], "/h/"), "/")
	if keys == "" {
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		return
	}
	label, _, _ := strings.Cut(strings.TrimPrefix(fields[1], "/h/"), "/")
	next, after, _ := strings.Cut(keys, "/")
	location := o.bases[next] + "/h/" + label
	if after != "" {
		location += "/" + after
	}
	fmt.Fprintf(conn, "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", location)
}

// Under ExactHeaders the transport never reads the hop's Headers, so a
// Sec-Fetch-Site pair in the list went out verbatim on every hop. It now takes
// the hop's value in its own slot and spelling, and nothing else in the list
// moves.
func TestRedirectHopSecFetchSiteExactHeaders(t *testing.T) {
	o := newRawFetchSiteOrigin(t)
	s := newFetchSiteSession(t, "chrome-latest", true)

	exact := []fingerprint.HeaderPair{
		{Key: "user-agent", Value: "mirror/1"},
		{Key: "sec-fetch-site", Value: "same-origin"},
		{Key: "sec-fetch-mode", Value: "cors"},
		{Key: "accept", Value: "*/*"},
	}
	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: o.bases["A"] + "/h/exact/B/A", ExactHeaders: exact,
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	pairs := func(site string) []string {
		return []string{"user-agent: mirror/1", "sec-fetch-site: " + site, "sec-fetch-mode: cors", "accept: */*"}
	}
	want := []struct {
		key   string
		pairs []string
	}{
		{"A", pairs("same-origin")},
		{"B", pairs("cross-site")},
		{"A", pairs("cross-site")},
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.hits) != len(want) {
		t.Fatalf("the origin saw %d requests, want %d", len(o.hits), len(want))
	}
	for i, w := range want {
		h := o.hits[i]
		if h.key != w.key {
			t.Fatalf("request %d reached %s, want %s", i, h.key, w.key)
		}
		if strings.Join(h.pairs, "\n") != strings.Join(w.pairs, "\n") {
			t.Errorf("request %d to %s sent\n  %s\nwant\n  %s", i, h.key,
				strings.Join(h.pairs, "\n  "), strings.Join(w.pairs, "\n  "))
		}
	}
	if exact[1].Value != "same-origin" {
		t.Errorf("the caller's list now says %q; the hop must work on a copy", exact[1].Value)
	}
}
