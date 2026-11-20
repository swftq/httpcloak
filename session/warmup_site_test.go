package session

import (
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

	"github.com/sardanioss/httpcloak/protocol"
)

// Warmup sends each subresource with the Sec-Fetch-Site that
// fingerprint.calculateFetchSite works out from the page. It used to take a
// host's last two labels for its registrable domain. So every .co.uk site was
// same-site with every other, and so were a.github.io and b.github.io, and
// IPv4 addresses that end in the same two octets. Host case also counted in
// the same-origin check, where a browser's URL parser drops it.
//
// The expected values are Chromium 156's: url::Origin first, then
// SchemefulSite, whose registrable domain comes from the public suffix list
// with private suffixes included, falling back to the host for an IP address,
// localhost or a public suffix. Gecko 159 agrees on each case. Every
// subresource here is a stylesheet, which warmup fetches without a delay;
// every subresource type takes its Sec-Fetch-Site from the same function.

// warmupSitePage is a page warmup loads and the origins of the stylesheets
// it links.
type warmupSitePage struct {
	page string
	subs []warmupSiteSub
}

type warmupSiteSub struct {
	origin, want string
}

// warmupSiteServer serves the pages and records each stylesheet's
// Sec-Fetch-Site by path. Two listeners give an origin a second port.
type warmupSiteServer struct {
	port, port2 string

	mu    sync.Mutex
	pages map[string]string   // path -> HTML
	seen  map[string][]string // path -> every Sec-Fetch-Site field
	proto map[string]string   // path -> protocol
}

var warmupSiteNames = []string{
	"www.example.co.uk", "other.co.uk", "a.example.co.uk", "co.uk",
	"a.github.io", "b.github.io", "github.io", "www.cnn.com", "edition.cnn.com",
	"192.168.0.1", "10.0.0.1", "a.test", "sub.a.test", "b.test",
	"www.example.com", "WWW.EXAMPLE.COM", "www.example.com.", "api.example.com.",
}

func newWarmupSiteServer(t *testing.T) *warmupSiteServer {
	t.Helper()
	s := &warmupSiteServer{pages: map[string]string{}, seen: map[string][]string{}, proto: map[string]string{}}
	start := func() string {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
		srv.EnableHTTP2 = true
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
	}
	s.port, s.port2 = start(), start()
	return s
}

func (s *warmupSiteServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	html, isPage := s.pages[r.URL.Path]
	if !isPage {
		s.seen[r.URL.Path] = r.Header.Values("Sec-Fetch-Site")
		s.proto[r.URL.Path] = r.Proto
	}
	s.mu.Unlock()
	if isPage {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, html)
		return
	}
	w.Header().Set("Content-Type", "text/css")
	io.WriteString(w, "body{}")
}

// at returns https://host:port, the first listener under host.
func (s *warmupSiteServer) at(host string) string {
	return "https://" + host + ":" + s.port
}

// load registers a page at prefix that links each of p.subs under a path of
// its own, and returns the page's URL and those paths, in p.subs's order.
func (s *warmupSiteServer) load(prefix string, p warmupSitePage) (string, []string) {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html><head>")
	paths := make([]string, len(p.subs))
	for i, sub := range p.subs {
		paths[i] = fmt.Sprintf("%s/%d.css", prefix, i)
		fmt.Fprintf(&b, `<link rel="stylesheet" href="%s%s">`, sub.origin, paths[i])
	}
	b.WriteString("</head><body></body></html>")
	s.mu.Lock()
	s.pages[prefix] = b.String()
	s.mu.Unlock()
	return p.page + prefix, paths
}

func TestWarmupSecFetchSiteUsesRegistrableDomain(t *testing.T) {
	s := newWarmupSiteServer(t)
	pages := []warmupSitePage{
		// A suffix the list has: example.co.uk is a site, co.uk is not.
		{s.at("www.example.co.uk"), []warmupSiteSub{
			{s.at("other.co.uk"), "cross-site"},
			{s.at("co.uk"), "cross-site"},
			{s.at("a.example.co.uk"), "same-site"},
		}},
		// A private suffix: every github.io user is a site of its own.
		{s.at("a.github.io"), []warmupSiteSub{
			{s.at("b.github.io"), "cross-site"},
			{s.at("github.io"), "cross-site"},
		}},
		{s.at("www.cnn.com"), []warmupSiteSub{
			{s.at("edition.cnn.com"), "same-site"},
		}},
		// An IP address is a site of its own; the port never matters to a site.
		{s.at("192.168.0.1"), []warmupSiteSub{
			{s.at("10.0.0.1"), "cross-site"},
			{"https://192.168.0.1:" + s.port2, "same-site"},
		}},
		// A TLD the list does not know takes its last label for the suffix.
		{s.at("a.test"), []warmupSiteSub{
			{s.at("sub.a.test"), "same-site"},
			{s.at("b.test"), "cross-site"},
		}},
		{s.at("localhost"), []warmupSiteSub{
			{"https://localhost:" + s.port2, "same-site"},
			{s.at("127.0.0.1"), "cross-site"},
		}},
		// A URL parser lowercases the host.
		{s.at("www.example.com"), []warmupSiteSub{
			{s.at("WWW.EXAMPLE.COM"), "same-origin"},
		}},
		// One trailing dot is looked past for the lookup and kept in the site.
		{s.at("www.example.com."), []warmupSiteSub{
			{s.at("api.example.com."), "same-site"},
		}},
	}

	for _, preset := range []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"} {
		for _, forceHTTP1 := range []bool{false, true} {
			wantProto := "HTTP/2.0"
			if forceHTTP1 {
				wantProto = "HTTP/1.1"
			}
			t.Run(preset+"/"+wantProto, func(t *testing.T) {
				connectTo := map[string]string{}
				for _, name := range warmupSiteNames {
					connectTo[name] = "127.0.0.1"
				}
				sess := NewSession("", &protocol.SessionConfig{
					Preset:             preset,
					InsecureSkipVerify: true, // httptest's certificate
					DisableHTTP3:       true, // the test server speaks TCP only
					ForceHTTP1:         forceHTTP1,
					ForceHTTP2:         !forceHTTP1,
					ConnectTo:          connectTo,
				})
				defer sess.Close()

				for i, p := range pages {
					prefix := fmt.Sprintf("/%s/%s/%d", preset, wantProto, i)
					page, paths := s.load(prefix, p)
					if err := sess.Warmup(context.Background(), page); err != nil {
						t.Fatalf("%s: %v", page, err)
					}
					for j, sub := range p.subs {
						s.mu.Lock()
						got, proto := s.seen[paths[j]], s.proto[paths[j]]
						s.mu.Unlock()
						if proto != wantProto {
							t.Fatalf("%s%s: server saw %q, want %s", sub.origin, paths[j], proto, wantProto)
						}
						if len(got) != 1 || got[0] != sub.want {
							t.Errorf("%s from page %s sent Sec-Fetch-Site %q, want %q", sub.origin, page, got, sub.want)
						}
					}
				}
			})
		}
	}
}
