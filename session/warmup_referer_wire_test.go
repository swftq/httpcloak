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

// Warmup sends each subresource the Referer a browser sends from the page
// under the default referrer policy, strict-origin-when-cross-origin. It used
// to send the full page URL, fragment included, to every subresource on every
// origin.
//
// The expected values are Chrome 156's and Firefox 159's for a stylesheet, a
// preloaded font, a script and an image, each linked from
// https://a.test:PORT/page?q=1#frag and from http://a.test:PORT/ppage?q=2#frag:
// the page URL minus its fragment on the page's own origin, and the page's
// origin with a trailing slash on any other, same-site or not. WebKit's
// SecurityPolicy::generateReferrerHeader gives the same under its default, so
// one rule covers every preset. Neither browser sends an https page's http
// load (an image goes upgraded to https), so the missing Referer there is the
// policy's answer rather than a capture; warmup still sends the load.

// warmupRefererServer serves warmup's pages over https and http and records
// each subresource's Referer fields by path. Every name maps to 127.0.0.1.
type warmupRefererServer struct {
	tlsPort, plainPort string

	mu    sync.Mutex
	pages map[string]string   // path -> HTML
	seen  map[string][]string // path -> every Referer field; nil when none
	proto map[string]string   // path -> protocol
}

var warmupRefererNames = []string{"a.test", "sub.a.test", "b.test"}

func newWarmupRefererServer(t *testing.T) *warmupRefererServer {
	t.Helper()
	s := &warmupRefererServer{pages: map[string]string{}, seen: map[string][]string{}, proto: map[string]string{}}
	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	tlsSrv.EnableHTTP2 = true
	tlsSrv.StartTLS()
	t.Cleanup(tlsSrv.Close)
	plainSrv := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(plainSrv.Close)
	s.tlsPort = strconv.Itoa(tlsSrv.Listener.Addr().(*net.TCPAddr).Port)
	s.plainPort = strconv.Itoa(plainSrv.Listener.Addr().(*net.TCPAddr).Port)
	return s
}

func (s *warmupRefererServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	html, isPage := s.pages[r.URL.Path]
	if !isPage {
		s.seen[r.URL.Path] = r.Header.Values("Referer")
		s.proto[r.URL.Path] = r.Proto
	}
	s.mu.Unlock()
	if isPage {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, html)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// warmupRefererKinds is each kind of subresource warmup fetches, as a page
// links it.
var warmupRefererKinds = []struct{ ext, tag string }{
	{"css", `<link rel="stylesheet" href="%s">`},
	{"woff2", `<link rel="preload" href="%s" as="font" crossorigin>`},
	{"js", `<script src="%s"></script>`},
	{"png", `<img src="%s">`},
}

// warmupRefererSub is one origin a page loads subresources from: "" for the
// page's own, linked by path. want is the Referer each should carry, "" for
// none.
type warmupRefererSub struct {
	label, base, want string
}

// warmupRefererLoad is one subresource the server should see.
type warmupRefererLoad struct {
	url, path, want string
	https           bool
}

// load registers a page at pageOrigin+prefix+"/"+name that links every kind
// from each of subs, and returns what each load should carry.
func (s *warmupRefererServer) load(pageOrigin, prefix, name string, subs []warmupRefererSub) []warmupRefererLoad {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html><head>")
	var loads []warmupRefererLoad
	for _, sub := range subs {
		origin := sub.base
		if origin == "" {
			origin = pageOrigin
		}
		for _, k := range warmupRefererKinds {
			path := fmt.Sprintf("%s/%s.%s", prefix, sub.label, k.ext)
			fmt.Fprintf(&b, k.tag, sub.base+path)
			loads = append(loads, warmupRefererLoad{
				url:   origin + path,
				path:  path,
				want:  sub.want,
				https: strings.HasPrefix(origin, "https://"),
			})
		}
	}
	b.WriteString("</head><body></body></html>")
	s.mu.Lock()
	s.pages[prefix+"/"+name] = b.String()
	s.mu.Unlock()
	return loads
}

func TestWarmupRefererFollowsTheDefaultPolicy(t *testing.T) {
	s := newWarmupRefererServer(t)
	tlsAt := func(host string) string { return "https://" + host + ":" + s.tlsPort }
	plainAt := func(host string) string { return "http://" + host + ":" + s.plainPort }

	for _, preset := range []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"} {
		for _, forceHTTP1 := range []bool{false, true} {
			wantProto := "HTTP/2.0"
			if forceHTTP1 {
				wantProto = "HTTP/1.1"
			}
			t.Run(preset+"/"+wantProto, func(t *testing.T) {
				connectTo := map[string]string{}
				for _, name := range warmupRefererNames {
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

				prefix := "/" + preset + "/" + wantProto
				httpsPage := tlsAt("a.test") + prefix + "/page"
				httpPage := plainAt("a.test") + prefix + "/ppage"
				pages := []struct {
					url   string
					loads []warmupRefererLoad
				}{
					{httpsPage + "?q=1#frag", s.load(tlsAt("a.test"), prefix, "page", []warmupRefererSub{
						{"same-origin", "", httpsPage + "?q=1"},
						{"same-site", tlsAt("sub.a.test"), tlsAt("a.test") + "/"},
						{"cross-site", tlsAt("b.test"), tlsAt("a.test") + "/"},
						{"http", plainAt("a.test"), ""},
					})},
					{httpPage + "?q=2#frag", s.load(plainAt("a.test"), prefix, "ppage", []warmupRefererSub{
						{"p-same-origin", "", httpPage + "?q=2"},
						{"p-same-site", plainAt("sub.a.test"), plainAt("a.test") + "/"},
						{"p-cross-site", plainAt("b.test"), plainAt("a.test") + "/"},
						{"p-https", tlsAt("a.test"), plainAt("a.test") + "/"},
					})},
				}

				for _, p := range pages {
					if err := sess.Warmup(context.Background(), p.url); err != nil {
						t.Fatalf("%s: %v", p.url, err)
					}
					for _, l := range p.loads {
						s.mu.Lock()
						got, sent := s.seen[l.path]
						proto := s.proto[l.path]
						s.mu.Unlock()
						if !sent {
							t.Errorf("%s from page %s was never requested", l.url, p.url)
							continue
						}
						// Plain http has no HTTP/2 here, so only https loads
						// follow the forced protocol.
						want := "HTTP/1.1"
						if l.https {
							want = wantProto
						}
						if proto != want {
							t.Fatalf("%s: server saw %s, want %s", l.url, proto, want)
						}
						if l.want == "" {
							if len(got) != 0 {
								t.Errorf("%s from page %s sent Referer %q, want none", l.url, p.url, got)
							}
							continue
						}
						if len(got) != 1 || got[0] != l.want {
							t.Errorf("%s from page %s sent Referer %q, want %q", l.url, p.url, got, l.want)
						}
					}
				}
			})
		}
	}
}
