package session

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/engine"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// WebKit adds Upgrade-Insecure-Requests: 1 to the load of a document or an
// iframe whose URL is not https, and to nothing else
// (CachedResourceLoader::requestResource). Safari 26.3 sent it on all 6 of its
// plain-HTTP document and iframe navigations, to localhost and to a LAN
// address alike, and on none of its 20 https ones. Its presets were captured
// over https and leave it out of their header set, so the session sent it on
// none. Chrome 156 and Firefox 159 sent it on every navigation, and their
// presets carry it in theirs, firefox-133's aside.
//
// The hosts and the ConnectTo map are TestSessionPlainHTTPAcceptEncoding's: a
// LAN name and a LAN address, and three loopback hosts. So is the plain-HTTP
// capture, encodingCapture.

// uirShape is one request shape each preset sends.
type uirShape struct {
	name    string
	method  string
	headers []string // name, value, name, value, ...
	body    string

	// navigation: the request stays a navigation, so Chrome and Firefox send
	// whatever their header set carries.
	navigation bool
	// webkit: WebKit sends the header on it over plain HTTP.
	webkit bool
}

var uirShapes = []uirShape{
	{name: "navigation", method: "GET", navigation: true, webkit: true},
	{name: "iframe-navigation", method: "GET", headers: []string{"Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "iframe"}, navigation: true, webkit: true},
	{name: "embed-navigation", method: "GET", headers: []string{"Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "embed"}, navigation: true},
	{name: "json-post", method: "POST", headers: []string{"Content-Type", "application/json"}, body: "{}"},
	{name: "no-cors-image", method: "GET", headers: []string{"Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Dest", "image"}},
}

// request builds the shape's request to url, with a Headers map of its own.
func (u uirShape) request(url string) *transport.Request {
	req := &transport.Request{Method: u.method, URL: url, Headers: map[string][]string{}}
	for i := 0; i+1 < len(u.headers); i += 2 {
		req.Headers[u.headers[i]] = []string{u.headers[i+1]}
	}
	if u.body != "" {
		req.Body = []byte(u.body)
	}
	return req
}

// uirInHeaderSet reports whether the preset's own header set carries the
// header, which is what the session sends on a navigation.
func uirInHeaderSet(p *fingerprint.Preset) bool {
	return slices.ContainsFunc(p.HeaderOrder, func(h fingerprint.HeaderPair) bool {
		return strings.EqualFold(h.Key, "upgrade-insecure-requests")
	})
}

// uirWanted reports whether the preset sends the header on the shape over
// plain HTTP: WebKit by its own rule, Chrome and Firefox when the request
// stays a navigation and their header set carries it.
func uirWanted(p *fingerprint.Preset, shape uirShape) bool {
	if engine.Of(p.UserAgent) == engine.WebKit {
		return shape.webkit
	}
	return shape.navigation && uirInHeaderSet(p)
}

// uirOne is the one line WebKit sends, spelled as Safari spelled it.
var uirOne = [][2]string{{"Upgrade-Insecure-Requests", "1"}}

// uirLines returns the Upgrade-Insecure-Requests lines of req, in any
// spelling.
func uirLines(req *capturedRequest) [][2]string {
	var lines [][2]string
	for _, l := range req.lines {
		if strings.EqualFold(l[0], "Upgrade-Insecure-Requests") {
			lines = append(lines, l)
		}
	}
	return lines
}

// checkUIR fails the test, naming the request what, unless it arrived with
// exactly uirOne when want and with no Upgrade-Insecure-Requests line when
// not.
func checkUIR(t *testing.T, what string, req *capturedRequest, want bool) {
	t.Helper()
	switch {
	case req == nil:
		t.Errorf("%s: no request arrived", what)
	case want && !slices.Equal(uirLines(req), uirOne):
		t.Errorf("%s: %q, want %q", what, uirLines(req), uirOne)
	case !want && len(uirLines(req)) > 0:
		t.Errorf("%s: %q, want none", what, uirLines(req))
	}
}

func TestSessionUpgradeInsecureRequestsOverPlainHTTP(t *testing.T) {
	srv := startEncodingCapture(t)
	names := fingerprint.Available()
	slices.Sort(names)
	var webkit int
	for _, name := range names {
		p := fingerprint.Get(name)
		if engine.Of(p.UserAgent) == engine.WebKit {
			webkit++
		}
		s := NewSession("", &protocol.SessionConfig{Preset: name, ConnectTo: plainEncodingConnectTo})
		for i, h := range plainEncodingHosts {
			for _, shape := range uirShapes {
				path := "/uir/" + name + "/" + strconv.Itoa(i) + "/" + shape.name
				sendAndClose(t, s, shape.request("http://"+h.host+":"+srv.port+path))
				checkUIR(t, name+" "+shape.name+" to http://"+h.host, srv.request(path), uirWanted(p, shape))
			}
		}
		s.Close()
	}
	if webkit == 0 {
		t.Fatal("no built-in preset is WebKit; the test checks nothing")
	}
}

// RequestStream builds its request on a path of its own, so the header is
// checked there as well: every shape on every WebKit name, and on
// chrome-latest, whose header set carries it. One plain-HTTP host is enough,
// as the rule reads only the scheme; RequestStream follows no redirect.
func TestSessionUpgradeInsecureRequestsStream(t *testing.T) {
	srv := startEncodingCapture(t)
	names := []string{"chrome-latest"}
	all := fingerprint.Available()
	slices.Sort(all)
	for _, name := range all {
		if engine.Of(fingerprint.Get(name).UserAgent) == engine.WebKit {
			names = append(names, name)
		}
	}
	if len(names) == 1 {
		t.Fatal("no built-in preset is WebKit; the test checks nothing")
	}
	for _, name := range names {
		p := fingerprint.Get(name)
		s := NewSession("", &protocol.SessionConfig{Preset: name, ConnectTo: plainEncodingConnectTo})
		for _, shape := range uirShapes {
			path := "/uir-stream/" + name + "/" + shape.name
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := s.RequestStream(ctx, shape.request("http://lan-origin.test:"+srv.port+path))
			if err != nil {
				cancel()
				t.Fatalf("%s %s RequestStream: %v", name, shape.name, err)
			}
			io.Copy(io.Discard, resp)
			resp.Close()
			cancel()
			checkUIR(t, name+" "+shape.name+" through RequestStream", srv.request(path), uirWanted(p, shape))
		}
		s.Close()
	}
}

// The rule is WebKit's for URLs that are not https, so over https the WebKit
// presets still send none, on HTTP/2 and on HTTP/1.1, while Chrome's and
// Firefox's still send theirs.
func TestSessionUpgradeInsecureRequestsNotOverHTTPS(t *testing.T) {
	origin := startUIRTLSOrigin(t)
	names := fingerprint.Available()
	slices.Sort(names)
	for _, name := range names {
		p := fingerprint.Get(name)
		isWebKit := engine.Of(p.UserAgent) == engine.WebKit
		if !isWebKit && name != "chrome-latest" && name != "firefox-latest" {
			continue
		}
		for _, forceHTTP1 := range []bool{false, true} {
			s := NewSession("", &protocol.SessionConfig{
				Preset:             name,
				InsecureSkipVerify: true, // httptest's certificate
				DisableHTTP3:       true, // the origin speaks TCP only
				ForceHTTP1:         forceHTTP1,
			})
			for _, shape := range uirShapes[:2] {
				path := "/uir-tls/" + name + "/" + strconv.FormatBool(forceHTTP1) + "/" + shape.name
				sendAndClose(t, s, shape.request(origin.base+path))
				hit, ok := origin.hit(path)
				switch {
				case !ok:
					t.Errorf("%s %s over https: no request arrived", name, shape.name)
				case isWebKit && len(hit.uir) > 0:
					t.Errorf("%s %s over %s: %q; WebKit sends it only to a URL that is not https", name, shape.name, hit.proto, hit.uir)
				case !isWebKit && !slices.Equal(hit.uir, []string{"1"}):
					t.Errorf("%s %s over %s: %q, want 1", name, shape.name, hit.proto, hit.uir)
				}
			}
			s.Close()
		}
	}
}

// Every redirect hop is a request of its own and goes by its own URL: a WebKit
// preset sends the header on each plain-HTTP hop and on no https one, and
// Chrome and Firefox send it on every hop. WebKit's own source suggests the
// first request's header rides along the chain instead
// (ResourceRequestBase::redirectedRequest copies every field); no Safari
// capture has a redirected navigation yet.
func TestSessionUpgradeInsecureRequestsPerRedirectHop(t *testing.T) {
	plain := startEncodingCapture(t)
	origin := startUIRTLSOrigin(t)
	plainBase := "http://lan-origin.test:" + plain.port
	for _, name := range []string{"safari-latest", "chrome-latest", "firefox-latest"} {
		isWebKit := engine.Of(fingerprint.Get(name).UserAgent) == engine.WebKit
		s := NewSession("", &protocol.SessionConfig{
			Preset:             name,
			ConnectTo:          plainEncodingConnectTo,
			FollowRedirects:    true,
			InsecureSkipVerify: true,
			DisableHTTP3:       true,
		})
		up, down := "/uir-hop/"+name+"/up", "/uir-hop/"+name+"/down"
		plain.respond(up, cannedReply{status: "302 Found", header: []string{"Location: " + origin.base + up + "-end"}})
		origin.redirect(down, plainBase+down+"-end")
		sendAndClose(t, s, &transport.Request{Method: "GET", URL: plainBase + up})
		sendAndClose(t, s, &transport.Request{Method: "GET", URL: origin.base + down})
		s.Close()

		for _, hop := range []string{up, down + "-end"} {
			checkUIR(t, name+" http://lan-origin.test"+hop, plain.request(hop), true)
		}
		for _, hop := range []string{up + "-end", down} {
			want := []string{"1"}
			if isWebKit {
				want = nil
			}
			hit, ok := origin.hit(hop)
			if !ok {
				t.Errorf("%s: no https request to %s", name, hop)
			} else if !slices.Equal(hit.uir, want) {
				t.Errorf("%s https %s: %q, want %q", name, hop, hit.uir, want)
			}
		}
	}
}

// A caller's own Upgrade-Insecure-Requests goes out as they set it, once,
// over plain HTTP and over https.
func TestSessionUpgradeInsecureRequestsCallerValue(t *testing.T) {
	plain := startEncodingCapture(t)
	origin := startUIRTLSOrigin(t)
	s := NewSession("", &protocol.SessionConfig{
		Preset:             "safari-latest",
		ConnectTo:          plainEncodingConnectTo,
		InsecureSkipVerify: true,
		DisableHTTP3:       true,
	})
	defer s.Close()

	for path, header := range map[string][]string{
		"/uir-caller/canonical": {"Upgrade-Insecure-Requests", "0"},
		"/uir-caller/lowercase": {"upgrade-insecure-requests", "1"},
		"/uir-caller/empty":     {"Upgrade-Insecure-Requests", ""},
	} {
		sendAndClose(t, s, &transport.Request{Method: "GET", URL: "http://lan-origin.test:" + plain.port + path,
			Headers: map[string][]string{header[0]: {header[1]}}})
		want := [][2]string{{"Upgrade-Insecure-Requests", header[1]}}
		if req := plain.request(path); req == nil {
			t.Errorf("caller's %s %q: no request arrived", header[0], header[1])
		} else if got := uirLines(req); !slices.Equal(got, want) {
			t.Errorf("caller's %s %q: %q on the wire, want %q", header[0], header[1], got, want)
		}
	}

	sendAndClose(t, s, &transport.Request{Method: "GET", URL: origin.base + "/uir-caller/https",
		Headers: map[string][]string{"Upgrade-Insecure-Requests": {"1"}}})
	if hit, _ := origin.hit("/uir-caller/https"); !slices.Equal(hit.uir, []string{"1"}) {
		t.Errorf("caller's header over https: %q, want 1", hit.uir)
	}
}

// Exact headers and TLS-only requests carry what the caller composed and
// nothing more, so neither gains the header, even on a navigation.
func TestSessionUpgradeInsecureRequestsSkipsExactAndTLSOnly(t *testing.T) {
	srv := startEncodingCapture(t)
	s := NewSession("", &protocol.SessionConfig{Preset: "safari-latest", ConnectTo: plainEncodingConnectTo})
	defer s.Close()
	base := "http://lan-origin.test:" + srv.port
	tlsOnly := true

	sendAndClose(t, s, &transport.Request{Method: "GET", URL: base + "/uir-tls-only", TLSOnly: &tlsOnly})
	sendAndClose(t, s, &transport.Request{Method: "GET", URL: base + "/uir-exact", ExactHeaders: []fingerprint.HeaderPair{
		{Key: "User-Agent", Value: fingerprint.Get("safari-latest").UserAgent},
		{Key: "Sec-Fetch-Mode", Value: "navigate"},
		{Key: "Sec-Fetch-Dest", Value: "document"},
	}})
	sendAndClose(t, s, &transport.Request{Method: "GET", URL: base + "/uir-default"})

	for path, want := range map[string]bool{
		"/uir-tls-only": false,
		"/uir-exact":    false,
		"/uir-default":  true,
	} {
		checkUIR(t, path, srv.request(path), want)
	}
}

// The header goes in before the order is chosen, so the order places it like
// any other. On a navigation that carries only its own headers it goes right
// after User-Agent, where Safari 26.3 sent it (run-20261031-234946 h1.log:2-14,
// and 7450-7459 to a LAN address). The built-in WebKit 26 presets get there
// through the cfnetwork model, which lays the request out with the header among
// its names; TestSessionWebKit26PlainHTTPLayout checks the frame's navigation
// with a Referer as well. Their table has a slot right after user-agent too,
// which a custom preset on safari-18 with that table, on the list model,
// checks. The pre-26 WebKit tables have none, so it joins the sorted tail of
// headers they leave out, ahead of a caller's X-Probe; added after the order,
// it would come after every ordered header. Where Safari 17 and 18 put it was
// not captured.
func TestSessionUpgradeInsecureRequestsInTheHeaderOrder(t *testing.T) {
	const custom = "uir-webkit-26-table"
	spec := `{"version":1,"preset":{"name":"` + custom + `","based_on":"safari-18","http2":{"hpack_header_order":[` +
		`"sec-fetch-dest","user-agent","upgrade-insecure-requests","accept","referer","sec-fetch-site",` +
		`"sec-fetch-mode","accept-language","priority","accept-encoding","cookie","content-type",` +
		`"content-length","origin"]}}}`
	p, err := fingerprint.LoadAndBuildPresetFromJSON([]byte(spec))
	if err != nil {
		t.Fatalf("load %s: %v", custom, err)
	}
	if err := fingerprint.RegisterStrict(custom, p); err != nil {
		t.Fatalf("register %s: %v", custom, err)
	}
	t.Cleanup(func() { fingerprint.Unregister(custom) })

	presets := []string{custom}
	names := fingerprint.Available()
	slices.Sort(names)
	for _, name := range names {
		p := fingerprint.Get(name)
		if engine.Of(p.UserAgent) == engine.WebKit && slices.Contains(p.H2HeaderOrder(), "upgrade-insecure-requests") {
			presets = append(presets, name)
		}
	}

	srv := startEncodingCapture(t)
	for _, name := range presets {
		s := NewSession("", &protocol.SessionConfig{Preset: name, ConnectTo: plainEncodingConnectTo})
		for _, host := range []string{"localhost", "lan-origin.test"} {
			path := "/uir-slot/" + name + "/" + host
			sendAndClose(t, s, &transport.Request{Method: "GET", URL: "http://" + host + ":" + srv.port + path})
			req := srv.request(path)
			if req == nil {
				t.Errorf("%s to http://%s: no request arrived", name, host)
				continue
			}
			i := slices.Index(req.names(), "user-agent")
			if i < 0 || i+1 >= len(req.lines) || req.lines[i+1] != uirOne[0] {
				t.Errorf("%s to http://%s: %q, want %q right after User-Agent", name, host, req.lines, uirOne[0])
			}
		}
		s.Close()
	}

	if slices.Contains(fingerprint.Get("safari-18").H2HeaderOrder(), "upgrade-insecure-requests") {
		t.Fatal("safari-18's table has a slot for the header; the sorted-tail case needs a preset without one")
	}
	s := NewSession("", &protocol.SessionConfig{Preset: "safari-18", ConnectTo: plainEncodingConnectTo})
	defer s.Close()
	path := "/uir-tail/safari-18"
	sendAndClose(t, s, &transport.Request{Method: "GET", URL: "http://lan-origin.test:" + srv.port + path,
		Headers: map[string][]string{"X-Probe": {"1"}}})
	req := srv.request(path)
	if req == nil {
		t.Fatal("safari-18 to http://lan-origin.test: no request arrived")
	}
	if u, x := slices.Index(req.lines, uirOne[0]), slices.Index(req.lines, [2]string{"X-Probe", "1"}); u < 0 || x < 0 || u > x {
		t.Errorf("safari-18: %q, want %q in the sorted tail, ahead of X-Probe", req.lines, uirOne[0])
	}
}

// uirTLSOrigin is an https origin speaking HTTP/2 and HTTP/1.1 that keeps the
// Upgrade-Insecure-Requests values of each request by path, and answers 302
// for the paths a test registered with redirect.
type uirTLSOrigin struct {
	base string

	mu        sync.Mutex
	hits      map[string]uirTLSHit
	redirects map[string]string
}

type uirTLSHit struct {
	proto string
	uir   []string
}

func startUIRTLSOrigin(t *testing.T) *uirTLSOrigin {
	t.Helper()
	o := &uirTLSOrigin{hits: map[string]uirTLSHit{}, redirects: map[string]string{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(o.serve))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	o.base = "https://" + srv.Listener.Addr().String()
	return o
}

func (o *uirTLSOrigin) serve(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	o.mu.Lock()
	o.hits[r.URL.Path] = uirTLSHit{proto: r.Proto, uir: r.Header.Values("Upgrade-Insecure-Requests")}
	location := o.redirects[r.URL.Path]
	o.mu.Unlock()
	if location != "" {
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusFound)
		return
	}
	io.WriteString(w, "ok")
}

func (o *uirTLSOrigin) redirect(path, location string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.redirects[path] = location
}

func (o *uirTLSOrigin) hit(path string) (uirTLSHit, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	h, ok := o.hits[path]
	return h, ok
}
