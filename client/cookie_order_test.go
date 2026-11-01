package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The order of the cookies in a Cookie header follows the browser engine, for
// client.Client's jar as for the session's, whose test has the evidence
// (session/cookie_order_wire_test.go). Safari sends the most recently stored
// cookie first, and the cookies one response stored by name. Chrome 156 and
// Firefox 159 send the earliest created cookie first, and one response's
// cookies in Set-Cookie order. A cookie set again while it is live keeps its
// creation time on Firefox, and on Chrome only when the value is the same.
//
// The jar used to move a cookie set again to the end, whatever the preset,
// and sorted by path length alone with a sort that does not keep the order of
// equal elements, so once more than 12 cookies matched a request and their
// paths differed in length it sent them in an order of its own.

// cookieOrderStep is one request of a timeline: the server answers path with
// setCookie, and the request carries the cookies stored before it, which must
// go out as want says for the preset's engine ("webkit", "chromium" or
// "gecko"). A step without want is not checked.
type cookieOrderStep struct {
	path      string
	setCookie []string
	want      map[string]string
}

func cookieOrderAll(cookie string) map[string]string {
	return map[string]string{"webkit": cookie, "chromium": cookie, "gecko": cookie}
}

// cookieOrderTimelines are the session test's two captured sequences:
// "page" from the WebSocket capture harness's page in the Safari 26.3 capture
// and the Chrome 156 and Firefox 159 validation runs, and "reset" from the
// six steps headless Chrome 156 and Firefox 159 ran, whose echoes are their
// wire lines verbatim. Safari's column of "reset" follows the captured rule.
var cookieOrderTimelines = []struct {
	name  string
	steps []cookieOrderStep
}{
	{"page", []cookieOrderStep{
		{path: "/page", setCookie: cookieOrderPage},
		{path: "/a", want: map[string]string{
			"webkit":   "lax=1; none=1; plain=1; strict=1",
			"chromium": "plain=1; lax=1; strict=1; none=1",
			"gecko":    "plain=1; lax=1; strict=1; none=1",
		}},
		{path: "/later", setCookie: []string{"403=1; Path=/; Max-Age=3600"}},
		{path: "/b", want: map[string]string{
			"webkit":   "403=1; lax=1; none=1; plain=1; strict=1",
			"chromium": "plain=1; lax=1; strict=1; none=1; 403=1",
			"gecko":    "plain=1; lax=1; strict=1; none=1; 403=1",
		}},
		{path: "/page", setCookie: cookieOrderPage},
		{path: "/c", want: map[string]string{
			"webkit":   "lax=1; none=1; plain=1; strict=1; 403=1",
			"chromium": "plain=1; lax=1; strict=1; none=1; 403=1",
			"gecko":    "plain=1; lax=1; strict=1; none=1; 403=1",
		}},
	}},
	{"reset", []cookieOrderStep{
		{path: "/step1", setCookie: []string{"a=1; Path=/; Max-Age=3600"}},
		{path: "/echo1", want: cookieOrderAll("a=1")},
		{path: "/step2", setCookie: []string{"b=1; Path=/; Max-Age=3600"}},
		{path: "/echo2", want: map[string]string{
			"webkit":   "b=1; a=1",
			"chromium": "a=1; b=1",
			"gecko":    "a=1; b=1",
		}},
		// One response stores two cookies.
		{path: "/step3", setCookie: []string{"c=1; Path=/; Max-Age=3600", "d=1; Path=/; Max-Age=3600"}},
		{path: "/echo3", want: map[string]string{
			"webkit":   "c=1; d=1; b=1; a=1",
			"chromium": "a=1; b=1; c=1; d=1",
			"gecko":    "a=1; b=1; c=1; d=1",
		}},
		// Set again with the same value.
		{path: "/step4", setCookie: []string{"a=1; Path=/; Max-Age=3600"}},
		{path: "/echo4", want: map[string]string{
			"webkit":   "a=1; c=1; d=1; b=1",
			"chromium": "a=1; b=1; c=1; d=1",
			"gecko":    "a=1; b=1; c=1; d=1",
		}},
		// Set again with a new value.
		{path: "/step5", setCookie: []string{"b=2; Path=/; Max-Age=3600"}},
		{path: "/echo5", want: map[string]string{
			"webkit":   "b=2; a=1; c=1; d=1",
			"chromium": "a=1; c=1; d=1; b=2",
			"gecko":    "a=1; b=2; c=1; d=1",
		}},
		// Two new cookies, then one set again with a new value, in one response.
		{path: "/step6", setCookie: []string{"e=1; Path=/; Max-Age=3600", "f=1; Path=/; Max-Age=3600", "c=9; Path=/; Max-Age=3600"}},
		{path: "/echo6", want: map[string]string{
			"webkit":   "c=9; e=1; f=1; b=2; a=1; d=1",
			"chromium": "a=1; d=1; b=2; e=1; f=1; c=9",
			"gecko":    "a=1; b=2; c=9; d=1; e=1; f=1",
		}},
	}},
}

var cookieOrderPage = []string{
	"plain=1; Path=/; Max-Age=3600",
	"lax=1; Path=/; Max-Age=3600; SameSite=Lax",
	"strict=1; Path=/; Max-Age=3600; SameSite=Strict",
	"none=1; Path=/; Max-Age=3600; SameSite=None; Secure",
}

var cookieOrderPresets = []struct{ name, engine string }{
	{"chrome-latest", "chromium"},
	{"firefox-latest", "gecko"},
	{"safari-latest", "webkit"},
	{"chrome-latest-ios", "webkit"},
}

var cookieOrderProtocols = []struct {
	name  string
	force Option
	major int
}{
	{"h1", WithForceHTTP1(), 1},
	{"h2", WithForceHTTP2(), 2},
}

// cookieOrderServer is an httptest TLS server that answers each path with its
// Set-Cookie lines, in order, and records the Cookie every request carried.
// Go's HTTP/2 server joins the cookie fields of a request in their wire order.
type cookieOrderServer struct {
	*httptest.Server
	mu    sync.Mutex
	last  string
	major int
}

func startCookieOrderServer(t *testing.T, setCookie map[string][]string) *cookieOrderServer {
	t.Helper()
	s := &cookieOrderServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.last = strings.Join(r.Header.Values("Cookie"), "; ")
		s.major = r.ProtoMajor
		s.mu.Unlock()
		for _, line := range setCookie[r.URL.Path] {
			w.Header().Add("Set-Cookie", line)
		}
		io.WriteString(w, "ok")
	}))
	s.EnableHTTP2 = true
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func (s *cookieOrderServer) seen() (cookie string, major int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last, s.major
}

// cookieOrderClientOptions are the options every client here takes.
func cookieOrderClientOptions(force Option) []Option {
	return []Option{
		WithInsecureSkipVerify(), // httptest's certificate
		WithPreferIPv4(),         // the server listens on 127.0.0.1 only
		WithTimeout(10 * time.Second),
		force,
	}
}

// cookieOrderDo sends GET path through c and returns the Cookie the server
// saw. It also checks that the jar's CookieHeader agrees with the wire.
func cookieOrderDo(t *testing.T, c *Client, srv *cookieOrderServer, path string) string {
	t.Helper()
	return cookieOrderDoAt(t, c, srv, srv.URL, path)
}

// cookieOrderDoAt is cookieOrderDo on the origin base, which can be a name
// that WithConnectTo sends to srv.
func cookieOrderDoAt(t *testing.T, c *Client, srv *cookieOrderServer, base, path string) string {
	t.Helper()
	u, err := url.Parse(base + path)
	if err != nil {
		t.Fatal(err)
	}
	header := c.Cookies().CookieHeader(u)
	resp, err := c.Do(context.Background(), &Request{Method: "GET", URL: base + path})
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	resp.Close()
	got, _ := srv.seen()
	if got != header {
		t.Errorf("GET %s sent Cookie %q, but the jar's CookieHeader was %q", path, got, header)
	}
	return got
}

// cookieOrderDoStream sends GET path through c.DoStream.
func cookieOrderDoStream(t *testing.T, c *Client, srv *cookieOrderServer, path string) string {
	t.Helper()
	resp, err := c.DoStream(context.Background(), &Request{Method: "GET", URL: srv.URL + path})
	if err != nil {
		t.Fatalf("stream GET %s: %v", path, err)
	}
	io.Copy(io.Discard, resp)
	resp.Close()
	got, _ := srv.seen()
	return got
}

// freezeCookieClock makes every store of j read the same system time, so
// only the jar's own clock tells two stores apart.
func freezeCookieClock(j *CookieJar, at time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.clock.Now = func() time.Time { return at }
}

// cookieOrderRun sends the steps of a timeline through c and checks each
// Cookie the preset's engine has a want for. The last checked request goes
// out five times through Do and once through DoStream.
func cookieOrderRun(t *testing.T, c *Client, srv *cookieOrderServer, steps []cookieOrderStep, engine string) {
	t.Helper()
	var final cookieOrderStep
	for _, st := range steps {
		got := cookieOrderDo(t, c, srv, st.path)
		if want, ok := st.want[engine]; ok {
			final = st
			if got != want {
				t.Errorf("GET %s sent Cookie %q, want %q", st.path, got, want)
			}
		}
	}
	want := final.want[engine]
	for i := 0; i < 4; i++ {
		if got := cookieOrderDo(t, c, srv, final.path); got != want {
			t.Errorf("GET %s again (%d) sent Cookie %q, want %q", final.path, i+2, got, want)
		}
	}
	if got := cookieOrderDoStream(t, c, srv, final.path); got != want {
		t.Errorf("DoStream %s sent Cookie %q, want %q", final.path, got, want)
	}
}

func cookieOrderSetCookies(steps []cookieOrderStep) map[string][]string {
	setCookie := map[string][]string{}
	for _, st := range steps {
		if st.setCookie != nil {
			setCookie[st.path] = st.setCookie
		}
	}
	return setCookie
}

// TestClientCookieOrderWire runs both timelines through a real send on a
// preset of each engine, over HTTP/1.1 and HTTP/2, once on the system clock
// and once with the jar's time source frozen.
func TestClientCookieOrderWire(t *testing.T) {
	for _, tl := range cookieOrderTimelines {
		setCookie := cookieOrderSetCookies(tl.steps)
		for _, preset := range cookieOrderPresets {
			for _, p := range cookieOrderProtocols {
				for _, clock := range []string{"system", "frozen"} {
					t.Run(tl.name+"/"+preset.name+"/"+p.name+"/"+clock, func(t *testing.T) {
						srv := startCookieOrderServer(t, setCookie)
						c := NewClient(preset.name, cookieOrderClientOptions(p.force)...)
						c.EnableCookies()
						t.Cleanup(func() { c.Close() })
						if clock == "frozen" {
							freezeCookieClock(c.Cookies(), time.Now())
						}
						cookieOrderRun(t, c, srv, tl.steps, preset.engine)
						if _, major := srv.seen(); major != p.major {
							t.Fatalf("the server saw HTTP/%d, want HTTP/%d", major, p.major)
						}
					})
				}
			}
		}
	}
}

// TestClientCookieOrderEveryJar checks the three ways a Client gets a jar:
// EnableCookies, NewSession, and retries, which turn the jar on by
// themselves. Each takes the order of the preset's browser.
func TestClientCookieOrderEveryJar(t *testing.T) {
	var steps []cookieOrderStep
	for _, tl := range cookieOrderTimelines {
		if tl.name == "reset" {
			steps = tl.steps
		}
	}
	setCookie := cookieOrderSetCookies(steps)
	jars := []struct {
		name string
		make func(preset string) *Client
	}{
		{"EnableCookies", func(preset string) *Client {
			c := NewClient(preset, cookieOrderClientOptions(WithForceHTTP2())...)
			c.EnableCookies()
			return c
		}},
		{"NewSession", func(preset string) *Client {
			return NewSession(preset, cookieOrderClientOptions(WithForceHTTP2())...)
		}},
		{"WithRetry", func(preset string) *Client {
			return NewClient(preset, append(cookieOrderClientOptions(WithForceHTTP2()), WithRetry(1))...)
		}},
	}
	for _, jar := range jars {
		for _, preset := range cookieOrderPresets {
			t.Run(jar.name+"/"+preset.name, func(t *testing.T) {
				srv := startCookieOrderServer(t, setCookie)
				c := jar.make(preset.name)
				t.Cleanup(func() { c.Close() })
				if c.Cookies() == nil {
					t.Fatal("the client has no cookie jar")
				}
				cookieOrderRun(t, c, srv, steps, preset.engine)
			})
		}
	}
}

// TestClientCookieOrderFollowsSetPreset switches a chrome-latest client to
// safari-latest after the "page" timeline. Its next request sends Safari's
// order, the page's cookies, set again last, first and by name, and the jar's
// CookieHeader agrees with the wire before and after the switch.
func TestClientCookieOrderFollowsSetPreset(t *testing.T) {
	var steps []cookieOrderStep
	for _, tl := range cookieOrderTimelines {
		if tl.name == "page" {
			steps = tl.steps
		}
	}
	for _, p := range cookieOrderProtocols {
		t.Run(p.name, func(t *testing.T) {
			srv := startCookieOrderServer(t, cookieOrderSetCookies(steps))
			c := NewClient("chrome-latest", cookieOrderClientOptions(p.force)...)
			c.EnableCookies()
			t.Cleanup(func() { c.Close() })
			cookieOrderRun(t, c, srv, steps, "chromium")

			c.SetPreset("safari-latest")
			const want = "lax=1; none=1; plain=1; strict=1; 403=1"
			if got := cookieOrderDo(t, c, srv, "/after-switch"); got != want {
				t.Errorf("after SetPreset(safari-latest), GET sent Cookie %q, want %q", got, want)
			}
			c.SetPreset("chrome-latest")
			const back = "plain=1; lax=1; strict=1; none=1; 403=1"
			if got := cookieOrderDo(t, c, srv, "/after-switch-back"); got != back {
				t.Errorf("after SetPreset(chrome-latest), GET sent Cookie %q, want %q", got, back)
			}
		})
	}
}

// TestClientCookieOrderManyCookies stores thirteen cookies in one response:
// twelve with Path=/ and then one with a longer path. The longer path goes
// first on every preset; then the twelve go in Set-Cookie order, or by name
// on WebKit presets. The old sort by path length alone sent "deep; k05; k09;
// k08; k07; k06; k11; k04; k03; k02; k01; k00; k10" here.
func TestClientCookieOrderManyCookies(t *testing.T) {
	var lines, setOrder, byName []string
	for i := 11; i >= 0; i-- {
		name := fmt.Sprintf("k%02d", i)
		lines = append(lines, name+"=1; Path=/")
		setOrder = append(setOrder, name+"=1")
	}
	for i := 0; i < 12; i++ {
		byName = append(byName, fmt.Sprintf("k%02d=1", i))
	}
	lines = append(lines, "deep=1; Path=/app")
	want := map[string]string{
		"chromium": "deep=1; " + strings.Join(setOrder, "; "),
		"gecko":    "deep=1; " + strings.Join(setOrder, "; "),
		"webkit":   "deep=1; " + strings.Join(byName, "; "),
	}
	for _, preset := range cookieOrderPresets {
		for _, p := range cookieOrderProtocols {
			t.Run(preset.name+"/"+p.name, func(t *testing.T) {
				srv := startCookieOrderServer(t, map[string][]string{"/many": lines})
				c := NewClient(preset.name, cookieOrderClientOptions(p.force)...)
				c.EnableCookies()
				t.Cleanup(func() { c.Close() })
				cookieOrderDo(t, c, srv, "/many")
				for i := 0; i < 5; i++ {
					if got := cookieOrderDo(t, c, srv, "/app/x"); got != want[preset.engine] {
						t.Errorf("GET /app/x (%d) sent Cookie %q, want %q", i+1, got, want[preset.engine])
					}
				}
			})
		}
	}
}

// TestClientCookieOrderAcrossDomains stores a cookie for the parent domain and
// then a host-only one, and sends a request that carries both. The jar used to
// send the host's cookies first. Chromium's CookieSorter and Firefox's
// CompareCookiesForSending read only the path length and the creation time,
// so the Chrome and Firefox presets send the parent domain's cookie, created
// first, first. On the WebKit presets the cookie stored last goes first: that
// is the captured rule's prediction, as no Safari capture has a domain cookie.
func TestClientCookieOrderAcrossDomains(t *testing.T) {
	setCookie := map[string][]string{
		"/setdomain": {"d=1; Domain=example.test; Path=/"},
		"/sethost":   {"h=1; Path=/"},
	}
	want := map[string]string{
		"chromium": "d=1; h=1",
		"gecko":    "d=1; h=1",
		"webkit":   "h=1; d=1", // predicted, not captured
	}
	for _, preset := range cookieOrderPresets {
		for _, p := range cookieOrderProtocols {
			t.Run(preset.name+"/"+p.name, func(t *testing.T) {
				srv := startCookieOrderServer(t, setCookie)
				u, err := url.Parse(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				// a.example.test is dialled on the server's address.
				opts := append(cookieOrderClientOptions(p.force), WithConnectTo("a.example.test", "127.0.0.1"))
				c := NewClient(preset.name, opts...)
				c.EnableCookies()
				t.Cleanup(func() { c.Close() })
				base := "https://a.example.test:" + u.Port()
				cookieOrderDoAt(t, c, srv, base, "/setdomain")
				cookieOrderDoAt(t, c, srv, base, "/sethost")
				if got := cookieOrderDoAt(t, c, srv, base, "/echo"); got != want[preset.engine] {
					t.Errorf("GET /echo sent Cookie %q, want %q", got, want[preset.engine])
				}
				if _, major := srv.seen(); major != p.major {
					t.Fatalf("the server saw HTTP/%d, want HTTP/%d", major, p.major)
				}
			})
		}
	}
}

// cookieCopyPresets are the clients the copy tests take cookies from, one
// with RFC 6265's order and one with WebKit's, and what each sends after
// storing a=1 and then b=1.
var cookieCopyPresets = []struct{ name, want string }{
	{"firefox-latest", "a=1; b=1"},
	{"safari-latest", "b=1; a=1"},
}

// startCookieCopySource stores a=1 and then b=1, from two responses, in a new
// client of preset, and checks what it sends with both.
func startCookieCopySource(t *testing.T, preset, want string) (*Client, *cookieOrderServer) {
	t.Helper()
	srv := startCookieOrderServer(t, map[string][]string{"/a": {"a=1; Path=/"}, "/b": {"b=1; Path=/"}})
	c := NewClient(preset, cookieOrderClientOptions(WithForceHTTP2())...)
	c.EnableCookies()
	t.Cleanup(func() { c.Close() })
	cookieOrderDo(t, c, srv, "/a")
	cookieOrderDo(t, c, srv, "/b")
	if got := cookieOrderDo(t, c, srv, "/echo"); got != want {
		t.Fatalf("before the copy, GET /echo sent Cookie %q, want %q", got, want)
	}
	return c, srv
}

// TestClientCookieCopyLeavesTheSource copies a client's cookies into another
// jar with the public API, as a caller moving a login from one client to
// another does, in the order Cookies returns them and reversed. The jar keeps
// the times it orders by in an entry of its own and never writes into a
// Cookie, so the source client sends what it sent before, and each cookie it
// hands out still equals the one parsed from its Set-Cookie line.
func TestClientCookieCopyLeavesTheSource(t *testing.T) {
	for _, src := range cookieCopyPresets {
		for _, reversed := range []bool{false, true} {
			name := src.name + "/forwards"
			if reversed {
				name = src.name + "/reversed"
			}
			t.Run(name, func(t *testing.T) {
				c, srv := startCookieCopySource(t, src.name, src.want)
				u, err := url.Parse(srv.URL + "/")
				if err != nil {
					t.Fatal(err)
				}
				cookies := c.Cookies().Cookies(u)
				if reversed {
					slices.Reverse(cookies)
				}
				NewCookieJar().SetCookies(u, cookies)

				if got := cookieOrderDo(t, c, srv, "/echo"); got != src.want {
					t.Errorf("after the copy, GET /echo sent Cookie %q, want %q", got, src.want)
				}
				for _, ck := range c.Cookies().Cookies(u) {
					from, err := url.Parse(srv.URL + "/" + ck.Name)
					if err != nil {
						t.Fatal(err)
					}
					if parsed := ParseSetCookie(ck.Name+"=1; Path=/", from); *ck != *parsed {
						t.Errorf("the jar hands out %+v, want %+v as parsed", *ck, *parsed)
					}
				}
			})
		}
	}
}

// TestClientCookieCopyWhileSending copies a client's cookies into another jar
// over and over, reversed, while the client sends. Run under -race: the
// copy's stores and the client's reads share no field.
func TestClientCookieCopyWhileSending(t *testing.T) {
	for _, src := range cookieCopyPresets {
		t.Run(src.name, func(t *testing.T) {
			c, srv := startCookieCopySource(t, src.name, src.want)
			u, err := url.Parse(srv.URL + "/")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				dst := NewCookieJar()
				for i := 0; i < 200; i++ {
					cookies := c.Cookies().Cookies(u)
					slices.Reverse(cookies)
					dst.SetCookies(u, cookies)
				}
			}()
			for i := 0; i < 20; i++ {
				if got := cookieOrderDo(t, c, srv, "/echo"); got != src.want {
					t.Errorf("GET /echo (%d) during the copies sent Cookie %q, want %q", i+1, got, src.want)
				}
			}
			<-done
			if got := cookieOrderDo(t, c, srv, "/echo"); got != src.want {
				t.Errorf("GET /echo after the copies sent Cookie %q, want %q", got, src.want)
			}
		})
	}
}
