package session

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// The order of the cookies in a Cookie header follows the browser engine.
//
// Safari sends the most recently stored cookie first, and the cookies one
// response stored by name: that fits all 618 requests with two or more cookies
// in a capture of Safari 26.3 on macOS (run-20261031-234946), over HTTP/1.1 and
// HTTP/2. Chrome 156 and Firefox 159 send the earliest created cookie first,
// and the cookies one response stored in Set-Cookie order. They differ on a
// cookie set again while it is live: Firefox keeps its creation time, and so
// its place, whatever the value; Chrome keeps it only when the value is the
// same, and with a new value gives it a new one, behind the cookies stored
// before. Headless Chrome 156 and Firefox 159 did so in five runs each, with or
// without a second between the steps, and Chromium's CookieMonster and
// Firefox's CookieStorage say the same.
//
// The jar used to send the oldest store first on every preset, and stamped
// stores with time.Now. Go's clock on Windows only moves on the timer
// interrupt, so the cookies of one response shared a time and went out in map
// order, which could change from one request to the next.

// cookieOrderStep is one request of a timeline: the server answers path with
// setCookie, and the request carries the cookies stored before it, which must
// go out as want says for the preset's engine ("webkit", "chromium" or
// "gecko"). A step without want is not checked.
type cookieOrderStep struct {
	path      string
	setCookie []string
	want      map[string]string
}

// cookieOrderAll is a want that every engine shares.
func cookieOrderAll(cookie string) map[string]string {
	return map[string]string{"webkit": cookie, "chromium": cookie, "gecko": cookie}
}

// cookieOrderTimelines are two captured sequences.
//
// "page": what the WebSocket capture harness's page did, in the captures of
// Safari 26.3 and of the Chrome 156 and Firefox 159 validation runs. Safari's
// /c is run-20261031-234946 h1tls.log:132 with the cookie names shortened,
// and /a and /b have the shape of its h1.log:32 and h1.log:5168 (those were
// over plain HTTP, which carries no Secure cookie). Chrome's /a is the
// Chrome 156 validation run of 2026-10-31, h1tls.log:169, with the names
// shortened too. Firefox kept the page's cookies ahead of a later one when
// the page set them again (the Firefox 159 validation run of 2026-10-31,
// h1tls.log:130 and :266).
//
// "reset": the six steps headless Chrome 156 and Firefox 159 ran, a fetch
// that sets cookies and then one that echoes the Cookie it carried; every
// echo below is their wire line verbatim. Safari was not captured on this
// sequence: its column follows the captured rule, and a re-set with a new
// value is not captured for it.
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

// cookieOrderPage is what the harness page set, in this order, over TLS.
var cookieOrderPage = []string{
	"plain=1; Path=/; Max-Age=3600",
	"lax=1; Path=/; Max-Age=3600; SameSite=Lax",
	"strict=1; Path=/; Max-Age=3600; SameSite=Strict",
	"none=1; Path=/; Max-Age=3600; SameSite=None; Secure",
}

// cookieOrderPresets are a preset of each engine, with Chrome on iOS for the
// WebKit browser that is not Safari.
var cookieOrderPresets = []struct{ name, engine string }{
	{"chrome-latest", "chromium"},
	{"firefox-latest", "gecko"},
	{"safari-latest", "webkit"},
	{"chrome-latest-ios", "webkit"},
}

// cookieOrderServer is an httptest TLS server that answers each path with its
// Set-Cookie lines, in order, and records the Cookie every request carried.
// Go's HTTP/2 server joins the cookie fields of a request in their wire order.
type cookieOrderServer struct {
	*httptest.Server
	mu    sync.Mutex
	sent  []string // "path: cookie", in arrival order
	major int
}

func startCookieOrderServer(t *testing.T, setCookie map[string][]string) *cookieOrderServer {
	t.Helper()
	s := &cookieOrderServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.sent = append(s.sent, r.URL.Path+": "+strings.Join(r.Header.Values("Cookie"), "; "))
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

// last returns what the n-th request from the end carried, 1 being the last.
func (s *cookieOrderServer) last(n int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sent) < n {
		return ""
	}
	return s.sent[len(s.sent)-n]
}

func newCookieOrderSession(t *testing.T, preset string, major int) *Session {
	t.Helper()
	s := NewSession("", &protocol.SessionConfig{
		Preset:             preset,
		InsecureSkipVerify: true, // httptest's certificate
		PreferIPv4:         true, // the server listens on 127.0.0.1 only
		ForceHTTP1:         major == 1,
		ForceHTTP2:         major == 2,
		Timeout:            10,
	})
	t.Cleanup(s.Close)
	return s
}

// cookieOrderGet sends GET path through s and returns what the server saw it
// carry.
func cookieOrderGet(t *testing.T, s *Session, srv *cookieOrderServer, path string) string {
	t.Helper()
	resp, err := s.Request(context.Background(), &transport.Request{Method: "GET", URL: srv.URL + path})
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	resp.Close()
	return strings.TrimPrefix(srv.last(1), path+": ")
}

// cookieOrderStream sends GET path through s.RequestStream.
func cookieOrderStream(t *testing.T, s *Session, srv *cookieOrderServer, path string) string {
	t.Helper()
	resp, err := s.RequestStream(context.Background(), &transport.Request{Method: "GET", URL: srv.URL + path})
	if err != nil {
		t.Fatalf("stream GET %s: %v", path, err)
	}
	io.Copy(io.Discard, resp)
	resp.Close()
	return strings.TrimPrefix(srv.last(1), path+": ")
}

// freezeCookieClock makes every store of j read the same system time, so
// only the jar's own clock tells two stores apart.
func freezeCookieClock(j *CookieJar, at time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.clock.Now = func() time.Time { return at }
}

var cookieOrderProtocols = []struct {
	name  string
	major int
}{
	{"h1", 1},
	{"h2", 2},
}

// TestSessionCookieOrderWire runs both timelines through a real send on a
// preset of each engine, over HTTP/1.1 and HTTP/2. Each runs once on the
// system clock and once with the jar's time source frozen, so the order
// depends on no clock. The last request goes out five times through Request
// and once through RequestStream, all with the same Cookie.
func TestSessionCookieOrderWire(t *testing.T) {
	for _, tl := range cookieOrderTimelines {
		setCookie := map[string][]string{}
		for _, st := range tl.steps {
			if st.setCookie != nil {
				setCookie[st.path] = st.setCookie
			}
		}
		for _, preset := range cookieOrderPresets {
			for _, p := range cookieOrderProtocols {
				for _, clock := range []string{"system", "frozen"} {
					t.Run(tl.name+"/"+preset.name+"/"+p.name+"/"+clock, func(t *testing.T) {
						srv := startCookieOrderServer(t, setCookie)
						s := newCookieOrderSession(t, preset.name, p.major)
						if clock == "frozen" {
							freezeCookieClock(s.cookies, time.Now())
						}

						var final cookieOrderStep
						for _, st := range tl.steps {
							got := cookieOrderGet(t, s, srv, st.path)
							if want, ok := st.want[preset.engine]; ok {
								final = st
								if got != want {
									t.Errorf("GET %s sent Cookie %q, want %q", st.path, got, want)
								}
							}
						}
						want := final.want[preset.engine]
						for i := 0; i < 4; i++ {
							if got := cookieOrderGet(t, s, srv, final.path); got != want {
								t.Errorf("GET %s again (%d) sent Cookie %q, want %q", final.path, i+2, got, want)
							}
						}
						if got := cookieOrderStream(t, s, srv, final.path); got != want {
							t.Errorf("RequestStream %s sent Cookie %q, want %q", final.path, got, want)
						}
						srv.mu.Lock()
						major := srv.major
						srv.mu.Unlock()
						if major != p.major {
							t.Fatalf("the server saw HTTP/%d, want HTTP/%d", major, p.major)
						}
					})
				}
			}
		}
	}
}

// TestSessionCookieOrderManyCookies stores thirteen cookies in one response:
// twelve with Path=/ and then one with a longer path. The longer path goes
// first on every preset; then the twelve go in Set-Cookie order, or by name
// on WebKit presets, the same on every request.
func TestSessionCookieOrderManyCookies(t *testing.T) {
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
			for _, clock := range []string{"system", "frozen"} {
				t.Run(preset.name+"/"+p.name+"/"+clock, func(t *testing.T) {
					srv := startCookieOrderServer(t, map[string][]string{"/many": lines})
					s := newCookieOrderSession(t, preset.name, p.major)
					if clock == "frozen" {
						freezeCookieClock(s.cookies, time.Now())
					}
					cookieOrderGet(t, s, srv, "/many")
					for i := 0; i < 5; i++ {
						if got := cookieOrderGet(t, s, srv, "/app/x"); got != want[preset.engine] {
							t.Errorf("GET /app/x (%d) sent Cookie %q, want %q", i+1, got, want[preset.engine])
						}
					}
				})
			}
		}
	}
}

// TestSessionSetCookieIsOneStore checks that each SetCookie call is a store of
// its own: the cookie set first goes first, or last on WebKit presets, on
// every request.
func TestSessionSetCookieIsOneStore(t *testing.T) {
	names := []string{"u", "v", "w", "x", "y", "z"}
	var inOrder, reversed []string
	for i := range names {
		inOrder = append(inOrder, names[i]+"=1")
		reversed = append(reversed, names[len(names)-1-i]+"=1")
	}
	want := map[string]string{
		"chromium": strings.Join(inOrder, "; "),
		"gecko":    strings.Join(inOrder, "; "),
		"webkit":   strings.Join(reversed, "; "),
	}
	for _, preset := range cookieOrderPresets {
		t.Run(preset.name, func(t *testing.T) {
			srv := startCookieOrderServer(t, nil)
			s := newCookieOrderSession(t, preset.name, 2)
			for _, name := range names {
				s.SetCookie(name, "1", "127.0.0.1", "/", false, false, "", 0, nil)
			}
			for i := 0; i < 5; i++ {
				if got := cookieOrderGet(t, s, srv, "/"); got != want[preset.engine] {
					t.Errorf("GET / (%d) sent Cookie %q, want %q", i+1, got, want[preset.engine])
				}
			}
		})
	}
}

// TestSessionCookieOrderSurvivesSave saves a session after the "reset"
// timeline and loads it back: the loaded session sends exactly the Cookie the
// saved one did, because every cookie keeps its creation and store time. A
// file without stored_at still loads, with created_at as the store time. The
// one built here stands for a file of an older version whose cookies of one
// response share created_at, as Go's clock on Windows gave them, and a WebKit
// preset sends it in the saved order. Where the clock told those cookies
// apart, a WebKit preset sends them newest created first instead, a known
// limitation of files without stored_at.
func TestSessionCookieOrderSurvivesSave(t *testing.T) {
	var steps []cookieOrderStep
	for _, tl := range cookieOrderTimelines {
		if tl.name == "reset" {
			steps = tl.steps
		}
	}
	setCookie := map[string][]string{}
	for _, st := range steps {
		if st.setCookie != nil {
			setCookie[st.path] = st.setCookie
		}
	}
	for _, preset := range cookieOrderPresets {
		t.Run(preset.name, func(t *testing.T) {
			srv := startCookieOrderServer(t, setCookie)
			s := newCookieOrderSession(t, preset.name, 2)
			var live string
			for _, st := range steps {
				live = cookieOrderGet(t, s, srv, st.path)
			}
			if want := steps[len(steps)-1].want[preset.engine]; live != want {
				t.Fatalf("the live session sent Cookie %q, want %q", live, want)
			}

			data, err := s.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			loaded, err := UnmarshalSession(data)
			if err != nil {
				t.Fatalf("UnmarshalSession: %v", err)
			}
			t.Cleanup(loaded.Close)
			for i := 0; i < 2; i++ {
				if got := cookieOrderGet(t, loaded, srv, "/after-load"); got != live {
					t.Errorf("the loaded session sent Cookie %q (%d), want %q as before the save", got, i+1, live)
				}
			}

			// A file as an older version wrote it on Windows: no stored_at,
			// and created_at stamped on every store, one time for the cookies
			// of one response.
			var state map[string]any
			if err := json.Unmarshal(data, &state); err != nil {
				t.Fatalf("unmarshal the saved state: %v", err)
			}
			for domain, list := range state["cookies"].(map[string]any) {
				for _, c := range list.([]any) {
					c := c.(map[string]any)
					stored, ok := c["stored_at"]
					if !ok {
						t.Fatalf("a cookie of %s was saved without stored_at: %v", domain, c)
					}
					c["created_at"] = stored
					delete(c, "stored_at")
				}
			}
			old, err := json.Marshal(state)
			if err != nil {
				t.Fatalf("marshal the older file: %v", err)
			}
			fromOld, err := UnmarshalSession(old)
			if err != nil {
				t.Fatalf("UnmarshalSession of a file without stored_at: %v", err)
			}
			t.Cleanup(fromOld.Close)
			first := cookieOrderGet(t, fromOld, srv, "/after-old-load")
			if again := cookieOrderGet(t, fromOld, srv, "/after-old-load"); again != first {
				t.Errorf("a session loaded from a file without stored_at sent %q, then %q", first, again)
			}
			if preset.engine == "webkit" && first != live {
				t.Errorf("a WebKit session loaded from a file without stored_at sent %q, want %q", first, live)
			}
		})
	}
}

// TestSessionCookieOrderStoreAfterLoad stores a cookie right after a load,
// with both jars' time sources frozen at one instant: the saved session's
// stores, the save, the load and the new store fall in one tick of the clock,
// as they can between two timer interrupts of Go's clock on Windows. Loading
// moves the jar's clock past the creation and the store time of every cookie
// it loads, so the new cookie is the newest: last on the Chrome and Firefox
// presets, first on the WebKit presets. It used to tie with the loaded cookies
// and go by name. The saved session stores one response, or that response and
// then one that sets a=1 again, so the latest time it saves is a creation time
// in the first case and a store time in the second. A file whose times run an
// hour ahead, as one written where the clock ran ahead, does not move the
// clock: the cookie stored after it keeps the system clock's time.
func TestSessionCookieOrderStoreAfterLoad(t *testing.T) {
	setCookie := map[string][]string{
		"/page":  {"a=1; Path=/", "z=1; Path=/"},
		"/again": {"a=1; Path=/"},
		"/new":   {"n=1; Path=/"},
	}
	want := map[string]string{
		"chromium": "a=1; z=1; n=1",
		"gecko":    "a=1; z=1; n=1",
		"webkit":   "n=1; a=1; z=1",
	}
	histories := []struct {
		name  string
		paths []string
	}{
		{"one-response", []string{"/page"}},
		{"set-again", []string{"/page", "/again"}},
	}
	for _, preset := range cookieOrderPresets {
		for _, p := range cookieOrderProtocols {
			for _, h := range histories {
				t.Run(preset.name+"/"+p.name+"/"+h.name, func(t *testing.T) {
					srv := startCookieOrderServer(t, setCookie)
					at := time.Now()
					loaded := cookieOrderStoreAfterLoad(t, preset.name, p.major, srv, h.paths, at, at)
					if got := cookieOrderGet(t, loaded, srv, "/echo"); got != want[preset.engine] {
						t.Errorf("GET /echo sent Cookie %q, want %q", got, want[preset.engine])
					}
					srv.mu.Lock()
					major := srv.major
					srv.mu.Unlock()
					if major != p.major {
						t.Fatalf("the server saw HTTP/%d, want HTTP/%d", major, p.major)
					}
				})
			}
		}
	}

	t.Run("file-ahead", func(t *testing.T) {
		srv := startCookieOrderServer(t, setCookie)
		at := time.Now()
		loaded := cookieOrderStoreAfterLoad(t, "safari-latest", 2, srv, []string{"/page", "/again"}, at.Add(time.Hour), at)
		var stored *time.Time
		for _, c := range loaded.GetCookies() {
			if c.Name == "n" {
				stored = c.StoredAt
			}
		}
		if stored == nil || !stored.Equal(at) {
			t.Errorf("the cookie stored after loading a file an hour ahead has StoredAt %v, want the system clock's %v", stored, at)
		}
	})
}

// cookieOrderStoreAfterLoad sends paths through a session whose jar reads
// savedAt, saves it and loads it back, then stores the cookie of /new in the
// loaded session, whose jar reads loadedAt.
func cookieOrderStoreAfterLoad(t *testing.T, preset string, major int, srv *cookieOrderServer, paths []string, savedAt, loadedAt time.Time) *Session {
	t.Helper()
	s := newCookieOrderSession(t, preset, major)
	freezeCookieClock(s.cookies, savedAt)
	for _, path := range paths {
		cookieOrderGet(t, s, srv, path)
	}
	data, err := s.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	loaded, err := UnmarshalSession(data)
	if err != nil {
		t.Fatalf("UnmarshalSession: %v", err)
	}
	t.Cleanup(loaded.Close)
	freezeCookieClock(loaded.cookies, loadedAt)
	cookieOrderGet(t, loaded, srv, "/new")
	return loaded
}

// TestSessionCookieOrderFromFilesWithoutTimes loads files that carry no
// cookie times, a v4 file and a v5 file without created_at. Each cookie is
// then a store of its own, in list order, so the one listed first goes first,
// or last on WebKit presets, and the order is the same on every request; it
// used to give them all one time and send them in map order.
func TestSessionCookieOrderFromFilesWithoutTimes(t *testing.T) {
	names := []string{"u", "v", "w", "x", "y", "z"}
	var list []CookieState
	var inOrder, reversed []string
	for i, name := range names {
		list = append(list, CookieState{Name: name, Value: "1", Domain: "127.0.0.1", Path: "/"})
		inOrder = append(inOrder, name+"=1")
		reversed = append(reversed, names[len(names)-1-i]+"=1")
	}
	want := map[string]string{
		"chromium": strings.Join(inOrder, "; "),
		"gecko":    strings.Join(inOrder, "; "),
		"webkit":   strings.Join(reversed, "; "),
	}
	for _, preset := range cookieOrderPresets {
		config := &protocol.SessionConfig{
			Preset:             preset.name,
			InsecureSkipVerify: true, // httptest's certificate
			PreferIPv4:         true, // the server listens on 127.0.0.1 only
			ForceHTTP2:         true,
			Timeout:            10,
		}
		files := map[string]any{
			"v4": SessionStateV4{Version: 4, Config: config, Cookies: list},
			"v5": SessionState{Version: 5, Config: config, Cookies: map[string][]CookieState{"127.0.0.1": list}},
		}
		for _, version := range []string{"v4", "v5"} {
			t.Run(preset.name+"/"+version, func(t *testing.T) {
				data, err := json.Marshal(files[version])
				if err != nil {
					t.Fatalf("marshal the %s file: %v", version, err)
				}
				s, err := UnmarshalSession(data)
				if err != nil {
					t.Fatalf("UnmarshalSession of the %s file: %v", version, err)
				}
				t.Cleanup(s.Close)
				srv := startCookieOrderServer(t, nil)
				for i := 0; i < 5; i++ {
					if got := cookieOrderGet(t, s, srv, "/"); got != want[preset.engine] {
						t.Errorf("GET / (%d) sent Cookie %q, want %q", i+1, got, want[preset.engine])
					}
				}
			})
		}
	}
}
