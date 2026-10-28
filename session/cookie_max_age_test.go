package session

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// A Set-Cookie whose Max-Age is 0 or less deletes the cookie (RFC 6265 Section
// 5.2.2), and a positive one sets its lifetime, over any Expires. The jar
// checks only Expires, and nothing turned Max-Age into one, so the session
// ignored Max-Age. "Max-Age=0" and "Max-Age=-1" kept the cookie and the next
// request sent "Cookie: sid=", a cookie with "Max-Age=1" never expired, and
// "Max-Age=3600" lost to a past Expires.
//
// Each case below was captured in Chrome 156 and Firefox 159, which agree on
// all of them. With several Max-Age attributes the last one decides, and an
// invalid one leaves none, so Expires decides. A Max-Age too large for an int,
// or for a time.Duration, keeps the cookie and must not wrap around. The
// client package reads Max-Age the same way.

const (
	maxAgeFuture = "Fri, 01 Jan 2100 00:00:00 GMT"
	maxAgePast   = "Thu, 01 Jan 1970 00:00:00 GMT"
)

var maxAgeCases = []struct {
	attrs   string // after "sid=x; Path=/; "
	maxAge  int    // MaxAge as parsed
	deleted bool
}{
	{"Max-Age=0", -1, true},
	{"Max-Age=00", -1, true},
	{"Max-Age=-0", -1, true},
	{"Max-Age=-1", -1, true},
	{"Max-Age = 0", -1, true},
	{"Max-Age=0; Expires=" + maxAgeFuture, -1, true},
	{"Max-Age=3600; Expires=" + maxAgePast, 3600, false},
	{"Max-Age=3600; Max-Age=0", -1, true},
	{"Max-Age=0; Max-Age=3600", 3600, false},
	{"Max-Age=0; Max-Age=abc", 0, false},
	{"Max-Age=abc", 0, false},
	{"Max-Age=", 0, false},
	{"Max-Age=1abc", 0, false},
	{"Max-Age=-99999999999999999999", -1, true},
}

// Too large for an int on 32-bit, for a time.Duration on 64-bit, and for an
// int64. Each lasts at least the 68 years a 32-bit int holds.
var maxAgeHuge = []string{"3000000000", "10000000000", "99999999999999999999"}

func TestExtractCookiesMaxAge(t *testing.T) {
	const reqURL = "https://example.com/"
	for _, tc := range maxAgeCases {
		t.Run(tc.attrs, func(t *testing.T) {
			s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest"})
			t.Cleanup(s.Close)
			s.extractCookies(map[string][]string{"set-cookie": {"sid=secret; Path=/"}}, reqURL)
			before := time.Now()
			s.extractCookies(map[string][]string{"set-cookie": {"sid=x; Path=/; " + tc.attrs}}, reqURL)

			want, wantCount := "sid=x", 1
			if tc.deleted {
				want, wantCount = "", 0
			}
			if got := s.cookies.BuildCookieHeader("example.com", "/", true); got != want {
				t.Errorf("BuildCookieHeader = %q, want %q", got, want)
			}

			// GetAll and Export list only live cookies, and ClearExpired keeps
			// only those.
			all := s.cookies.GetAll()
			exported := s.cookies.Export()["example.com"]
			s.cookies.ClearExpired()
			if len(all) != wantCount || len(exported) != wantCount || s.cookies.Count() != wantCount {
				t.Fatalf("GetAll has %d, Export %d and ClearExpired left %d; want %d each",
					len(all), len(exported), s.cookies.Count(), wantCount)
			}
			if tc.deleted {
				return
			}

			c := all[0]
			if c.MaxAge != tc.maxAge {
				t.Errorf("MaxAge = %d, want %d", c.MaxAge, tc.maxAge)
			}
			switch {
			case tc.maxAge > 0:
				lo, hi := before.Add(time.Hour), time.Now().Add(time.Hour)
				if c.Expires == nil || c.Expires.Before(lo) || c.Expires.After(hi) {
					t.Errorf("Expires = %v, want an hour from now", c.Expires)
				}
			case c.Expires != nil:
				t.Errorf("Expires = %v, want none, as for a session cookie", *c.Expires)
			}
		})
	}
}

func TestExtractCookiesMaxAgeHuge(t *testing.T) {
	for _, v := range maxAgeHuge {
		t.Run(v, func(t *testing.T) {
			s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest"})
			t.Cleanup(s.Close)
			s.extractCookies(map[string][]string{"set-cookie": {"sid=x; Path=/; Max-Age=" + v}}, "https://example.com/")
			if got := s.cookies.BuildCookieHeader("example.com", "/", true); got != "sid=x" {
				t.Errorf("BuildCookieHeader = %q, want sid=x", got)
			}
			all := s.cookies.GetAll()
			if len(all) != 1 || all[0].Expires == nil || all[0].Expires.Before(time.Now().AddDate(68, 0, 0)) {
				t.Fatalf("GetAll = %+v, want sid with an Expires at least 68 years from now", all)
			}
		})
	}
}

// A cookie deleted with Max-Age is gone from the next request, and one that
// Max-Age keeps alive is still sent, through a real send. Each preset builds
// its own header block, so every browser family the library mimics is covered.
func TestSessionCookieMaxAgeWire(t *testing.T) {
	cases := []struct{ setCookie, want string }{
		{"sid=; Path=/; Max-Age=0", ""},
		{"sid=; Path=/; Max-Age=-1", ""},
		{"sid=gone; Path=/; Max-Age=0; Expires=" + maxAgeFuture, ""},
		{"sid=kept; Path=/; Max-Age=3600; Expires=" + maxAgePast, "sid=kept"},
		{"sid=kept; Path=/; Max-Age=10000000000", "sid=kept"},
	}
	protocols := []struct {
		name  string
		major int
	}{
		{"h1", 1},
		{"h2", 2},
	}
	for _, preset := range []string{"chrome-latest", "firefox-latest", "safari-latest", "chrome-latest-ios"} {
		for _, p := range protocols {
			for _, tc := range cases {
				t.Run(preset+"/"+p.name+"/"+tc.setCookie, func(t *testing.T) {
					var mu sync.Mutex
					sent := map[string][]string{}
					protoMajor := 0
					srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						sent[r.URL.Path] = r.Header.Values("Cookie")
						protoMajor = r.ProtoMajor
						mu.Unlock()
						switch r.URL.Path {
						case "/set":
							w.Header().Add("Set-Cookie", "sid=secret; Path=/")
						case "/delete":
							w.Header().Add("Set-Cookie", tc.setCookie)
						}
						io.WriteString(w, "ok")
					}))
					srv.EnableHTTP2 = true
					srv.StartTLS()
					t.Cleanup(srv.Close)

					s := NewSession("", &protocol.SessionConfig{
						Preset:             preset,
						InsecureSkipVerify: true, // httptest's certificate
						PreferIPv4:         true, // the server listens on 127.0.0.1 only
						ForceHTTP1:         p.major == 1,
						ForceHTTP2:         p.major == 2,
						Timeout:            10000,
					})
					t.Cleanup(s.Close)

					for _, path := range []string{"/set", "/delete", "/next"} {
						if _, err := s.Request(context.Background(), &transport.Request{Method: "GET", URL: srv.URL + path}); err != nil {
							t.Fatalf("GET %s: %v", path, err)
						}
					}

					mu.Lock()
					defer mu.Unlock()
					if protoMajor != p.major {
						t.Fatalf("the server saw HTTP/%d, want HTTP/%d", protoMajor, p.major)
					}
					if got := sent["/delete"]; len(got) != 1 || got[0] != "sid=secret" {
						t.Fatalf("the request before the delete sent Cookie %q, want sid=secret", got)
					}
					got := sent["/next"]
					switch {
					case tc.want == "" && len(got) != 0:
						t.Errorf("the next request sent Cookie %q; the Set-Cookie deleted it", got)
					case tc.want != "" && (len(got) != 1 || got[0] != tc.want):
						t.Errorf("the next request sent Cookie %q, want %s", got, tc.want)
					}
				})
			}
		}
	}
}
