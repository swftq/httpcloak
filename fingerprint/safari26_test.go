package fingerprint

import (
	"slices"
	"strings"
	"testing"
)

// Safari 26.3 measured on macOS 26.3 and in the iOS 26.3.1 simulator, against a
// server that logs HTTP/1.1 as sent and every HTTP/2 frame. Both sent the same
// SETTINGS (2=0, 3=100, 4=2097152, 9=1), a connection WINDOW_UPDATE of
// 10420225, pseudo-headers in the order m,s,a,p and no priority fields on any
// HEADERS frame. Every request carried an incremental priority header whose
// urgency followed the request's destination, on HTTP/1.1 as well.
func TestSafari26Presets(t *testing.T) {
	for _, c := range []struct {
		name, ua string
		aliases  []string
	}{
		{"safari-26", "Version/26.3 Safari/605.1.15", []string{"safari-latest"}},
		{"safari-26-ios", "iPhone OS 18_7 like Mac OS X", []string{"safari-latest-ios", "ios-safari-latest", "ios-safari-26"}},
	} {
		p := GetStrict(c.name)
		if p == nil {
			t.Fatalf("%s not registered", c.name)
		}
		for _, a := range c.aliases {
			if got := GetStrict(a); got == nil || got.Name != c.name {
				t.Errorf("%s resolves to %v, want %s", a, got, c.name)
			}
		}
		if !strings.Contains(p.UserAgent, c.ua) {
			t.Errorf("%s: User-Agent %q, want it to contain %q", c.name, p.UserAgent, c.ua)
		}
		s := p.HTTP2Settings
		if !s.NoRFC7540Priorities || s.StreamWeight != 0 || s.ConnectionWindowUpdate != 10420225 {
			t.Errorf("%s: NoRFC7540Priorities=%v StreamWeight=%d window=%d, want true 0 10420225",
				c.name, s.NoRFC7540Priorities, s.StreamWeight, s.ConnectionWindowUpdate)
		}
		if got := p.H2Config.SettingsOrder; !slices.Equal(got, []uint16{2, 3, 4, 9}) {
			t.Errorf("%s: settings order %v, want [2 3 4 9]", c.name, got)
		}
		if got := p.H2PseudoHeaderOrder(); !slices.Equal(got, []string{":method", ":scheme", ":authority", ":path"}) {
			t.Errorf("%s: pseudo-header order %v", c.name, got)
		}
		if !p.SendsPriorityOverHTTP1() {
			t.Errorf("%s: Safari sends its priority header over HTTP/1.1", c.name)
		}
		for dest, want := range map[string]string{
			"document": "u=0, i", "iframe": "u=0, i", "style": "u=1, i", "script": "u=1, i",
			"font": "u=3, i", "empty": "u=3, i", "image": "u=5, i",
		} {
			if _, _, hv, ok := p.H2PriorityFor(dest); !ok || hv != want {
				t.Errorf("%s/%s: priority %q (found %v), want %q", c.name, dest, hv, ok, want)
			}
		}
		for _, hp := range p.HeaderOrder {
			if hp.Key == "sec-fetch-user" || hp.Key == "upgrade-insecure-requests" {
				t.Errorf("%s: navigation sends %s; Safari 26 sent neither over HTTPS", c.name, hp.Key)
			}
		}
	}
}

// Safari 26.3 ended every ordinary request of a capture on macOS 26.3
// (run-20261031-234946) the same way: Accept-Language, Priority,
// Accept-Encoding, the Cookie when it had one, and on HTTP/1.1 Connection, with
// nothing after it. That held on all 288 HTTP/1.1 requests, plain and over TLS,
// and on all 153 HTTP/2 ones, which end at the cookie. Every other field came
// before Accept-Language: the body's headers on all 270 HTTP/1.1 and 122 HTTP/2
// requests that had a body, and Cache-Control, the field the table does not
// name that turned up most, right before it on 259 of the 288. Chrome on iOS
// runs on the same WebKit, so its presets from 148 on carry the same table.
//
// Every order a WebKit 26 preset hands the transport must therefore end that
// way, whatever the destination, and name connection once. Nothing may land
// after it either, so the body's headers, Transfer-Encoding and the marker for
// the caller's own headers come before accept-language. A redirect hop gets
// the early-referer table when a preset has one and the usual order otherwise,
// so H2HeaderOrderFor and the two optional tables cover every order
// HeaderOrderFor returns. Those two must at least end accept-encoding, cookie,
// connection: the one redirect hop Safari was seen sending, a WebSocket
// handshake's after a 302, moved Accept-Language and Priority into the middle.
func TestWebKit26OrdersEndLikeSafari(t *testing.T) {
	tail := []string{"accept-language", "priority", "accept-encoding", "cookie", "connection"}
	early := []string{"content-type", "content-length", "transfer-encoding", "origin", OtherHeaders}
	presets := []string{"safari-26", "safari-26-ios", "chrome-148-ios", "chrome-150-ios", "chrome-151-ios", "chrome-152-ios", "chrome-155-ios"}
	var table []string
	for _, name := range presets {
		p := GetStrict(name)
		if p == nil {
			t.Fatalf("%s not registered", name)
		}
		check := func(label string, order, tail []string) {
			if n := len(order); n < len(tail) || !slices.Equal(order[n-len(tail):], tail) {
				t.Errorf("%s %s: %q does not end %q", name, label, order, tail)
			}
			connections := 0
			for _, h := range order {
				if h == "connection" {
					connections++
				}
			}
			if connections != 1 {
				t.Errorf("%s %s: connection named %d times in %q, want once", name, label, connections, order)
			}
		}

		check("H2HeaderOrder()", p.H2HeaderOrder(), tail)
		for _, dest := range []string{"", "document", "iframe", "empty", "style", "script", "font", "image"} {
			order := p.H2HeaderOrderFor(dest)
			label := `H2HeaderOrderFor("` + dest + `")`
			check(label, order, tail)
			al := slices.Index(order, "accept-language")
			for _, h := range early {
				if i := slices.Index(order, h); i < 0 || i > al {
					t.Errorf("%s %s: %q at %d, want it before accept-language at %d in %q", name, label, h, i, al, order)
				}
			}
		}
		if p.H2Config != nil {
			for _, o := range []struct {
				label string
				order []string
			}{
				{"HPACKHeaderOrderSubresource", p.H2Config.HPACKHeaderOrderSubresource},
				{"HPACKHeaderOrderEarlyReferer", p.H2Config.HPACKHeaderOrderEarlyReferer},
			} {
				if len(o.order) > 0 {
					check(o.label, o.order, tail[2:])
				}
			}
		}

		// The tables are copies, in three JSON files, so keep them equal.
		if table == nil {
			table = p.H2HeaderOrder()
		} else if got := p.H2HeaderOrder(); !slices.Equal(got, table) {
			t.Errorf("%s: order %q, want %s's %q", name, got, presets[0], table)
		}
	}
}
