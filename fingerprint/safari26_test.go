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
