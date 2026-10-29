package fingerprint

import (
	"strings"
	"testing"
)

// Chrome 156, measured on 156.0.8078.48 against this library's chrome-155
// preset: one powhttp session holding the browser and the candidate, on
// billetterie.psg.fr, www.fandom.com, my.nordaccount.com and evade.rs.
//
// Three fields move and nothing else does, which is what these tests pin.

// TestChrome156BrandListReorders is the part a version bump gets wrong.
//
// Chromium varies the GREASE brand's name, version **and position** per
// release. 155 ended the list with `"Not(A:Brand";v="24"`; 156 opens it with
// `"Not:A-Brand";v="8"`. A bump that edits only the major number keeps two
// wrong brands and the wrong order, which is a fingerprint that matches no
// Chrome at all.
func TestChrome156BrandListReorders(t *testing.T) {
	const want = `"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"`
	for _, plat := range []string{"windows", "linux", "macos"} {
		p := Get("chrome-156-" + plat)
		if got := p.Headers["sec-ch-ua"]; got != want {
			t.Errorf("chrome-156-%s: sec-ch-ua = %s, want %s", plat, got, want)
		}
		// The ordered list is the emit set, so the value there is the one that
		// reaches the wire. A file that updates `values` and forgets `order`
		// sends 155's brands in 156's clothing.
		var found int
		for _, pair := range p.HeaderOrder {
			if strings.EqualFold(pair.Key, "sec-ch-ua") {
				found++
				if pair.Value != want {
					t.Errorf("chrome-156-%s: ordered sec-ch-ua = %s, want %s",
						plat, pair.Value, want)
				}
			}
		}
		if found != 1 {
			t.Errorf("chrome-156-%s: sec-ch-ua appears %d times in the order, want 1", plat, found)
		}
	}
}

// TestChrome156FullVersionList is the build, in the new brand order.
func TestChrome156FullVersionList(t *testing.T) {
	const want = `"Not:A-Brand";v="8.0.0.0", "Chromium";v="156.0.8078.48", "Google Chrome";v="156.0.8078.48"`
	for _, name := range []string{"chrome-156", "chrome-156-windows", "chrome-156-linux",
		"chrome-156-macos", "chrome-latest", "chrome-latest-windows",
		"chrome-latest-linux", "chrome-latest-macos"} {
		if got := Get(name).ResolveClientHints().UAFullVersionList; got != want {
			t.Errorf("%s: sec-ch-ua-full-version-list = %s, want %s", name, got, want)
		}
	}
}

// TestChrome156FullVersionSkipsTheGreaseBrand is the trap the reorder sets.
//
// sec-ch-ua-full-version is derived from the list rather than stored, by taking
// the first brand that is neither Chromium nor GREASE. With GREASE now leading,
// a derivation that trusted position would answer "8.0.0.0" — a version no
// browser has ever reported. Chrome sends "156.0.8078.48", measured.
func TestChrome156FullVersionSkipsTheGreaseBrand(t *testing.T) {
	const want = `"156.0.8078.48"`
	for _, plat := range []string{"windows", "linux", "macos"} {
		if got := Get("chrome-156-" + plat).ResolveClientHints().UAFullVersion; got != want {
			t.Errorf("chrome-156-%s: sec-ch-ua-full-version = %s, want %s", plat, got, want)
		}
	}
}

// TestChrome156KeepsEverythingElse. The capture checked each of these against
// 155 and found no movement, so inheriting them through based_on is a claim
// about the browser and worth holding to.
func TestChrome156KeepsEverythingElse(t *testing.T) {
	for _, plat := range []string{"windows", "linux", "macos"} {
		p156, p155 := Get("chrome-156-"+plat), Get("chrome-155-"+plat)

		if a, b := p156.ResolveNavigationAccept(), p155.ResolveNavigationAccept(); a != b {
			t.Errorf("chrome-156-%s: navigation Accept moved\n got %q\nwant %q", plat, a, b)
		}
		if a, b := p156.ResolveImageAccept(), p155.ResolveImageAccept(); a != b {
			t.Errorf("chrome-156-%s: image Accept moved\n got %q\nwant %q", plat, a, b)
		}

		// The navigation order, name by name. Only sec-ch-ua's *value* moves.
		if len(p156.HeaderOrder) != len(p155.HeaderOrder) {
			t.Fatalf("chrome-156-%s: order is %d slots, 155 has %d",
				plat, len(p156.HeaderOrder), len(p155.HeaderOrder))
		}
		for i := range p156.HeaderOrder {
			if a, b := p156.HeaderOrder[i].Key, p155.HeaderOrder[i].Key; a != b {
				t.Errorf("chrome-156-%s: slot %d is %q, 155 has %q", plat, i, a, b)
			}
		}

		// The platform version is not in any preset file; it comes from
		// defaultClientHintPlatformVersion, and Chrome 156 sends what it
		// already returned.
		if a, b := p156.ResolveClientHints().UAPlatformVersion,
			p155.ResolveClientHints().UAPlatformVersion; a != b {
			t.Errorf("chrome-156-%s: platform version moved, %q against %q", plat, a, b)
		}
	}
}

// TestChrome156LatestAliases. The -latest aliases move as a set. This is the
// single home for the assertion; move it to the next version's file rather than
// copying it.
//
// Desktop only. Android's User-Agent carries a device model and iOS's a full
// build number, and neither is derivable from a desktop capture, so both stay
// on 155 until a capture of each lands.
func TestChrome156LatestAliases(t *testing.T) {
	for _, tc := range []struct{ alias, wantUA string }{
		{"chrome-latest", "Chrome/156.0.0.0"},
		{"chrome-latest-windows", "Chrome/156.0.0.0"},
		{"chrome-latest-linux", "Chrome/156.0.0.0"},
		{"chrome-latest-macos", "Chrome/156.0.0.0"},
		{"chrome-latest-android", "Chrome/155.0.0.0"},
		{"chrome-latest-ios", "CriOS/155.0.8059.37"},
		{"ios-chrome-latest", "CriOS/155.0.8059.37"},
	} {
		p := GetStrict(tc.alias)
		if p == nil {
			t.Errorf("%s not registered", tc.alias)
			continue
		}
		if !strings.Contains(p.UserAgent, tc.wantUA) {
			t.Errorf("%s: UA = %q, want it to contain %q", tc.alias, p.UserAgent, tc.wantUA)
		}
	}
}

// TestChrome156PlatformTokens. The capture is Windows'; Linux and macOS take
// the measured delta on their own base, so the one thing that must still differ
// between them is the User-Agent's platform token.
func TestChrome156PlatformTokens(t *testing.T) {
	for _, tc := range []struct{ plat, token string }{
		{"windows", "(Windows NT 10.0; Win64; x64)"},
		{"linux", "(X11; Linux x86_64)"},
		{"macos", "(Macintosh; Intel Mac OS X 10_15_7)"},
	} {
		ua := Get("chrome-156-" + tc.plat).UserAgent
		if !strings.Contains(ua, tc.token) {
			t.Errorf("chrome-156-%s: UA = %q, want it to contain %q", tc.plat, ua, tc.token)
		}
		if !strings.Contains(ua, "Chrome/156.0.0.0") {
			t.Errorf("chrome-156-%s: UA = %q, want Chrome/156.0.0.0", tc.plat, ua)
		}
	}
}
