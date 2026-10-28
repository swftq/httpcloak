package fingerprint

import (
	"slices"
	"strings"
	"testing"
)

// WebKit sends Sec-Fetch-Dest, Sec-Fetch-Mode and Sec-Fetch-Site and has never
// implemented Sec-Fetch-User (WebKit bug 247697), so neither Safari nor Chrome
// on iOS sends it. The WebKit presets leave it out of their headers, but
// HeaderCoherence wrote ?1 on every user-triggered navigation whatever the
// preset, so GenerateNavigationHeaders handed it back for safari-18.
func TestHeaderCoherenceWebKitPresetsSendNoSecFetchUser(t *testing.T) {
	var webkit []string
	for _, name := range Available() {
		if strings.Contains(Get(name).UserAgent, "AppleWebKit/605.1.15") {
			webkit = append(webkit, name)
		}
	}
	for _, want := range []string{"safari-17-ios", "safari-18", "safari-18-ios", "chrome-143-ios", "chrome-155-ios"} {
		if !slices.Contains(webkit, want) {
			t.Fatalf("%s is not among the WebKit presets %v", want, webkit)
		}
	}
	for _, name := range Available() {
		hc := NewHeaderCoherence(Get(name))
		// A map that already carries the header, as one built from an older
		// preset would, must lose it too.
		applied := map[string]string{"Sec-Fetch-User": "?1"}
		hc.ApplyToHeaders(applied, NavigationContext())
		for from, h := range map[string]map[string]string{
			"GenerateNavigationHeaders": hc.GenerateNavigationHeaders(),
			"ApplyToHeaders":            applied,
		} {
			v, ok := h["Sec-Fetch-User"]
			if slices.Contains(webkit, name) {
				if ok {
					t.Errorf("%s: %s wrote Sec-Fetch-User %q; WebKit sends none", name, from, v)
				}
			} else if v != "?1" {
				// Chromium and Gecko send it on a navigation a person started.
				t.Errorf("%s: %s wrote Sec-Fetch-User %q, want ?1", name, from, v)
			}
		}
	}
}
