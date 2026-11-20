package fingerprint

import (
	"net/url"
	"strings"
	"testing"
)

// Over plain HTTP, Chrome 156 and Firefox 159 send gzip, deflate to any host
// that is not loopback and their full list to a loopback one; Safari 26.3
// sends gzip, deflate on every plain-HTTP request. Measured against a page on
// a LAN address that loaded resources from localhost and back. The wire half
// is in the client and session packages; this covers the rule itself.

// The hosts both browsers count as loopback: Chromium's net::IsLocalhost and
// Firefox's IsPotentiallyTrustworthyLoopbackHost agree on every case here.
func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":       true,
		"LOCALHOST":       true,
		"localhost.":      true,
		"app.localhost":   true,
		"App.LocalHost.":  true,
		"127.0.0.1":       true,
		"127.1.2.3":       true,
		"127.255.255.255": true,
		"::1":             true,

		// Both browsers read an IPv4-mapped address as IPv6, which is loopback
		// only when it is exactly ::1. net.IP.IsLoopback says yes here.
		"::ffff:127.0.0.1": false,

		"0.0.0.0":           false,
		"::":                false,
		"192.168.1.196":     false,
		"10.0.0.1":          false,
		"169.254.229.206":   false,
		"lan-origin.test":   false,
		"example.com":       false,
		"localhost.com":     false,
		"localhost.example": false,
		"notlocalhost":      false,
		"localhost..":       false,
		"":                  false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// Every built-in derives its rule from its User-Agent. Safari and Chrome on
// iOS run on WebKit and CFNetwork; every other built-in is Chromium or Gecko.
func TestFullEncodingOverHTTPByPreset(t *testing.T) {
	for _, name := range Available() {
		p := GetStrict(name)
		if p == nil {
			continue
		}
		want := FullEncodingLoopback
		if strings.Contains(name, "safari") || strings.Contains(name, "ios") {
			want = FullEncodingNever
		}
		if got := p.ResolveFullEncodingOverHTTP(); got != want {
			t.Errorf("%s: %q, want %q (User-Agent %q)", name, got, want, p.UserAgent)
		}
	}

	for ua, want := range map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0":             FullEncodingLoopback,
		"Mozilla/5.0 (Android 15; Mobile; rv:159.0) Gecko/159.0 Firefox/159.0":                                                                      FullEncodingLoopback,
		"Mozilla/5.0 (iPhone; CPU iPhone OS 26_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/159.0 Mobile/15E148 Safari/605.1.15": FullEncodingNever,
		"curl/8.11.1":   FullEncodingAlways,
		"okhttp/4.12.0": FullEncodingAlways,
		"":              FullEncodingAlways,
	} {
		if got := (&Preset{UserAgent: ua}).ResolveFullEncodingOverHTTP(); got != want {
			t.Errorf("User-Agent %q: %q, want %q", ua, got, want)
		}
	}

	// A set field wins over the User-Agent.
	p := &Preset{UserAgent: "curl/8.11.1", FullEncodingOverHTTP: FullEncodingNever}
	if got := p.ResolveFullEncodingOverHTTP(); got != FullEncodingNever {
		t.Errorf("explicit never on a curl User-Agent: %q", got)
	}
}

func TestSendsFullEncodingTo(t *testing.T) {
	for _, tc := range []struct {
		rule, url string
		want      bool
	}{
		{FullEncodingLoopback, "https://example.com/", true},
		{FullEncodingLoopback, "http://example.com/", false},
		{FullEncodingLoopback, "http://192.168.1.196:8080/", false},
		{FullEncodingLoopback, "http://localhost:8080/", true},
		{FullEncodingLoopback, "http://127.0.0.1/", true},
		{FullEncodingLoopback, "http://[::1]:8080/", true},
		{FullEncodingLoopback, "http://[::ffff:127.0.0.1]/", false},
		{FullEncodingNever, "https://example.com/", true},
		{FullEncodingNever, "http://example.com/", false},
		{FullEncodingNever, "http://localhost:8080/", false},
		{FullEncodingAlways, "http://example.com/", true},
		{FullEncodingAlways, "https://example.com/", true},
	} {
		u, err := url.Parse(tc.url)
		if err != nil {
			t.Fatal(err)
		}
		p := &Preset{FullEncodingOverHTTP: tc.rule}
		if got := p.SendsFullEncodingTo(u); got != tc.want {
			t.Errorf("%s %s: %v, want %v", tc.rule, tc.url, got, tc.want)
		}
	}
	if !(&Preset{FullEncodingOverHTTP: FullEncodingNever}).SendsFullEncodingTo(nil) {
		t.Error("no URL must leave the preset's value alone")
	}
}

// describe writes the resolved rule for every preset, a loaded copy keeps it
// whatever its User-Agent says, and a JSON preset can set it.
func TestFullEncodingOverHTTPJSON(t *testing.T) {
	for name, want := range map[string]string{
		"chrome-latest":  FullEncodingLoopback,
		"firefox-148":    FullEncodingLoopback,
		"safari-18":      FullEncodingNever,
		"chrome-148-ios": FullEncodingNever,
	} {
		out, err := Describe(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, `"full_encoding_over_http": "`+want+`"`) {
			t.Errorf("describe %s lacks full_encoding_over_http %q", name, want)
		}
	}

	// A described Safari copy given a Chrome User-Agent stays on Safari's rule.
	out, err := Describe("safari-18")
	if err != nil {
		t.Fatal(err)
	}
	out = strings.Replace(out, `"name": "safari-18"`, `"name": "safari-18-chrome-ua"`, 1)
	ua := GetStrict("safari-18").UserAgent
	out = strings.Replace(out, `"user_agent": "`+ua+`"`, `"user_agent": "`+GetStrict("chrome-latest").UserAgent+`"`, 1)
	p, err := LoadAndBuildPresetFromJSON([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if p.UserAgent == ua {
		t.Fatal("test did not replace the User-Agent")
	}
	if got := p.ResolveFullEncodingOverHTTP(); got != FullEncodingNever {
		t.Errorf("loaded Safari copy with a Chrome User-Agent: %q, want never", got)
	}

	for _, tc := range []struct {
		headers string
		want    string
	}{
		{`"full_encoding_over_http": "always"`, FullEncodingAlways},
		{`"full_encoding_over_http": "never"`, FullEncodingNever},
		{`"user_agent": "curl/8.11.1"`, FullEncodingAlways},
		{`"user_agent": "MyApp/2.1 CFNetwork/3826.400.120 Darwin/25.3.0", "full_encoding_over_http": "never"`, FullEncodingNever},
	} {
		js := `{"version": 1, "preset": {"name": "fe-json", "based_on": "chrome-latest", "headers": {` + tc.headers + `}}}`
		p, err := LoadAndBuildPresetFromJSON([]byte(js))
		if err != nil {
			t.Fatalf("%s: %v", tc.headers, err)
		}
		if got := p.ResolveFullEncodingOverHTTP(); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.headers, got, tc.want)
		}
	}

	js := `{"version": 1, "preset": {"name": "fe-bad", "based_on": "chrome-latest", "headers": {"full_encoding_over_http": "https"}}}`
	if _, err := LoadAndBuildPresetFromJSON([]byte(js)); err == nil || !strings.Contains(err.Error(), "full_encoding_over_http") {
		t.Errorf("accepted an unknown full_encoding_over_http value: %v", err)
	}
}
