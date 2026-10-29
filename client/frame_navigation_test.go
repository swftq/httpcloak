package client

import (
	"net/url"
	"testing"

	customhttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// The navigation headers here set Sec-Fetch-User: ?1 unconditionally, and
// Chrome sends it only on a navigation a person started; an iframe loading its
// src is not one. A request the caller marks as a frame's navigation goes
// without, unless the caller sets it for a click inside the frame.
func TestClientFrameNavigationSendsNoSecFetchUser(t *testing.T) {
	preset := fingerprint.Get("chrome-latest")
	target, _ := url.Parse("https://example.com/")
	for _, c := range []struct {
		name    string
		headers map[string][]string
		user    string // "" means none
	}{
		{"top-level navigation", nil, "?1"},
		{"iframe", map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}}, ""},
		{"frame, lowercase", map[string][]string{"sec-fetch-mode": {"navigate"}, "sec-fetch-dest": {"frame"}}, ""},
		{"a click inside an iframe", map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}, "Sec-Fetch-User": {"?1"}}, "?1"},
	} {
		req := &Request{Method: "GET", URL: target.String(), Headers: c.headers}
		httpReq, err := customhttp.NewRequest("GET", req.URL, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		applyModeHeaders(httpReq, preset, req, target, nil)

		if got := httpReq.Header.Get("Sec-Fetch-User"); got != c.user {
			t.Errorf("%s: Sec-Fetch-User %q, want %q", c.name, got, c.user)
		}
		if httpReq.Header.Get("Upgrade-Insecure-Requests") != "1" {
			t.Errorf("%s: no longer a navigation: %v", c.name, httpReq.Header)
		}
	}
}
