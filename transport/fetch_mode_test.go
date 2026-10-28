package transport

import (
	"context"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// The session judges a redirect hop's Origin by FetchMode, so FetchMode has to
// name the Sec-Fetch-Mode the request really goes out with, or the hop's
// Origin and its Sec-Fetch-Mode disagree on the wire. Each case is sent for
// real, and the mode the server received is compared with FetchMode's answer.
func TestFetchModeIsWhatGoesOut(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		mu.Lock()
		got = r.Header.Values("Sec-Fetch-Mode")
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)

	tlsOnly := true
	cases := []struct {
		name string
		req  Request
		want string
	}{
		{"navigation", Request{Method: "GET"}, "navigate"},
		{"API Accept", Request{Method: "GET", Headers: map[string][]string{"Accept": {"application/json"}}}, "cors"},
		{"JSON POST", Request{Method: "POST", Body: []byte("{}"),
			Headers: map[string][]string{"Content-Type": {"application/json"}}}, "cors"},
		{"form POST", Request{Method: "POST", Body: []byte("b=2"),
			Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}}, "navigate"},
		{"caller's mode", Request{Method: "GET", Headers: map[string][]string{"sec-fetch-mode": {"no-cors"}}}, "no-cors"},
		{"TLS-only", Request{Method: "GET", TLSOnly: &tlsOnly}, ""},
		{"TLS-only with the caller's mode", Request{Method: "GET", TLSOnly: &tlsOnly,
			Headers: map[string][]string{"Sec-Fetch-Mode": {"cors"}}}, "cors"},
		{"exact without a mode", Request{Method: "GET",
			ExactHeaders: []fingerprint.HeaderPair{{Key: "User-Agent", Value: "x"}}}, ""},
		{"exact with a mode", Request{Method: "GET", ExactHeaders: []fingerprint.HeaderPair{
			{Key: "User-Agent", Value: "x"}, {Key: "sec-fetch-mode", Value: "CORS"}}}, "cors"},
	}
	for _, preset := range []string{"chrome-latest", "firefox-latest", "safari-latest"} {
		tr := NewTransport(preset)
		t.Cleanup(tr.Close)
		for _, c := range cases {
			req := c.req
			req.URL = srv.URL
			if mode := tr.FetchMode(&req); mode != c.want {
				t.Errorf("%s, %s: FetchMode = %q, want %q", preset, c.name, mode, c.want)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, err := tr.Do(ctx, &req)
			cancel()
			if err != nil {
				t.Fatalf("%s, %s: %v", preset, c.name, err)
			}
			mu.Lock()
			wire := strings.ToLower(strings.Join(got, ", "))
			mu.Unlock()
			if wire != c.want {
				t.Errorf("%s, %s: went out with Sec-Fetch-Mode %q, want %q", preset, c.name, wire, c.want)
			}
		}
	}
}
