package transport

import (
	"context"
	"slices"
	"testing"
	"time"
)

// Safari 26 sent a priority header on every request, its urgency following the
// destination, and no priority fields on any HTTP/2 HEADERS frame: it announces
// SETTINGS_NO_RFC7540_PRIORITIES and means it. Measured on macOS 26.3 and in
// the iOS 26.3.1 simulator. The table drives the header and nothing else.
func TestWebKit26PriorityHeaderWithoutFramePriority(t *testing.T) {
	for _, preset := range []string{"safari-26", "safari-26-ios"} {
		for _, c := range []struct {
			mode, dest, want string
		}{
			{"", "", "u=0, i"},
			{"navigate", "iframe", "u=0, i"},
			{"no-cors", "style", "u=1, i"},
			{"no-cors", "script", "u=1, i"},
			{"cors", "font", "u=3, i"},
			{"cors", "empty", "u=3, i"},
			{"no-cors", "image", "u=5, i"},
		} {
			srv := startH2CaptureServer(t)
			tr := NewTransport(preset)
			tr.SetProtocol(ProtocolHTTP2)
			tr.SetInsecureSkipVerify(true)

			var headers map[string][]string
			if c.dest != "" {
				headers = map[string][]string{"Sec-Fetch-Mode": {c.mode}, "Sec-Fetch-Dest": {c.dest}}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + srv.addr + "/r", Headers: headers})
			cancel()
			if err != nil {
				t.Fatalf("%s %s: %v", preset, c.dest, err)
			}
			resp.Close()
			tr.Close()

			got := <-srv.captures
			if got.HasPriority {
				t.Errorf("%s %q: HEADERS carried priority fields %+v; Safari 26 sends none", preset, c.dest, got.Priority)
			}
			if v := got.Headers["priority"]; v != c.want {
				t.Errorf("%s %q: priority %q, want %q", preset, c.dest, v, c.want)
			}
			if _, ok := got.Headers["sec-fetch-user"]; ok {
				t.Errorf("%s %q: sent sec-fetch-user, which WebKit does not implement", preset, c.dest)
			}
			if pseudo := got.HeaderOrder[:4]; !slices.Equal(pseudo, []string{":method", ":scheme", ":authority", ":path"}) {
				t.Errorf("%s %q: pseudo-header order %v", preset, c.dest, pseudo)
			}
		}
	}
}

// Over HTTP/1.1 too: Safari sent the same priority header there, on plain HTTP
// and over TLS, on macOS and iOS alike.
func TestWebKit26PriorityOverHTTP1(t *testing.T) {
	srv := newH1OrderCapture(t)
	for _, preset := range []string{"safari-26", "safari-26-ios"} {
		tr := NewTransport(preset)
		names := srv.do(t, tr, &Request{Method: "GET", URL: srv.url,
			Headers: map[string][]string{"Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Dest": {"image"}}})
		tr.Close()
		if !slices.Contains(names, "priority") {
			t.Errorf("%s: no priority header over HTTP/1.1 (%v)", preset, names)
		}
	}
}
