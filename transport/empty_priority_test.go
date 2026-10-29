package transport

import (
	"context"
	"slices"
	"testing"
	"time"
)

// Chrome sends no priority header for a request at the default urgency, u=3
// and not incremental: quiche serializes that priority to nothing, and
// spdy_http_utils.cc adds the header only when something is left. An async or
// injected script is such a request, and Chrome sent each one with no header
// at weight 147. A caller could not ask for that. "" sent an empty priority
// field, which no browser sends, and the weight came from the dest, 220 for a
// script; ExactHeaders and TLS-only left the header out but kept the 220, a
// pair no Chrome build produces either.
func TestEmptyPriorityHeaderSendsNone(t *testing.T) {
	script := func(priority ...string) map[string][]string {
		h := map[string][]string{"Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Dest": {"script"}}
		if priority != nil {
			h["priority"] = priority
		}
		return h
	}
	for _, c := range []struct {
		name    string
		preset  string
		headers map[string][]string
		tlsOnly bool
		header  string // "" means none on the wire
		weight  int
		excl    bool
	}{
		{"empty", "chrome-155-windows", script(""), false, "", 147, true},
		{"blank", "chrome-155-windows", script(" "), false, "", 147, true},
		// Asking for nothing still gets what the table gives a script.
		{"unset", "chrome-155-windows", script(), false, "u=1", 220, true},
		// No header by any other road is the same default urgency.
		{"tls-only", "chrome-155-windows", script(), true, "", 147, true},
		// A request with no Sec-Fetch-Dest either, which no browser sends,
		// keeps the preset's static weight.
		{"tls-only without a dest", "chrome-155-windows", map[string][]string{"Accept": {"*/*"}}, true, "", 256, true},
		// Firefox's weight is the table's whatever the header says.
		{"firefox", "firefox-148-windows", script(""), false, "", 22, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := startH2CaptureServer(t)
			tr := NewTransport(c.preset)
			tr.SetProtocol(ProtocolHTTP2)
			tr.SetInsecureSkipVerify(true)
			defer tr.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + srv.addr + "/s.js",
				Headers: c.headers, TLSOnly: &c.tlsOnly})
			if err != nil {
				t.Fatal(err)
			}
			resp.Close()

			got := <-srv.captures
			if v, sent := got.Headers["priority"]; v != c.header || sent != (c.header != "") {
				t.Errorf("priority %q (sent: %v), want %q", v, sent, c.header)
			}
			if w := int(got.Priority.Weight) + 1; w != c.weight || got.Priority.Exclusive != c.excl {
				t.Errorf("weight %d exclusive %v, want %d %v", w, got.Priority.Exclusive, c.weight, c.excl)
			}
		})
	}
}

// Firefox sends the same priority header over HTTP/1.1 as over HTTP/2, so ""
// has to take it off that wire as well.
func TestEmptyPriorityHeaderSendsNoneOverHTTP1(t *testing.T) {
	srv := newH1OrderCapture(t)
	tr := NewTransport("firefox-148-windows")
	defer tr.Close()

	for _, c := range []struct {
		headers map[string][]string
		sent    bool
	}{
		{nil, true},
		{map[string][]string{"priority": {""}}, false},
	} {
		names := srv.do(t, tr, &Request{Method: "GET", URL: srv.url, Headers: c.headers})
		if slices.Contains(names, "priority") != c.sent {
			t.Errorf("headers %q: priority sent %v, want %v (%v)", c.headers, !c.sent, c.sent, names)
		}
	}
}
