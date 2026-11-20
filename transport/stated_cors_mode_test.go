package transport

import (
	"testing"

	"github.com/sardanioss/httpcloak/internal/secfetch"
)

// A request whose caller names the page API, fetch() or XMLHttpRequest, goes
// out in cors mode with Sec-Fetch-Dest: empty even when its shape would not be
// sniffed as one (applyPresetHeaders asks statedCORS first). FetchMode, which
// the session's redirect hops read to pick each hop's Origin, and
// secfetch.Dest, which decides whether a response's Accept-CH is learned, must
// agree with what goes on the wire.
func TestStatedCORSModeAgreesWithTheWire(t *testing.T) {
	tr := NewTransport("chrome-latest")
	defer tr.Close()
	preset := tr.getPreset()

	for _, initiator := range []string{InitiatorFetch, InitiatorXHR} {
		req := &Request{Method: "GET", URL: "https://a.test/page", Initiator: initiator}
		if got := tr.FetchMode(req); got != "cors" {
			t.Errorf("%s: FetchMode = %q, want cors", initiator, got)
		}
		if got := secfetch.Dest(preset, false, req.Method, req.Initiator, req.Headers, req.ExactHeaders); got != "empty" {
			t.Errorf("%s: secfetch.Dest = %q, want empty", initiator, got)
		}
	}

	// Without one, a plain GET is a navigation.
	req := &Request{Method: "GET", URL: "https://a.test/page"}
	if got := tr.FetchMode(req); got != "navigate" {
		t.Errorf("no initiator: FetchMode = %q, want navigate", got)
	}
	if got := secfetch.Dest(preset, false, req.Method, req.Initiator, req.Headers, req.ExactHeaders); got != "document" {
		t.Errorf("no initiator: secfetch.Dest = %q, want document", got)
	}
}
