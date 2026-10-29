package session

import (
	"context"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// By default a redirect hop carries the Referer of the request before it,
// because that is what Chrome and Firefox do. This is the control for the two
// tests below: without it, a knob that silently did nothing and a knob that
// worked would look identical.
func TestRedirectRefererOnByDefault(t *testing.T) {
	srv := newBodyCapture(t, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})
	page := srv.url + "app/page.html?q=1"

	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "hop0",
		Headers: map[string][]string{"Referer": {page}},
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.hops) != 2 {
		t.Fatalf("server saw %d hops, want 2", len(srv.hops))
	}
	if !hasHeader(srv.hops[1], "referer") {
		t.Fatal("hop 2 carried no Referer by default; Chrome carries the " +
			"request's Referer on every hop except an https->http downgrade")
	}
	if got := srv.hops[1].values["referer"]; got != page {
		t.Errorf("hop 2 Referer = %q, want the request's own Referer %q, not "+
			"the URL that issued the 302", got, page)
	}
}

// DisableRedirectReferer suppresses it: the original request still carries the
// caller's Referer, and the hop carries none. Forwarding it would hand the new
// host exactly what the caller asked us not to send.
func TestDisableRedirectRefererSuppressesIt(t *testing.T) {
	srv := newBodyCapture(t, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})
	page := "https://caller.example/secret?token=abc"

	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "hop0",
		Headers:                map[string][]string{"Referer": {page}},
		DisableRedirectReferer: true,
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.hops) != 2 {
		t.Fatalf("server saw %d hops, want 2", len(srv.hops))
	}
	if got := srv.hops[0].values["referer"]; got != page {
		t.Errorf("hop 1 Referer = %q, want the caller's %q; the knob is about "+
			"redirect hops, not the request itself", got, page)
	}
	if hasHeader(srv.hops[1], "referer") {
		t.Errorf("hop 2 carried Referer %q despite DisableRedirectReferer",
			srv.hops[1].values["referer"])
	}
}

// And it holds on every hop and whatever the caller called the header. The
// session copies the caller's headers onto each hop under their own names, so a
// knob that only looked for "Referer" would let a lowercase one through.
func TestDisableRedirectRefererDropsItOnEveryHop(t *testing.T) {
	srv := newBodyCapture(t, 302, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "hop0",
		Headers:                map[string][]string{"referer": {"https://caller.example/secret?token=abc"}},
		DisableRedirectReferer: true,
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.hops) != 3 {
		t.Fatalf("server saw %d hops, want 3", len(srv.hops))
	}
	for i, hop := range srv.hops[1:] {
		if got := hop.values["referer"]; got != "" {
			t.Errorf("hop %d forwarded the caller's Referer %q despite "+
				"DisableRedirectReferer", i+2, got)
		}
	}
}

// ExactHeaders has to survive a redirect. Its contract is that nothing else is
// added, and the hop used to rebuild the request without it, so a caller
// mirroring a captured request got their exact bytes on the first request and
// the full preset pipeline on every hop after it, with no error and no warning.
func TestExactHeadersSurviveARedirect(t *testing.T) {
	srv := newBodyCapture(t, 302, 200)
	s := newBodyTestSession(t, &protocol.SessionConfig{FollowRedirects: true})

	exact := []fingerprint.HeaderPair{
		{Key: "user-agent", Value: "mirror/1"},
		{Key: "accept", Value: "*/*"},
		{Key: "x-mirror", Value: "1"},
	}

	if _, err := s.Request(context.Background(), &transport.Request{
		Method: "GET", URL: srv.url + "hop0",
		ExactHeaders: exact,
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.hops) != 2 {
		t.Fatalf("server saw %d hops, want 2", len(srv.hops))
	}

	// Both hops must carry exactly the given names, in the given order. The
	// order half is not incidental: these are deliberately not alphabetical
	// (user-agent before accept), so a writer that sorts its output fails here.
	want := []string{"user-agent", "accept", "x-mirror"}
	hop1, hop2 := srv.hops[0].headers, srv.hops[1].headers
	if len(hop1) != len(exact) {
		t.Fatalf("hop 1 sent %d headers %v, want exactly the %d given; the preset "+
			"pipeline leaked into the original request", len(hop1), hop1, len(exact))
	}
	for i := range want {
		if hop1[i] != want[i] {
			t.Errorf("hop 1 header %d is %q, want %q; ExactHeaders puts the pairs "+
				"on the wire in the order given", i, hop1[i], want[i])
		}
	}
	if len(hop2) != len(hop1) {
		t.Fatalf("hop 1 sent %v but hop 2 sent %v; ExactHeaders did not survive "+
			"the redirect and the preset pipeline rebuilt the request", hop1, hop2)
	}
	for i := range hop1 {
		if hop2[i] != hop1[i] {
			t.Errorf("header %d is %q on hop 1 and %q on hop 2; the hop must "+
				"reproduce the caller's exact shape", i, hop1[i], hop2[i])
		}
	}
	for _, name := range hop2 {
		if srv.hops[1].values[name] != srv.hops[0].values[name] {
			t.Errorf("header %q is %q on hop 1 and %q on hop 2", name,
				srv.hops[0].values[name], srv.hops[1].values[name])
		}
	}
}
