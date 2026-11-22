package transport

import (
	"context"
	"slices"
	"sort"
	"testing"
	"time"

	utls "github.com/sardanioss/utls"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/hrrtest"
)

// TestSecondClientHelloAfterHelloRetryRequest sends a request through every
// preset, over HTTP/1.1 and HTTP/2, to a server that answers the first
// ClientHello with a HelloRetryRequest for P-384, and reads the second
// ClientHello off the wire.
//
// For every preset, the second hello is the first with the key_share list
// replaced by one P-384 share, in a record of version 0x0303, and nothing else
// changed but the padding (hrrtest.CheckRetry: RFC 8446 sections 4.1.2 and
// 5.1).
//
// The padding follows the browser:
//
//   - Presets on the hellos Safari 26.3 sends, HelloSafari_18 and HelloIOS_18,
//     send the second hello unpadded. Safari's own, against a Go server
//     accepting P-384 only, is its first hello with one P-384 share, after one
//     ChangeCipherSpec, and 364 bytes with no padding (run-20261121-225724,
//     macOS 26.3, tlshrr.log:2-51). The forced HTTP/1.1 send here has the same
//     SNI and ALPN, so it must come to the same 364 bytes.
//   - Every other preset keeps utls's padding: a hello is padded exactly when
//     its spec carries a padding extension and the hello, padding aside, is
//     256 to 511 bytes long, the window BoringPaddingStyle pads. The Chromium
//     and Firefox specs carry none, so neither hello is padded, which is what
//     BoringSSL (which never pads a second hello) and NSS (which pads only
//     inside that window, and these second hellos are longer) send too. The
//     iOS 14 spec, safari-17-ios, pads both; no capture shows what iOS 17
//     sends after a HelloRetryRequest.
//
// The first hello follows utls's rule on every preset, which the change for
// the second must not disturb.
func TestSecondClientHelloAfterHelloRetryRequest(t *testing.T) {
	names := fingerprint.Available()
	sort.Strings(names)

	sem := make(chan struct{}, 6)
	for _, name := range names {
		for _, m := range []struct {
			label string
			proto Protocol
		}{{"h1", ProtocolHTTP1}, {"h2", ProtocolHTTP2}} {
			t.Run(name+"/"+m.label, func(t *testing.T) {
				t.Parallel()
				sem <- struct{}{}
				defer func() { <-sem }()
				checkHelloRetryRequestSend(t, name, m.proto)
			})
		}
	}
}

func checkHelloRetryRequestSend(t *testing.T, name string, proto Protocol) {
	p := fingerprint.Get(name)
	if p == nil {
		t.Fatalf("preset %s missing", name)
	}
	s := hrrtest.Start(t)

	tr := NewTransport(name)
	defer tr.Close()
	tr.SetProtocol(proto)
	tr.SetInsecureSkipVerify(true)
	// localhost, as Safari's capture used, so the SNI matches it.
	tr.SetConnectTo("localhost", "127.0.0.1")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://localhost:" + s.Port() + "/"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, err := resp.Text()
	resp.Close()
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	if resp.StatusCode != 200 || body != "hrr=true curve=CurveP384" {
		t.Fatalf("status %d, server reported %q: the handshake did not go through a HelloRetryRequest for P-384", resp.StatusCode, body)
	}

	sent := s.Sent()
	if len(sent) != 1 {
		t.Fatalf("%d connections, want 1", len(sent))
	}
	flight, err := hrrtest.ParseFlight(sent[0])
	if err != nil {
		t.Fatalf("client flight: %v", err)
	}
	if len(flight.Hellos) != 2 {
		t.Fatalf("%d ClientHellos (%v), want 2", len(flight.Hellos), flight.Records)
	}
	first, second := flight.Hellos[0], flight.Hellos[1]
	if err := hrrtest.CheckRetry(first, second); err != nil {
		t.Errorf("second ClientHello: %v", err)
	}
	shares, err := second.KeyShares()
	if err != nil {
		t.Fatalf("second ClientHello key_share: %v", err)
	}
	if len(shares) != 1 || shares[0] != (hrrtest.KeyShare{Group: uint16(utls.CurveP384), KeyLen: 97}) {
		t.Errorf("second ClientHello key shares %v, want one P-384 share of 97 bytes", shares)
	}

	specPads := presetSpecPads(t, p)
	inWindow := func(n int) bool { return n > 0xff && n < 0x200 }
	if want := specPads && inWindow(first.UnpaddedLen()); first.Padded() != want {
		t.Errorf("first ClientHello (%d bytes, %d unpadded) padded=%v, want %v", first.Len(), first.UnpaddedLen(), first.Padded(), want)
	}

	if !safariRetryHello(p) {
		if want := specPads && inWindow(second.UnpaddedLen()); second.Padded() != want {
			t.Errorf("second ClientHello (%d bytes, %d unpadded) padded=%v, want %v as utls pads it", second.Len(), second.UnpaddedLen(), second.Padded(), want)
		}
		return
	}
	if second.Padded() {
		t.Errorf("second ClientHello padded to %d bytes; Safari 26.3 sends it unpadded", second.Len())
	}
	if want := []string{"ClientHello", "ChangeCipherSpec", "ClientHello"}; !slices.Equal(flight.Records, want) {
		t.Errorf("records %v, want %v as Safari sends them", flight.Records, want)
	}
	if proto == ProtocolHTTP1 && second.Len() != 364 {
		t.Errorf("second ClientHello is %d bytes, Safari's is 364", second.Len())
	}
}

// safariRetryHello reports whether p is built on a hello Safari 26.3 sends,
// whose second ClientHello therefore goes out unpadded. HelloIOS_18 builds
// the HelloSafari_18 spec.
func safariRetryHello(p *fingerprint.Preset) bool {
	if fingerprint.ClientHelloSourceOf(p, "") != fingerprint.SourceClientHelloID {
		return false
	}
	return p.ClientHelloID == utls.HelloSafari_18 || p.ClientHelloID == utls.HelloIOS_18
}

// presetSpecPads reports whether the spec p's TCP connections are built from
// carries a padding extension that sizes itself.
func presetSpecPads(t *testing.T, p *fingerprint.Preset) bool {
	t.Helper()
	spec, _, err := fingerprint.ResolveClientHelloSpec(p, "", nil, false, 0)
	if err != nil {
		t.Fatalf("resolve spec: %v", err)
	}
	for _, ext := range spec.Extensions {
		if pad, ok := ext.(*utls.UtlsPaddingExtension); ok && pad.GetPaddingLen != nil {
			return true
		}
	}
	return false
}
