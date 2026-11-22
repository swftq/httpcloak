package fingerprint

import (
	"context"
	"net"
	"testing"
	"time"

	tls "github.com/sardanioss/utls"

	"github.com/sardanioss/httpcloak/internal/hrrtest"
)

// padsBeforeAndAfterRetry calls spec's padding function as utls does when it
// marshals a hello: twice for the first hello, then once more after replacing
// the key share list, as processHelloRetryRequest does before it marshals the
// retry. The length given is inside BoringPaddingStyle's window, so a padding
// function left as utls built it pads every time.
func padsBeforeAndAfterRetry(t *testing.T, spec *tls.ClientHelloSpec) (first, retry bool) {
	t.Helper()
	var pad *tls.UtlsPaddingExtension
	var keyShare *tls.KeyShareExtension
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *tls.UtlsPaddingExtension:
			pad = e
		case *tls.KeyShareExtension:
			keyShare = e
		}
	}
	if pad == nil || pad.GetPaddingLen == nil || keyShare == nil {
		t.Fatal("spec has no computed padding extension or no key_share extension")
	}
	const unpaddedLen = 364
	_, first = pad.GetPaddingLen(unpaddedLen)
	if _, again := pad.GetPaddingLen(unpaddedLen); again != first {
		t.Errorf("first hello padded=%v, then padded=%v when marshalled again", first, again)
	}
	keyShare.KeyShares = []tls.KeyShare{{Group: tls.CurveP384, Data: make([]byte, 97)}}
	_, retry = pad.GetPaddingLen(unpaddedLen)
	return first, retry
}

func TestApplyRetryHelloPaddingCoversTheSafariHellosOnly(t *testing.T) {
	for _, tc := range []struct {
		name        string
		id          tls.ClientHelloID
		retryPadded bool
	}{
		{"Safari 18", tls.HelloSafari_18, false},
		{"iOS 18", tls.HelloIOS_18, false},
		// No capture shows what iOS 17 sends after a HelloRetryRequest.
		{"iOS 14", tls.HelloIOS_14, true},
		// NSS pads the retry as it pads the first hello.
		{"Firefox 105", tls.HelloFirefox_105, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := tls.UTLSIdToSpec(tc.id)
			if err != nil {
				t.Fatal(err)
			}
			ApplyRetryHelloPadding(&spec, tc.id)
			first, retry := padsBeforeAndAfterRetry(t, &spec)
			if !first {
				t.Error("first hello not padded")
			}
			if retry != tc.retryPadded {
				t.Errorf("retry padded=%v, want %v", retry, tc.retryPadded)
			}
		})
	}
}

// TestSpecBuildersMatchTheRetryHelloPadding checks the TCP spec builders the
// transports and the pool use: a ClientHelloID source follows its browser, and
// a JA3 string, which names no browser, keeps utls's padding.
func TestSpecBuildersMatchTheRetryHelloPadding(t *testing.T) {
	const ja3WithPadding = "771,4865-4866-4867,0-10-11-13-16-43-45-51-21,29-23-24,0"
	for _, tc := range []struct {
		name        string
		build       func() (*tls.ClientHelloSpec, error)
		retryPadded bool
	}{
		{"ResolveClientHelloSpec safari-18", func() (*tls.ClientHelloSpec, error) {
			spec, _, err := ResolveClientHelloSpec(Get("safari-18"), "", nil, false, 0)
			return spec, err
		}, false},
		{"ResolveClientHelloSpec chrome-latest-ios", func() (*tls.ClientHelloSpec, error) {
			spec, _, err := ResolveClientHelloSpec(Get("chrome-latest-ios"), "", nil, false, 0)
			return spec, err
		}, false},
		{"ResolveClientHelloSpec safari-17-ios", func() (*tls.ClientHelloSpec, error) {
			spec, _, err := ResolveClientHelloSpec(Get("safari-17-ios"), "", nil, false, 0)
			return spec, err
		}, true},
		{"ResolveClientHelloSpec custom JA3 on safari-18", func() (*tls.ClientHelloSpec, error) {
			spec, _, err := ResolveClientHelloSpec(Get("safari-18"), ja3WithPadding, nil, false, 0)
			return spec, err
		}, true},
		{"SpecForWithAnchors iOS 18", func() (*tls.ClientHelloSpec, error) {
			return SpecForWithAnchors(tls.HelloIOS_18, 0, nil, nil)
		}, false},
		{"SpecForWithAnchors iOS 14", func() (*tls.ClientHelloSpec, error) {
			return SpecForWithAnchors(tls.HelloIOS_14, 0, nil, nil)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := tc.build()
			if err != nil {
				t.Fatal(err)
			}
			first, retry := padsBeforeAndAfterRetry(t, spec)
			if !first {
				t.Error("first hello not padded")
			}
			if retry != tc.retryPadded {
				t.Errorf("retry padded=%v, want %v", retry, tc.retryPadded)
			}
		})
	}
}

// TestPadFirstHelloOnlyThroughAHelloRetryRequest runs real handshakes through
// utls against a server that forces a HelloRetryRequest. It uses the iOS 14
// spec, whose first hello falls inside the padding window, unlike the Safari
// 18 spec's, so both halves show: the first hello is padded with or without
// the wrapper, and the retry is padded only without it.
func TestPadFirstHelloOnlyThroughAHelloRetryRequest(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		s := hrrtest.Start(t)
		spec, err := tls.UTLSIdToSpec(tls.HelloIOS_14)
		if err != nil {
			t.Fatal(err)
		}
		if wrapped {
			padFirstHelloOnly(spec.Extensions)
		}

		raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", s.Port()))
		if err != nil {
			t.Fatal(err)
		}
		conn := tls.UClient(raw, &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		}, tls.HelloCustom)
		if err := conn.ApplyPreset(&spec); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = conn.HandshakeContext(ctx)
		cancel()
		conn.Close()
		if err != nil {
			t.Fatalf("wrapped=%v: handshake: %v", wrapped, err)
		}

		sent := s.Sent()
		if len(sent) != 1 {
			t.Fatalf("wrapped=%v: %d connections, want 1", wrapped, len(sent))
		}
		flight, err := hrrtest.ParseFlight(sent[0])
		if err != nil {
			t.Fatalf("wrapped=%v: %v", wrapped, err)
		}
		if len(flight.Hellos) != 2 {
			t.Fatalf("wrapped=%v: %d ClientHellos, want 2: the server sent no HelloRetryRequest", wrapped, len(flight.Hellos))
		}
		first, second := flight.Hellos[0], flight.Hellos[1]
		if !first.Padded() || first.Len() != 512 {
			t.Errorf("wrapped=%v: first hello %d bytes, padded=%v; want padded to 512", wrapped, first.Len(), first.Padded())
		}
		if second.Padded() == wrapped {
			t.Errorf("wrapped=%v: retry %d bytes, padded=%v", wrapped, second.Len(), second.Padded())
		}
		if err := hrrtest.CheckRetry(first, second); err != nil {
			t.Errorf("wrapped=%v: retry: %v", wrapped, err)
		}
	}
}
