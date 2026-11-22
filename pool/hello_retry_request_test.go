package pool

import (
	"context"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/hrrtest"
)

// TestPoolSecondClientHelloAfterHelloRetryRequest dials through the pool that
// client.Client uses, which builds its specs itself (tcpClientHelloSpec), to
// a server that answers the first ClientHello with a HelloRetryRequest. The
// transport package's TestSecondClientHelloAfterHelloRetryRequest covers every
// preset this way and says what each should send; this checks the pool takes
// the same path, on a preset from each family.
func TestPoolSecondClientHelloAfterHelloRetryRequest(t *testing.T) {
	for _, tc := range []struct {
		preset      string
		retryPadded bool
	}{
		{"safari-18", false},
		{"safari-26-ios", false},
		{"chrome-latest-ios", false},
		// The iOS 14 hello keeps utls's padding: no capture shows iOS 17's.
		{"safari-17-ios", true},
		{"chrome-latest", false},
		{"firefox-latest", false},
	} {
		t.Run(tc.preset, func(t *testing.T) {
			s := hrrtest.Start(t)
			m := NewManagerWithTLSConfig(fingerprint.Get(tc.preset), true)
			t.Cleanup(m.Close)
			hp, err := m.GetPool("127.0.0.1", s.Port())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := hp.GetConn(ctx); err != nil {
				t.Fatalf("connect: %v", err)
			}

			sent := s.Sent()
			if len(sent) != 1 {
				t.Fatalf("%d connections, want 1", len(sent))
			}
			flight, err := hrrtest.ParseFlight(sent[0])
			if err != nil {
				t.Fatal(err)
			}
			if len(flight.Hellos) != 2 {
				t.Fatalf("%d ClientHellos, want 2: the server sent no HelloRetryRequest", len(flight.Hellos))
			}
			first, second := flight.Hellos[0], flight.Hellos[1]
			if err := hrrtest.CheckRetry(first, second); err != nil {
				t.Errorf("second ClientHello: %v", err)
			}
			if second.Padded() != tc.retryPadded {
				t.Errorf("second ClientHello (%d bytes) padded=%v, want %v", second.Len(), second.Padded(), tc.retryPadded)
			}
		})
	}
}
