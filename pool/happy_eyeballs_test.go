package pool

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// TestHappyEyeballsFallbackStartsAtOnceWithNoPreferredDial: the preferred
// family's 250ms head start is over a preferred dial in flight. With none in
// flight there is nothing to wait for, but a host with no address of the
// preferred family (IPv6 by default, so any IPv4-only host) sat out the whole
// timer anyway, and every new client.Client HTTP/2 connection to it was 250ms
// late.
func TestHappyEyeballsFallbackStartsAtOnceWithNoPreferredDial(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	p := &HostPool{
		port:   strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		preset: fingerprint.Get("chrome-latest"),
	}
	loopback := []net.IP{net.IPv4(127, 0, 0, 1)}
	// TCP cannot connect to a multicast address, so the OS fails these dials
	// at once without sending anything.
	unreachableV6 := []net.IP{net.ParseIP("ff02::1"), net.ParseIP("ff02::2")}
	unreachableV4 := []net.IP{net.IPv4(224, 0, 0, 1)}

	for _, tt := range []struct {
		name      string
		preferred []net.IP
		fallback  []net.IP
		wantErr   bool
	}{
		{name: "no preferred address", fallback: loopback},
		{name: "every preferred dial fails", preferred: unreachableV6, fallback: loopback},
		{name: "every dial fails", preferred: unreachableV6, fallback: unreachableV4, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			start := time.Now()
			conn, err := p.dialHappyEyeballs(ctx, tt.preferred, tt.fallback)
			elapsed := time.Since(start)
			if tt.wantErr {
				if err == nil {
					conn.Close()
					t.Fatalf("connected to %v, want an error", conn.RemoteAddr())
				}
			} else {
				if err != nil {
					t.Fatalf("dialHappyEyeballs: %v", err)
				}
				remote := conn.RemoteAddr().String()
				conn.Close()
				if remote != ln.Addr().String() {
					t.Fatalf("connected to %s, want %s", remote, ln.Addr())
				}
			}
			// A loopback connect takes well under a millisecond, so a dial
			// anywhere near 250ms sat out the head start.
			if elapsed > 100*time.Millisecond {
				t.Fatalf("returned after %v, want the fallback dialed at once", elapsed.Round(time.Millisecond))
			}
		})
	}
}
