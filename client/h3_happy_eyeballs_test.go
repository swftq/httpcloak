package client

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/dns"
)

// TestHTTP3DialRacesAddressFamilies requests a server that listens on
// 127.0.0.1 only as localhost, which resolves to ::1 and 127.0.0.1. The HTTP/3
// pool used to dial a host's addresses one after another, and a QUIC attempt to
// an address nothing answers on does not fail: UDP reports no error, so the ::1
// attempt ran out quic-go's 5 s handshake idle timeout before 127.0.0.1 was
// tried. Raced, as the Session's HTTP/3 dial is, 127.0.0.1 starts 250 ms after
// ::1.
func TestHTTP3DialRacesAddressFamilies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Both families have to be in play or the test proves nothing: with no ::1
	// in the answer there is nothing to wait out, and with no IPv6 loopback the
	// ::1 attempt fails at once. Resolved through the cache the client uses.
	ipv6, ipv4, err := dns.NewCache().ResolveIPv6First(ctx, "localhost")
	if err != nil {
		t.Skipf("resolving localhost: %v", err)
	}
	if !containsIP(ipv6, net.IPv6loopback) || !containsIP(ipv4, net.IPv4(127, 0, 0, 1)) {
		t.Skipf("localhost resolves to %v and %v here, want ::1 and 127.0.0.1", ipv6, ipv4)
	}
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	probe.Close()

	server, err := url.Parse(gzipH3Server(t, []byte("ok")))
	if err != nil {
		t.Fatal(err)
	}
	target := "https://localhost:" + server.Port() + "/"

	c := NewClient("chrome-latest",
		WithForceHTTP3(),
		WithInsecureSkipVerify(),
		WithTimeout(30*time.Second),
	)
	defer c.Close()

	start := time.Now()
	resp, err := c.Do(ctx, &Request{Method: http.MethodGet, URL: target})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, err := resp.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if string(body) != "ok" || resp.Protocol != "h3" {
		t.Fatalf("got %q over %q, want \"ok\" over h3", body, resp.Protocol)
	}
	t.Logf("first request took %v", elapsed)
	if elapsed > 2*time.Second {
		t.Fatalf("first request took %v: 127.0.0.1 was not tried until the ::1 attempt timed out", elapsed)
	}
}

func containsIP(ips []net.IP, want net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(want) {
			return true
		}
	}
	return false
}
