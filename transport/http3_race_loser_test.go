package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/quic-go"
)

// A Happy Eyeballs attempt that finishes its handshake after another attempt
// has won is dropped without a word to its server. It used to be closed with
// CloseWithError(0, "lost happy-eyeballs race"), so the server received an
// application CONNECTION_CLOSE carrying a phrase no browser sends. Chromium
// closes a QUIC session it no longer needs with SILENT_CLOSE. Whether a loser
// completes at all is down to timing, so the race's drop is applied here to a
// connection that has completed its handshake, and the server is asked what
// reached it.
func TestHTTP3RaceLoserClosesSilently(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.Listen(c, h3RaceTestTLS(t), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); c.Close() })

	tr, err := NewHTTP3Transport(fingerprint.Get("chrome-155-windows"), dns.NewCache())
	if err != nil {
		t.Fatal(err)
	}
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	// The configs a raced attempt gets, as dialQUIC and raceQUICDialWithECH
	// build them.
	tlsCfg := tr.tlsConfig.Clone()
	tlsCfg.ServerName = "localhost"
	cfg := tr.quicConfig.Clone()
	cfg.CachedClientHelloSpec = tr.getSpecForHost("localhost")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.dialDirect(ctx, c.LocalAddr().(*net.UDPAddr), tlsCfg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}

	tr.dropDirectConn(conn)

	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the dropped connection is still open")
	}
	if n := tr.liveSockets(); n != 0 {
		t.Errorf("%d sockets left after the drop, want 0", n)
	}
	// A CONNECTION_CLOSE ends the server's side within a round trip, with
	// what the client sent as the cause. Silence leaves it open until its
	// idle timeout.
	select {
	case <-server.Context().Done():
		t.Errorf("the server's side ended: %v; the client must not send CONNECTION_CLOSE", context.Cause(server.Context()))
	case <-time.After(300 * time.Millisecond):
	}
}
