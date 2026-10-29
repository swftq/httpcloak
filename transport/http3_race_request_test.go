package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	shttp "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	"github.com/sardanioss/quic-go/qlog"
	"github.com/sardanioss/quic-go/qlogwriter"
)

// quicServerLog is a server's record of the QUIC connections clients opened
// to it and of every CONNECTION_CLOSE frame it received on them.
type quicServerLog struct {
	mu     sync.Mutex
	conns  int
	closes []string
}

func (l *quicServerLog) tracer(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	l.mu.Lock()
	l.conns++
	l.mu.Unlock()
	return quicServerTrace{l}
}

func (l *quicServerLog) snapshot() (conns int, closes []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conns, append([]string(nil), l.closes...)
}

type quicServerTrace struct{ l *quicServerLog }

func (tr quicServerTrace) AddProducer() qlogwriter.Recorder { return tr }
func (tr quicServerTrace) SupportsSchemas(string) bool      { return false }
func (tr quicServerTrace) Close() error                     { return nil }

func (tr quicServerTrace) RecordEvent(e qlogwriter.Event) {
	p, ok := e.(qlog.PacketReceived)
	if !ok {
		return
	}
	for _, f := range p.Frames {
		if cc, ok := f.Frame.(*qlog.ConnectionCloseFrame); ok {
			tr.l.mu.Lock()
			tr.l.closes = append(tr.l.closes, fmt.Sprintf("%s packet: application=%v code=0x%x reason=%q",
				p.Header.PacketType, cc.IsApplicationError, cc.ErrorCode, cc.ReasonPhrase))
			tr.l.mu.Unlock()
		}
	}
}

// The first request to a host in auto mode races HTTP/3 against HTTP/2, and
// when HTTP/3 wins, the request goes out on the QUIC connection the race made,
// as Chrome sends a request on the session its QUIC job made. The race used to
// dial a connection of its own and close it once connected, with
// CloseWithError(0, "connect probe"), and the request then dialed a second
// one. The server saw two handshakes for one request. The first ended with an
// application CONNECTION_CLOSE carrying that phrase, or, when the close went
// out before the handshake was confirmed, with a transport APPLICATION_ERROR
// in an Initial packet.
//
// The origin serves HTTP/3 on UDP and HTTP/2 over TLS on TCP, on one port, and
// holds its TLS handshake so that HTTP/3 wins.
func TestAutoRaceSendsRequestOnRacedConnection(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tcp.Addr().(*net.TCPAddr).Port
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		tcp.Close()
		t.Skipf("UDP port %d is taken: %v", port, err)
	}

	log := &quicServerLog{}
	h3srv := &http3.Server{
		TLSConfig:  h3RaceTestTLS(t),
		QUICConfig: &quic.Config{Tracer: log.tracer},
		Handler: shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
			w.WriteHeader(200)
		}),
	}
	go func() { _ = h3srv.Serve(udp) }()
	t.Cleanup(func() { h3srv.Close(); udp.Close() })

	h2srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusOK)
	}))
	h2srv.Listener.Close()
	h2srv.Listener = tcp
	h2srv.EnableHTTP2 = true
	h2srv.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		time.Sleep(300 * time.Millisecond)
		return nil, nil
	}}
	h2srv.StartTLS()
	t.Cleanup(h2srv.Close)

	tr := autoTransport(t, "chrome-155-windows")
	resp := doGet(t, tr, fmt.Sprintf("https://127.0.0.1:%d/", port))
	if resp.Protocol != "h3" {
		t.Fatalf("served over %q, want h3: the TCP handshake was held so that HTTP/3 would win", resp.Protocol)
	}

	// Long enough for a close sent as the race ended to arrive.
	time.Sleep(200 * time.Millisecond)
	conns, closes := log.snapshot()
	if conns != 1 {
		t.Errorf("the server saw %d QUIC connections for one request, want 1: the request must go out on the connection the race made", conns)
	}
	if len(closes) > 0 {
		t.Errorf("the server received %q before the transport closed; nothing may close the raced connection", closes)
	}
}

// h3ListenerWithLog starts a QUIC listener whose server records what reaches
// it, and accepts its connections so the accept queue never fills.
func h3ListenerWithLog(t *testing.T) (port string, log *quicServerLog) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	log = &quicServerLog{}
	ln, err := quic.Listen(c, h3RaceTestTLS(t), &quic.Config{Tracer: log.tracer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); c.Close() })
	go func() {
		for {
			if _, err := ln.Accept(context.Background()); err != nil {
				return
			}
		}
	}()
	return strconv.Itoa(c.LocalAddr().(*net.UDPAddr).Port), log
}

// A connection from the race that the request does not go out on is dropped
// without a word to the server, the way Chromium drops a QUIC session it no
// longer needs (SILENT_CLOSE): when HTTP/3 lost and its attempt connected
// before the race was decided or after it, and when HTTP/3 won but the
// request went out on a connection the transport already had. Whether an
// attempt that loses still completes is down to timing, so each case drives
// the race's HTTP/3 side directly.
func TestHTTP3RaceDropsUnusedConnectionSilently(t *testing.T) {
	cases := []struct {
		name string
		// run plays the race and returns the client connection it dropped,
		// or nil when the drop happened out of the test's sight.
		run func(t *testing.T, ctx context.Context, tr *HTTP3Transport, r *h3Race) *quic.Conn
	}{
		{"connected, then lost", func(t *testing.T, ctx context.Context, tr *HTTP3Transport, r *h3Race) *quic.Conn {
			if err := r.connect(ctx); err != nil {
				t.Fatal(err)
			}
			conn := r.conn
			r.lose()
			return conn
		}},
		{"lost, then connected", func(t *testing.T, ctx context.Context, tr *HTTP3Transport, r *h3Race) *quic.Conn {
			r.lose()
			if err := r.connect(ctx); err != errRaceDecided {
				t.Fatalf("connect after the race was decided returned %v, want errRaceDecided", err)
			}
			return nil
		}},
		{"won, request went elsewhere", func(t *testing.T, ctx context.Context, tr *HTTP3Transport, r *h3Race) *quic.Conn {
			if err := r.connect(ctx); err != nil {
				t.Fatal(err)
			}
			conn := r.conn
			release := r.won()
			release()
			return conn
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port, log := h3ListenerWithLog(t)
			tr, err := NewHTTP3Transport(fingerprint.Get("chrome-155-windows"), dns.NewCache())
			if err != nil {
				t.Fatal(err)
			}
			tr.SetInsecureSkipVerify(true)
			defer tr.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if conn := tc.run(t, ctx, tr, tr.newRace("127.0.0.1", port)); conn != nil {
				select {
				case <-conn.Context().Done():
				case <-time.After(5 * time.Second):
					t.Fatal("the dropped connection is still open")
				}
			}
			if n := tr.liveSockets(); n != 0 {
				t.Errorf("%d sockets left after the drop, want 0", n)
			}
			// A CONNECTION_CLOSE would arrive within a round trip.
			time.Sleep(300 * time.Millisecond)
			if conns, closes := log.snapshot(); conns != 1 || len(closes) > 0 {
				t.Errorf("the server saw %d connections and received %q; want 1 and no CONNECTION_CLOSE", conns, closes)
			}
		})
	}
}

// Connect keeps its connection for the next request to the origin, as
// HTTP2Transport.Connect keeps its connection in the pool. It used to close
// the connection again with CloseWithError(0, "connect probe"), leaving the
// request to open another.
func TestHTTP3ConnectKeepsConnectionForRequest(t *testing.T) {
	log := &quicServerLog{}
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		TLSConfig:  h3RaceTestTLS(t),
		QUICConfig: &quic.Config{Tracer: log.tracer},
		Handler: shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
			w.WriteHeader(200)
		}),
	}
	go func() { _ = srv.Serve(c) }()
	t.Cleanup(func() { srv.Close(); c.Close() })
	port := strconv.Itoa(c.LocalAddr().(*net.UDPAddr).Port)

	tr, err := NewHTTP3Transport(fingerprint.Get("chrome-155-windows"), dns.NewCache())
	if err != nil {
		t.Fatal(err)
	}
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tr.Connect(ctx, "127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	if err := h3Fetch(tr, "https://127.0.0.1:"+port+"/"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if conns, closes := log.snapshot(); conns != 1 || len(closes) > 0 {
		t.Errorf("the server saw %d connections and received %q; want 1 and no CONNECTION_CLOSE", conns, closes)
	}
}
