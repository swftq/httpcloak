package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
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

// h3ClosePacket is one packet a test server received that carried a
// CONNECTION_CLOSE: its frame types in order, and a copy of the close.
type h3ClosePacket struct {
	frames []string
	close  qlog.ConnectionCloseFrame
}

// h3CloseTrace hands every received packet that carries a CONNECTION_CLOSE to
// closes. quic-go reuses frames once the event is recorded, so it copies.
type h3CloseTrace struct{ closes chan<- h3ClosePacket }

func (t *h3CloseTrace) AddProducer() qlogwriter.Recorder { return t }
func (t *h3CloseTrace) SupportsSchemas(string) bool      { return true }
func (t *h3CloseTrace) Close() error                     { return nil }

func (t *h3CloseTrace) RecordEvent(ev qlogwriter.Event) {
	p, ok := ev.(qlog.PacketReceived)
	if !ok {
		return
	}
	var cp h3ClosePacket
	found := false
	for _, f := range p.Frames {
		cp.frames = append(cp.frames, fmt.Sprintf("%T", f.Frame))
		if cc, ok := f.Frame.(*qlog.ConnectionCloseFrame); ok {
			cp.close = *cc
			found = true
		}
	}
	if found {
		select {
		case t.closes <- cp:
		default:
		}
	}
}

func h3CloseServerConfig(closes chan<- h3ClosePacket) *quic.Config {
	return &quic.Config{
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &h3CloseTrace{closes: closes}
		},
	}
}

// What a closing connection must send, by preset. Chrome 156 closed every
// session with 0x1c, NO_ERROR, frame type 0, "70:net error" on exit and when a
// browser context closed; Firefox 159 with 0x1d H3_NO_ERROR (0x100) and no
// reason. WebKit has not been captured and closes as Firefox does. Both
// browsers put an ACK in front of the close.
var h3ShutdownCloses = []struct {
	preset string
	want   qlog.ConnectionCloseFrame
}{
	{"chrome-155-windows", qlog.ConnectionCloseFrame{ErrorCode: uint64(quic.NoError), ReasonPhrase: "70:net error"}},
	{"safari-18", qlog.ConnectionCloseFrame{IsApplicationError: true, ErrorCode: uint64(http3.ErrCodeNoError)}},
	{"firefox-148-windows", qlog.ConnectionCloseFrame{IsApplicationError: true, ErrorCode: uint64(http3.ErrCodeNoError)}},
}

func checkH3ClosePacket(t *testing.T, closes <-chan h3ClosePacket, want qlog.ConnectionCloseFrame) {
	t.Helper()
	select {
	case got := <-closes:
		wantFrames := []string{fmt.Sprintf("%T", &qlog.AckFrame{}), fmt.Sprintf("%T", &qlog.ConnectionCloseFrame{})}
		if fmt.Sprint(got.frames) != fmt.Sprint(wantFrames) {
			t.Errorf("close packet frames %v, want %v", got.frames, wantFrames)
		}
		if got.close != want {
			t.Errorf("CONNECTION_CLOSE %+v, want %+v", got.close, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the server received no CONNECTION_CLOSE")
	}
}

// Every way the session ends its HTTP/3 connections sends the close the
// preset's browser sends. They all used to send CloseWithError(0, ""), an
// application close with code 0, which is not an HTTP/3 code, and no ACK.
func TestHTTP3ShutdownClosesLikeTheBrowser(t *testing.T) {
	paths := []struct {
		name  string
		close func(tr *HTTP3Transport, origin string)
	}{
		{"Close", func(tr *HTTP3Transport, _ string) { tr.Close() }},
		{"Refresh", func(tr *HTTP3Transport, _ string) { tr.Refresh() }},
		{"closeOrigin", func(tr *HTTP3Transport, origin string) { tr.closeOrigin(origin) }},
		{"closeDirectConns", func(tr *HTTP3Transport, _ string) { tr.closeDirectConns(false) }},
	}
	for _, tc := range h3ShutdownCloses {
		for _, path := range paths {
			t.Run(tc.preset+"/"+path.name, func(t *testing.T) {
				closes := make(chan h3ClosePacket, 8)
				c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				srv := &http3.Server{
					TLSConfig:  h3RaceTestTLS(t),
					QUICConfig: h3CloseServerConfig(closes),
					Handler:    shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) { w.WriteHeader(200) }),
				}
				go func() { _ = srv.Serve(c) }()
				t.Cleanup(func() { srv.Close(); c.Close() })
				time.Sleep(100 * time.Millisecond)
				origin := c.LocalAddr().String()

				tr, err := NewHTTP3Transport(fingerprint.Get(tc.preset), dns.NewCache())
				if err != nil {
					t.Fatal(err)
				}
				tr.SetInsecureSkipVerify(true)
				defer tr.Close()
				if err := h3Fetch(tr, "https://"+origin+"/"); err != nil {
					t.Fatal(err)
				}
				// By now the client has acknowledged everything, as it will
				// have when a browser closes an idle connection; the close
				// still carries an ACK.
				time.Sleep(100 * time.Millisecond)

				path.close(tr, origin)
				checkH3ClosePacket(t, closes, tc.want)
			})
		}
	}
}

// A dial that finishes after Close is ended at once, with the same close.
// Chromium's pool closes the sessions still in their handshake the same way
// as the rest when it goes away.
func TestHTTP3DialAfterCloseClosesLikeTheBrowser(t *testing.T) {
	closes := make(chan h3ClosePacket, 8)
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.Listen(c, h3RaceTestTLS(t), h3CloseServerConfig(closes))
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

	tr, err := NewHTTP3Transport(fingerprint.Get("chrome-155-windows"), dns.NewCache())
	if err != nil {
		t.Fatal(err)
	}
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()
	tr.closeDirectConns(true) // what Close does to refuse later dials

	// The configs a raced attempt gets, as dialQUIC and raceQUICDialWithECH
	// build them.
	tlsCfg := tr.tlsConfig.Clone()
	tlsCfg.ServerName = "localhost"
	cfg := tr.quicConfig.Clone()
	cfg.CachedClientHelloSpec = tr.getSpecForHost("localhost")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := tr.dialDirect(ctx, c.LocalAddr().(*net.UDPAddr), tlsCfg, cfg); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after Close: %v, want net.ErrClosed", err)
	}
	select {
	case got := <-closes:
		if want := (qlog.ConnectionCloseFrame{ErrorCode: uint64(quic.NoError), ReasonPhrase: "70:net error"}); got.close != want {
			t.Errorf("CONNECTION_CLOSE %+v, want %+v", got.close, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the server received no CONNECTION_CLOSE")
	}
}
