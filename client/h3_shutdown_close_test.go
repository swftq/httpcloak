package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	fhttp "github.com/sardanioss/http"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	"github.com/sardanioss/quic-go/qlog"
	"github.com/sardanioss/quic-go/qlogwriter"
)

// poolClosePacket is one packet the test server received that carried a
// CONNECTION_CLOSE: its frame types in order, and a copy of the close.
type poolClosePacket struct {
	frames []string
	close  qlog.ConnectionCloseFrame
}

// poolCloseTrace hands every received packet that carries a CONNECTION_CLOSE
// to closes. quic-go reuses frames once the event is recorded, so it copies.
type poolCloseTrace struct{ closes chan<- poolClosePacket }

func (t *poolCloseTrace) AddProducer() qlogwriter.Recorder { return t }
func (t *poolCloseTrace) SupportsSchemas(string) bool      { return true }
func (t *poolCloseTrace) Close() error                     { return nil }

func (t *poolCloseTrace) RecordEvent(ev qlogwriter.Event) {
	p, ok := ev.(qlog.PacketReceived)
	if !ok {
		return
	}
	var cp poolClosePacket
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

// client.Client's HTTP/3 pool closes its connections the way the preset's
// browser does: Chrome 156 sent 0x1c, NO_ERROR, frame type 0, "70:net error",
// and Firefox 159 0x1d H3_NO_ERROR with no reason, each after an ACK in the
// same packet. WebKit presets close as Firefox does. The pool used to send
// CloseWithError(0, "") through http3.Transport.Close; the "closing" phrase in
// QUICConn.Close was never reached.
func TestHTTP3PoolClosesLikeTheBrowser(t *testing.T) {
	chrome := qlog.ConnectionCloseFrame{ErrorCode: uint64(quic.NoError), ReasonPhrase: "70:net error"}
	h3NoError := qlog.ConnectionCloseFrame{IsApplicationError: true, ErrorCode: uint64(http3.ErrCodeNoError)}
	for _, tc := range []struct {
		preset string
		want   qlog.ConnectionCloseFrame
	}{
		{"chrome-155-windows", chrome},
		{"safari-18", h3NoError},
	} {
		for _, path := range []struct {
			name  string
			close func(*Client)
		}{
			{"Close", (*Client).Close},
			{"CloseQUICConnections", (*Client).CloseQUICConnections},
		} {
			t.Run(tc.preset+"/"+path.name, func(t *testing.T) {
				closes := make(chan poolClosePacket, 8)
				udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				srv := &http3.Server{
					TLSConfig: h3GzipTestTLS(t),
					QUICConfig: &quic.Config{
						Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
							return &poolCloseTrace{closes: closes}
						},
					},
					Handler: fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) { w.WriteHeader(200) }),
				}
				go func() { _ = srv.Serve(udpConn) }()
				t.Cleanup(func() { srv.Close(); udpConn.Close() })
				time.Sleep(100 * time.Millisecond)

				c := NewClient(tc.preset, WithForceHTTP3(), WithInsecureSkipVerify(), WithoutRetry())
				defer c.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				resp, err := c.Get(ctx, "https://"+udpConn.LocalAddr().String()+"/", nil)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.Protocol != "h3" {
					t.Fatalf("protocol %q, want h3", resp.Protocol)
				}
				// By now the client has acknowledged everything; the close
				// still carries an ACK.
				time.Sleep(100 * time.Millisecond)

				path.close(c)
				select {
				case got := <-closes:
					wantFrames := []string{fmt.Sprintf("%T", &qlog.AckFrame{}), fmt.Sprintf("%T", &qlog.ConnectionCloseFrame{})}
					if fmt.Sprint(got.frames) != fmt.Sprint(wantFrames) {
						t.Errorf("close packet frames %v, want %v", got.frames, wantFrames)
					}
					if got.close != tc.want {
						t.Errorf("CONNECTION_CLOSE %+v, want %+v", got.close, tc.want)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("the server received no CONNECTION_CLOSE")
				}
			})
		}
	}
}
