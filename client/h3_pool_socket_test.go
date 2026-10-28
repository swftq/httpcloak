package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	fhttp "github.com/sardanioss/http"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
)

// TestHTTP3PoolClosesSocketWithConnection checks that the UDP socket an HTTP/3
// connection was dialled on is closed once the connection ends, whichever side
// ends it. The pool opens a socket and a quic.Transport for every connection,
// and quic.Transport.Close leaves a socket it was handed open. Nothing closed
// the winning attempt's socket, so it stayed bound after its connection was
// gone, and after Client.Close.
func TestHTTP3PoolClosesSocketWithConnection(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(*Client, *http3.Server)
		// The client ends the connection, so its CONNECTION_CLOSE has to reach
		// the server before the socket goes.
		clientCloses bool
	}{
		{"client closes", func(c *Client, _ *http3.Server) { c.Close() }, true},
		// Server.Close sends CONNECTION_CLOSE, so the client's connection ends
		// while the client and its pool stay open.
		{"server closes", func(_ *Client, srv *http3.Server) { srv.Close() }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			conns := make(chan *quic.Conn, 1)
			srv := &http3.Server{
				TLSConfig: h3GzipTestTLS(t),
				ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
					select {
					case conns <- c:
					default:
					}
					return ctx
				},
				Handler: fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) {
					w.Write([]byte("ok"))
				}),
			}
			go srv.Serve(udpConn)
			t.Cleanup(func() { srv.Close(); udpConn.Close() })

			c := NewClient("chrome-latest",
				WithForceHTTP3(),
				WithInsecureSkipVerify(),
				WithTimeout(30*time.Second),
			)
			defer c.Close()

			resp, err := c.Do(ctx, &Request{Method: http.MethodGet, URL: "https://" + udpConn.LocalAddr().String() + "/"})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if _, err := resp.Bytes(); err != nil {
				t.Fatalf("Bytes: %v", err)
			}
			if resp.Protocol != "h3" {
				t.Fatalf("protocol = %q, want h3", resp.Protocol)
			}
			serverConn := <-conns
			remote, err := netip.ParseAddrPort(serverConn.RemoteAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			port := int(remote.Port())

			// The check is a bind of the address the client's socket holds,
			// which fails for as long as that socket is open. It has to fail
			// now, or a pass below proves nothing.
			if err := bindUDP4(port); err == nil {
				t.Fatalf("bound UDP port %d while the connection on it was open", port)
			}

			tc.end(c, srv)

			deadline := time.Now().Add(2 * time.Second)
			for {
				err := bindUDP4(port)
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("UDP port %d still bound 2s after its connection ended: %v", port, err)
				}
				time.Sleep(10 * time.Millisecond)
			}

			if !tc.clientCloses {
				return
			}
			// Ended by the client's CONNECTION_CLOSE, not left to run out the
			// server's idle timeout.
			select {
			case <-serverConn.Context().Done():
			case <-time.After(2 * time.Second):
				t.Fatal("the server's connection was still open 2s after the client closed it")
			}
			var appErr *quic.ApplicationError
			if cause := context.Cause(serverConn.Context()); !errors.As(cause, &appErr) || !appErr.Remote {
				t.Fatalf("the server's connection ended with %v, want the client's CONNECTION_CLOSE", cause)
			}
		})
	}
}

// bindUDP4 binds port on every IPv4 address, as the pool's sockets are bound,
// and closes it again.
func bindUDP4(port int) error {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return err
	}
	return c.Close()
}
