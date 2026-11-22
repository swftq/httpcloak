// Package hrrtest is a test helper for the ClientHello a client sends after a
// HelloRetryRequest. It runs an HTTPS server that sends every client through
// one, keeps what each client sent, and reads the ClientHellos back out of it.
package hrrtest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TLS extension types the tests look at.
const (
	ExtPadding  = 21
	ExtKeyShare = 51
)

// Server is an HTTPS server, HTTP/1.1 and HTTP/2, whose only key exchange
// group is P-384. A client that sends no P-384 key share in its first
// ClientHello but lists the group gets a HelloRetryRequest for it (RFC 8446
// section 4.1.4), which is every browser preset: none of them sends a P-384
// share, and all of them list P-384.
//
// Each response body says what the server negotiated, as
// "hrr=<bool> curve=<name>", for example "hrr=true curve=CurveP384".
type Server struct {
	*httptest.Server

	mu    sync.Mutex
	conns []*recordingConn
}

// Start starts a Server and closes it when t ends.
func Start(t testing.TB) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hrr=%v curve=%v", r.TLS.HelloRetryRequest, r.TLS.CurveID)
	}))
	srv.Listener = &recordingListener{Listener: ln, s: s}
	// A client that hangs up after its handshake is expected here.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{
		Certificates:     []tls.Certificate{certificate(t)},
		CurvePreferences: []tls.CurveID{tls.CurveP384},
		NextProtos:       []string{"h2", "http/1.1"},
		MinVersion:       tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.Server = srv
	return s
}

// Port is the port the server listens on, at 127.0.0.1.
func (s *Server) Port() string {
	_, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	return port
}

// Sent returns, for each connection accepted so far and in the order they
// were accepted, every byte its client sent.
func (s *Server) Sent() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.conns))
	for i, c := range s.conns {
		out[i] = c.bytes()
	}
	return out
}

type recordingConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.buf.Write(b[:n])
	c.mu.Unlock()
	return n, err
}

func (c *recordingConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.buf.Bytes())
}

type recordingListener struct {
	net.Listener
	s *Server
}

func (l *recordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	rc := &recordingConn{Conn: c}
	l.s.mu.Lock()
	l.s.conns = append(l.s.conns, rc)
	l.s.mu.Unlock()
	return rc, nil
}

func certificate(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Flight is the cleartext start of what a client sent: everything before its
// first encrypted record.
type Flight struct {
	// Records names each record in order: "ClientHello" for the record a
	// ClientHello begins in, "ChangeCipherSpec" for a change_cipher_spec.
	Records []string
	Hellos  []ClientHello
}

// ClientHello is one ClientHello as it went out.
type ClientHello struct {
	// RecordVersion is the version field of the record the message began in.
	RecordVersion uint16
	// Body is the message after its 4-byte handshake header.
	Body []byte

	LegacyVersion uint16
	Random        []byte
	SessionID     []byte
	CipherSuites  []byte
	Compression   []byte
	Extensions    []Extension
}

// Extension is one ClientHello extension, as type and body.
type Extension struct {
	Type uint16
	Data []byte
}

// KeyShare is one key_share entry: its group and the length of its key.
type KeyShare struct {
	Group  uint16
	KeyLen int
}

// ParseFlight reads the records a client sent up to its first encrypted one.
func ParseFlight(b []byte) (Flight, error) {
	var f Flight
	var hs []byte // handshake bytes not yet consumed
	var hsVers uint16
	for len(b) > 0 {
		if len(b) < 5 {
			return f, io.ErrUnexpectedEOF
		}
		typ, vers := b[0], binary.BigEndian.Uint16(b[1:3])
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			return f, io.ErrUnexpectedEOF
		}
		payload := b[5 : 5+n]
		b = b[5+n:]
		switch typ {
		case 20:
			f.Records = append(f.Records, "ChangeCipherSpec")
		case 22:
			if len(hs) == 0 {
				hsVers = vers
				f.Records = append(f.Records, "ClientHello")
			}
			hs = append(hs, payload...)
			for len(hs) >= 4 {
				mlen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
				if len(hs) < 4+mlen {
					break
				}
				if hs[0] != 1 {
					return f, fmt.Errorf("cleartext handshake message of type %d", hs[0])
				}
				h, err := parseClientHello(bytes.Clone(hs[4 : 4+mlen]))
				if err != nil {
					return f, err
				}
				h.RecordVersion = hsVers
				f.Hellos = append(f.Hellos, h)
				hs = hs[4+mlen:]
			}
		case 23:
			return f, nil
		default:
			return f, fmt.Errorf("record of type %d", typ)
		}
	}
	return f, nil
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if len(r.b) < n {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() int {
	if v := r.take(1); v != nil {
		return int(v[0])
	}
	return 0
}

func (r *reader) u16() int {
	if v := r.take(2); v != nil {
		return int(binary.BigEndian.Uint16(v))
	}
	return 0
}

func parseClientHello(body []byte) (ClientHello, error) {
	h := ClientHello{Body: body}
	r := &reader{b: body}
	h.LegacyVersion = uint16(r.u16())
	h.Random = r.take(32)
	h.SessionID = r.take(r.u8())
	h.CipherSuites = r.take(r.u16())
	h.Compression = r.take(r.u8())
	exts := &reader{b: r.take(r.u16())}
	if r.err == nil && len(r.b) != 0 {
		r.err = fmt.Errorf("%d bytes after the extensions", len(r.b))
	}
	for r.err == nil && exts.err == nil && len(exts.b) > 0 {
		typ := uint16(exts.u16())
		data := exts.take(exts.u16())
		h.Extensions = append(h.Extensions, Extension{typ, data})
	}
	if err := errors.Join(r.err, exts.err); err != nil {
		return h, fmt.Errorf("ClientHello: %w", err)
	}
	return h, nil
}

// Ext returns the extension of the given type.
func (h ClientHello) Ext(typ uint16) (Extension, bool) {
	for _, e := range h.Extensions {
		if e.Type == typ {
			return e, true
		}
	}
	return Extension{}, false
}

// Padded reports whether the hello carries a padding extension.
func (h ClientHello) Padded() bool {
	_, ok := h.Ext(ExtPadding)
	return ok
}

// Len is the length of the handshake message, its 4-byte header included.
func (h ClientHello) Len() int { return 4 + len(h.Body) }

// UnpaddedLen is Len less the padding extension, if there is one: the length
// BoringSSL, and utls's BoringPaddingStyle, decide the padding from.
func (h ClientHello) UnpaddedLen() int {
	if e, ok := h.Ext(ExtPadding); ok {
		return h.Len() - 4 - len(e.Data)
	}
	return h.Len()
}

// KeyShares reads the key_share extension.
func (h ClientHello) KeyShares() ([]KeyShare, error) {
	e, ok := h.Ext(ExtKeyShare)
	if !ok {
		return nil, errors.New("no key_share extension")
	}
	r := &reader{b: e.Data}
	list := &reader{b: r.take(r.u16())}
	var out []KeyShare
	for r.err == nil && list.err == nil && len(list.b) > 0 {
		group := uint16(list.u16())
		key := list.take(list.u16())
		out = append(out, KeyShare{group, len(key)})
	}
	return out, errors.Join(r.err, list.err)
}

// CheckRetry reports the first way second, a ClientHello sent in answer to a
// HelloRetryRequest, differs from first beyond what RFC 8446 section 4.1.2
// allows: the key_share list replaced, the padding extension added, removed
// or resized. (The other allowed changes, to early_data, cookie and
// pre_shared_key, need a HelloRetryRequest or a session these tests never
// produce.) It also checks the record version, which section 5.1 sets to
// 0x0303 for every record but an initial ClientHello.
func CheckRetry(first, second ClientHello) error {
	if second.RecordVersion != 0x0303 {
		return fmt.Errorf("record version %#04x, want 0x0303", second.RecordVersion)
	}
	switch {
	case first.LegacyVersion != second.LegacyVersion:
		return errors.New("legacy_version changed")
	case !bytes.Equal(first.Random, second.Random):
		return errors.New("random changed")
	case !bytes.Equal(first.SessionID, second.SessionID):
		return errors.New("session ID changed")
	case !bytes.Equal(first.CipherSuites, second.CipherSuites):
		return errors.New("cipher suites changed")
	case !bytes.Equal(first.Compression, second.Compression):
		return errors.New("compression methods changed")
	}
	a, b := withoutPadding(first.Extensions), withoutPadding(second.Extensions)
	if len(a) != len(b) {
		return fmt.Errorf("%d extensions, want %d (the first hello's, padding aside)", len(b), len(a))
	}
	for i := range a {
		if a[i].Type != b[i].Type {
			return fmt.Errorf("extension %d is type %d, was %d", i, b[i].Type, a[i].Type)
		}
		if a[i].Type != ExtKeyShare && !bytes.Equal(a[i].Data, b[i].Data) {
			return fmt.Errorf("extension %d changed", a[i].Type)
		}
	}
	return nil
}

func withoutPadding(exts []Extension) []Extension {
	var out []Extension
	for _, e := range exts {
		if e.Type != ExtPadding {
			out = append(out, e)
		}
	}
	return out
}
