package transport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	utls "github.com/sardanioss/utls"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// Safari 26.3's QUIC Initial packets, through a real send.
//
// The wire snapshot sends to an IP literal, so its hellos carry no SNI, and it
// records the ClientHello but not the packets that carry it. This test sends
// each WebKit HTTP/3 preset to localhost, as the Safari capture did, decrypts
// the first two Initial packets and compares them with the browser's: Safari
// 26.3 on macOS 26.3, run-20261121-225724, lo0.pcap packets 34075 and 34076
// (h3.log:4-15).
//
// The browser sent, in two 1200-byte datagrams 25 microseconds apart:
//
//	pn 0 (1 byte): CRYPTO 0+999, PADDING 162
//	pn 1 (1 byte): CRYPTO 999+483, PADDING 677
//
// with an 8-byte destination connection ID, an empty source connection ID and
// no token. The ClientHello was 1482 bytes, and its quic_transport_parameters
// were these 43 bytes.
const safari26TransportParameters = "0901080e0240400f00040481000000050480200000060480200000070480200000c0000000ff0808080107"

var safari26Initials = []string{
	"datagram 1200: dcid 8, scid 0, token 0, pn 0 (1-byte): CRYPTO 0+999, PADDING 162",
	"datagram 1200: dcid 8, scid 0, token 0, pn 1 (1-byte): CRYPTO 999+483, PADDING 677",
}

func TestWebKitQUICInitialMatchesSafari26(t *testing.T) {
	if testing.Short() {
		t.Skip("sends real HTTP/3 handshakes")
	}
	var names []string
	for _, name := range fingerprint.Available() {
		p := fingerprint.Get(name)
		if p != nil && p.SupportHTTP3 && p.QUICClientHelloID == utls.HelloIOS_18_QUIC {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, must := range []string{"safari-latest", "safari-18-ios", "chrome-143-ios", "chrome-latest-ios"} {
		if !contains(names, must) {
			t.Fatalf("%s is not among the WebKit HTTP/3 presets %v", must, names)
		}
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			pkts, hello := firstInitials(t, name)
			if got, want := strings.Join(pkts, "\n"), strings.Join(safari26Initials, "\n"); got != want {
				t.Errorf("Initial packets:\n%s\nSafari 26.3 sent:\n%s", got, want)
			}
			if len(hello) != 1482 {
				t.Errorf("ClientHello is %d bytes; Safari's was 1482", len(hello))
			}
			ext, order := helloExtension(t, hello, 57)
			if got := hex.EncodeToString(ext); got != safari26TransportParameters {
				t.Errorf("quic_transport_parameters:\n got %s\nwant %s", got, safari26TransportParameters)
			}
			if got := strings.Join(order, ","); got != "GREASE,0,10,16,5,13,18,51,45,43,57,27,GREASE" {
				t.Errorf("extension order %s", got)
			}
		})
	}
}

// firstInitials sends one HTTP/3 request to localhost, to a socket that never
// answers, and returns the first two datagrams as Initial packets the way a
// server decrypts them, with the ClientHello they carry.
func firstInitials(t *testing.T, name string) ([]string, []byte) {
	t.Helper()
	// localhost may resolve to either family; listen on both.
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	tr := NewTransport(name)
	tr.SetProtocol(ProtocolHTTP3)
	tr.SetInsecureSkipVerify(true)
	tr.SetDisableECH(true)
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.Do(ctx, &Request{Method: "GET", URL: "https://localhost:" + portOf(pc.LocalAddr()) + "/"})
	}()
	defer func() { cancel(); <-done }()

	var out []string
	crypto := map[uint64][]byte{}
	var origDCID []byte
	buf := make([]byte, 65536)
	pc.SetReadDeadline(time.Now().Add(10 * time.Second))
	for len(out) < 2 {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("reading datagram %d: %v", len(out)+1, err)
		}
		d := append([]byte(nil), buf[:n]...)
		if d[0]&0xf0 != 0xc0 {
			t.Fatalf("datagram %d is not an Initial packet: first byte %#x", len(out)+1, d[0])
		}
		p := 5
		dcid := d[p+1 : p+1+int(d[p])]
		if origDCID == nil {
			origDCID = append([]byte(nil), dcid...)
		}
		p += 1 + int(d[p])
		scidLen := int(d[p])
		p += 1 + scidLen
		tokenLen, k := quicVarint(d[p:])
		p += k + int(tokenLen)
		length, k := quicVarint(d[p:])
		p += k
		if p+int(length) != n {
			t.Fatalf("datagram %d holds %d bytes past one Initial packet", len(out)+1, n-p-int(length))
		}

		// The keys come from the first destination connection ID.
		key, iv, hp := quicClientInitialKeys(origDCID)
		hb, _ := aes.NewCipher(hp)
		var mask [16]byte
		hb.Encrypt(mask[:], d[p+4:p+20])
		d[0] ^= mask[0] & 0x0f
		pnLen := int(d[0]&0x3) + 1
		var pn uint64
		for i := 0; i < pnLen; i++ {
			d[p+i] ^= mask[1+i]
			pn = pn<<8 | uint64(d[p+i])
		}
		nonce := append([]byte(nil), iv...)
		var pnb [8]byte
		binary.BigEndian.PutUint64(pnb[:], pn)
		for i := range pnb {
			nonce[len(nonce)-8+i] ^= pnb[i]
		}
		block, _ := aes.NewCipher(key)
		aead, _ := cipher.NewGCM(block)
		plain, err := aead.Open(nil, nonce, d[p+pnLen:n], d[:p+pnLen])
		if err != nil {
			t.Fatalf("datagram %d: %v", len(out)+1, err)
		}

		var frames []string
		for len(plain) > 0 {
			switch plain[0] {
			case 0x00:
				z := 0
				for z < len(plain) && plain[z] == 0 {
					z++
				}
				frames = append(frames, fmt.Sprintf("PADDING %d", z))
				plain = plain[z:]
			case 0x01:
				frames = append(frames, "PING")
				plain = plain[1:]
			case 0x06:
				q := 1
				off, m := quicVarint(plain[q:])
				q += m
				l, m := quicVarint(plain[q:])
				q += m
				frames = append(frames, fmt.Sprintf("CRYPTO %d+%d", off, l))
				crypto[off] = append([]byte(nil), plain[q:q+int(l)]...)
				plain = plain[q+int(l):]
			default:
				t.Fatalf("datagram %d: unexpected frame %#x", len(out)+1, plain[0])
			}
		}
		out = append(out, fmt.Sprintf("datagram %d: dcid %d, scid %d, token %d, pn %d (%d-byte): %s",
			n, len(dcid), scidLen, tokenLen, pn, pnLen, strings.Join(frames, ", ")))
	}
	return out, contiguous(crypto)
}

// helloExtension returns one extension's body from a ClientHello handshake
// message, and the extension order.
func helloExtension(t *testing.T, hello []byte, id uint16) ([]byte, []string) {
	t.Helper()
	if len(hello) < 4 {
		t.Fatal("no ClientHello")
	}
	r := &byteReader{b: hello[4:]}
	r.skip(2 + 32)
	r.bytes8()  // session_id
	r.bytes16() // cipher_suites
	r.bytes8()  // compression
	exts := &byteReader{b: r.bytes16()}
	var body []byte
	var order []string
	for len(exts.b) > 0 && exts.err == nil {
		eid := exts.u16()
		data := exts.bytes16()
		order = append(order, u16Name(eid))
		if eid == id {
			body = data
		}
	}
	if r.err != nil || exts.err != nil {
		t.Fatalf("ClientHello: %v %v", r.err, exts.err)
	}
	return body, order
}
