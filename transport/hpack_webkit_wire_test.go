package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/net/http2/hpack"
	"github.com/sardanioss/qpack"
	"github.com/sardanioss/quic-go"
	utls "github.com/sardanioss/utls"
)

// Wire locks on the header encoding of the presets on WebKit 26's network
// stack (webKit26Presets).
//
// Safari 26.3 on macOS 26.3, captured at a local TLS server that logged every
// HTTP/2 header block before decoding it: 189 HEADERS on four connections,
// 153 ordinary requests and 36 extended CONNECTs.
//   - Every cookie went out as a field of its own, a literal never indexed on
//     name 32 (1f 11), the fields contiguous and last: 1059 of them, none
//     holding a ';'.
//   - :path was a literal without indexing on name 4 (04) on 149 of the 153
//     ordinary requests. The other four were ":path: /", static entry 4 (84).
//   - content-length was a literal without indexing on name 28 (0f 0d), 122
//     times out of 122.
//   - Every other field was incremental or indexed, :authority included, and
//     so were the CONNECTs' :method and :protocol.
//
// The presets get there through the chrome policy plus four
// hpack_representation entries. Re-encoding the captured fields that way
// through the fork's encoder gives Safari's 189 blocks byte for byte. These
// tests assert the representations through a real send instead of replaying
// those bytes.

// hpackField is one field of a captured header block: what a decoder made of
// it, and the instruction that carried it.
type hpackField struct {
	Name, Value string
	In          hpackInstr
}

// hpackFields decodes the blocks of one connection in order on one decoder,
// as the server's own decoder does, and pairs each field with its instruction.
func hpackFields(t *testing.T, blocks [][]byte) [][]hpackField {
	t.Helper()
	dec := hpack.NewDecoder(4096, nil)
	out := make([][]hpackField, len(blocks))
	for i, b := range blocks {
		fields, err := dec.DecodeFull(b)
		if err != nil {
			t.Fatalf("block %d: %v", i+1, err)
		}
		var ins []hpackInstr
		for _, in := range parseHPACK(t, b) {
			if in.Kind != "TABLE_SIZE_UPDATE" {
				ins = append(ins, in)
			}
		}
		if len(ins) != len(fields) {
			t.Fatalf("block %d: %d instructions for %d fields", i+1, len(ins), len(fields))
		}
		for j, f := range fields {
			out[i] = append(out[i], hpackField{Name: f.Name, Value: f.Value, In: ins[j]})
		}
	}
	return out
}

func hpackFieldNamed(block []hpackField, name string) (hpackField, bool) {
	for _, f := range block {
		if f.Name == name {
			return f, true
		}
	}
	return hpackField{}, false
}

// hpackRep is an expected representation. index 0 stands for any entry of the
// dynamic table, and a nil prefix is not checked.
type hpackRep struct {
	kind   string
	index  uint64
	prefix []byte
}

func (r hpackRep) matches(in hpackInstr) bool {
	if in.Kind != r.kind {
		return false
	}
	if r.index == 0 {
		return in.NameIndex >= 62
	}
	return in.NameIndex == r.index && (r.prefix == nil || bytes.Equal(in.Prefix, r.prefix))
}

func (r hpackRep) String() string {
	idx := fmt.Sprint(r.index)
	if r.index == 0 {
		idx = "62+"
	}
	if r.prefix == nil {
		return r.kind + " " + idx
	}
	return fmt.Sprintf("%s %s (% x)", r.kind, idx, r.prefix)
}

func instrString(in hpackInstr) string {
	return fmt.Sprintf("%s %d (% x)", in.Kind, in.NameIndex, in.Prefix)
}

// shortValues shortens long values for a failure message.
func shortValues(vals []string) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		if len(v) > 16 {
			v = fmt.Sprintf("%s...(%d bytes)", v[:16], len(v))
		}
		out[i] = v
	}
	return out
}

// One field per cookie, each never indexed, on every request. A never-indexed
// field is never inserted, so the whole jar goes out again each time, where
// chrome-latest sends it once and then one byte a crumb
// (TestHPACKCookieCrumbsAreIndexed). Safari sent 1f 11 on every one of its
// 1059 cookie fields, five or six to a request, but each was 11 to 14 bytes:
// no capture shows it with crumbs as long as sid and tok here. Firefox 159 and
// nghttp2 never-index only crumbs under 20 bytes, and would index these two.
func TestHPACKWebKitCookieCrumbsNeverIndexed(t *testing.T) {
	sid, tok := "sid="+strings.Repeat("A", 480), "tok="+strings.Repeat("B", 150)
	jar := "alpha=one; beta=two; " + sid + "; " + tok
	crumbs := []string{"alpha=one", "beta=two", sid, tok}

	for _, preset := range webKit26Presets {
		t.Run(preset, func(t *testing.T) {
			h := startHPACKWireServer(t, 0, nil)
			blocks := driveAs(t, h, preset, 3, func(tr *Transport, base string) {
				for _, p := range []string{"/fi/matkat", "/fi/matkat/one", "/fi/matkat/two"} {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					_, err := tr.Do(ctx, &Request{
						Method:  "GET",
						URL:     base + p,
						Headers: map[string][]string{"Cookie": {jar}},
					})
					cancel()
					if err != nil {
						t.Logf("%s: %v", p, err)
					}
				}
			})

			never := hpackRep{"LIT_NEVER", 32, []byte{0x1f, 0x11}}
			for i, block := range hpackFields(t, blocks[:3]) {
				var got []string
				first := -1
				for j, f := range block {
					if f.Name != "cookie" {
						continue
					}
					if first < 0 {
						first = j
					}
					got = append(got, f.Value)
					if !never.matches(f.In) {
						t.Errorf("request %d: cookie %q went out %s, want %s, as Safari sends every cookie",
							i+1, shortValues([]string{f.Value})[0], instrString(f.In), never)
					}
				}
				if !slices.Equal(got, crumbs) {
					t.Errorf("request %d: cookie fields %q, want one per cookie, %q",
						i+1, shortValues(got), shortValues(crumbs))
				}
				if first != len(block)-len(crumbs) {
					t.Errorf("request %d: the cookie fields start at field %d of %d; Safari sends "+
						"them together, last", i+1, first+1, len(block))
				}
			}

			// The jar is re-sent in full: the four crumbs alone take 526 bytes
			// as never-indexed literals, Huffman coded. chrome-latest's third
			// block is 32 bytes in all.
			if n := len(blocks[2]); n < 526 {
				t.Errorf("request 3 header block is %d bytes, less than the 526 the four crumbs take "+
					"when re-sent; they went into the dynamic table", n)
			}
			t.Logf("block sizes: %d, %d, %d bytes", len(blocks[0]), len(blocks[1]), len(blocks[2]))
		})
	}
}

// :path is a literal without indexing, so no path enters the table and a
// repeated one goes out in full again, while ":path: /" is static entry 4 and
// takes one byte. Safari sent 84 for "/", and 04 then the Huffman-coded
// literal for "/report". The rest of the pseudo-headers are as before:
// :method and :scheme static, :authority inserted and then referenced.
func TestHPACKWebKitPathNotIndexed(t *testing.T) {
	for _, preset := range webKit26Presets {
		t.Run(preset, func(t *testing.T) {
			h := startHPACKWireServer(t, 0, nil)
			blocks := driveAs(t, h, preset, 3, func(tr *Transport, base string) {
				get(t, tr, base+"/")
				get(t, tr, base+"/fi/x")
				get(t, tr, base+"/fi/x")
			})

			for i, block := range hpackFields(t, blocks[:3]) {
				want := map[string]hpackRep{
					":method":    {"INDEXED", 2, []byte{0x82}},
					":scheme":    {"INDEXED", 7, []byte{0x87}},
					":path":      {"LIT_WITHOUT", 4, []byte{0x04}},
					":authority": {"INDEXED", 0, nil},
				}
				if i == 0 {
					want[":path"] = hpackRep{"INDEXED", 4, []byte{0x84}}
					want[":authority"] = hpackRep{"LIT_INCREMENTAL", 1, []byte{0x41}}
				}
				for _, name := range []string{":method", ":scheme", ":authority", ":path"} {
					f, ok := hpackFieldNamed(block, name)
					if !ok {
						t.Errorf("request %d: no %s field", i+1, name)
						continue
					}
					if !want[name].matches(f.In) {
						t.Errorf("request %d: %s: %s went out %s, want %s",
							i+1, name, f.Value, instrString(f.In), want[name])
					}
				}
			}
		})
	}
}

// content-length is a literal without indexing on name 28, request after
// request, even when the length repeats. Safari sent 0f 0d 82 13 e0 for a
// 290-byte fetch() body, and that representation on all 122 requests that
// carried one. chrome-latest is the control: Chrome inserts it, then refers
// to it.
func TestHPACKWebKitContentLengthNotIndexed(t *testing.T) {
	type row struct {
		preset string
		want   [2]hpackRep
	}
	rows := []row{{"chrome-latest", [2]hpackRep{{"LIT_INCREMENTAL", 28, []byte{0x5c}}, {"INDEXED", 0, nil}}}}
	without := hpackRep{"LIT_WITHOUT", 28, []byte{0x0f, 0x0d}}
	for _, p := range webKit26Presets {
		rows = append(rows, row{p, [2]hpackRep{without, without}})
	}

	body := bytes.Repeat([]byte("x"), 290)
	for _, c := range rows {
		t.Run(c.preset, func(t *testing.T) {
			s := startH2Server(t, h2Config{ReadToEndStream: true})
			tr := NewTransport(c.preset)
			tr.SetProtocol(ProtocolHTTP2)
			tr.SetInsecureSkipVerify(true)
			defer tr.Close()
			for i := 0; i < 2; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				resp, err := tr.Do(ctx, &Request{Method: "POST", URL: s.url("/report"), Body: body})
				cancel()
				if err != nil {
					t.Fatalf("POST %d: %v", i+1, err)
				}
				resp.Close()
			}
			if n := s.connCount(); n != 1 {
				t.Fatalf("the two POSTs used %d connections, want 1", n)
			}
			blocks := s.headerBlocks()
			if len(blocks) != 2 {
				t.Fatalf("captured %d header blocks, want 2", len(blocks))
			}

			for i, block := range hpackFields(t, blocks) {
				m, ok := hpackFieldNamed(block, ":method")
				if want := (hpackRep{"INDEXED", 3, []byte{0x83}}); !ok || !want.matches(m.In) {
					t.Errorf("request %d: :method %s went out %s, want %s", i+1, m.Value, instrString(m.In), want)
				}
				cl, ok := hpackFieldNamed(block, "content-length")
				if !ok {
					t.Fatalf("request %d: no content-length field", i+1)
				}
				if cl.Value != "290" || !c.want[i].matches(cl.In) {
					t.Errorf("request %d: content-length: %s went out %s, want 290 as %s",
						i+1, cl.Value, instrString(cl.In), c.want[i])
				}
			}
		})
	}
}

// The chrome policy alone would send every method that has no static entry,
// anything but GET and POST, as a literal without indexing. The presets keep
// it incremental, as the default policy had it and as Safari indexed the
// method of its extended CONNECTs: 42 07 434f4e4e454354 the first time, a
// dynamic reference after that. This fails if the :method entry is dropped
// from hpack_representation.
func TestHPACKWebKitOtherMethodsStayIndexed(t *testing.T) {
	for _, preset := range webKit26Presets {
		t.Run(preset, func(t *testing.T) {
			h := startHPACKWireServer(t, 0, nil)
			blocks := driveAs(t, h, preset, 2, func(tr *Transport, base string) {
				for i := 0; i < 2; i++ {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					if _, err := tr.Do(ctx, &Request{Method: "PUT", URL: base + "/fi/x"}); err != nil {
						t.Logf("PUT %d: %v", i+1, err)
					}
					cancel()
				}
			})

			fields := hpackFields(t, blocks[:2])
			for i, want := range []hpackRep{{"LIT_INCREMENTAL", 2, []byte{0x42}}, {"INDEXED", 0, nil}} {
				m, ok := hpackFieldNamed(fields[i], ":method")
				if !ok {
					t.Fatalf("request %d: no :method field", i+1)
				}
				if m.Value != "PUT" || !want.matches(m.In) {
					t.Errorf("request %d: :method %s went out %s, want PUT as %s", i+1, m.Value, instrString(m.In), want)
				}
				if i == 0 && m.In.ValueHuff {
					t.Errorf("request 1: PUT was Huffman coded; it is shorter raw, and Safari sent CONNECT raw")
				}
			}
		})
	}
}

// A navigation inserts 9 entries: the 8 regular headers and :authority. It
// was 10 while :path went into the table too. The server sees the count from
// request 1 alone, because its decoder mirrors every insertion.
func TestHPACKWebKitInsertionCount(t *testing.T) {
	for _, preset := range webKit26Presets {
		t.Run(preset, func(t *testing.T) {
			h := startHPACKWireServer(t, 0, nil)
			blocks := driveAs(t, h, preset, 1, func(tr *Transport, base string) {
				get(t, tr, base+"/fi/matkat")
			})
			if got := countInstr(parseHPACK(t, blocks[0]), "LIT_INCREMENTAL"); got != 9 {
				t.Errorf("a navigation inserted %d entries, want 9 (8 regular headers plus "+
					":authority). 10 means :path is being inserted", got)
			}
		})
	}
}

// The older WebKit presets keep their encoding. No capture shows the HPACK of
// Safari 18 or of Chrome on iOS before 148, so they still send one joined
// cookie field, inserted and then referenced, and insert :path.
func TestHPACKOlderWebKitUnchanged(t *testing.T) {
	for _, preset := range []string{"safari-18", "chrome-147-ios"} {
		t.Run(preset, func(t *testing.T) {
			h := startHPACKWireServer(t, 0, nil)
			blocks := driveAs(t, h, preset, 2, func(tr *Transport, base string) {
				for _, p := range []string{"/fi/a", "/fi/b"} {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					_, err := tr.Do(ctx, &Request{
						Method:  "GET",
						URL:     base + p,
						Headers: map[string][]string{"Cookie": {"a=1; b=2"}},
					})
					cancel()
					if err != nil {
						t.Logf("%s: %v", p, err)
					}
				}
			})

			cookieWant := []hpackRep{{"LIT_INCREMENTAL", 32, []byte{0x60}}, {"INDEXED", 0, nil}}
			for i, block := range hpackFields(t, blocks[:2]) {
				var cookies []hpackField
				for _, f := range block {
					if f.Name == "cookie" {
						cookies = append(cookies, f)
					}
				}
				if len(cookies) != 1 || cookies[0].Value != "a=1; b=2" {
					var vals []string
					for _, f := range cookies {
						vals = append(vals, f.Value)
					}
					t.Fatalf("request %d: cookie fields %q, want the one joined field", i+1, vals)
				}
				if !cookieWant[i].matches(cookies[0].In) {
					t.Errorf("request %d: cookie went out %s, want %s", i+1, instrString(cookies[0].In), cookieWant[i])
				}
				p, ok := hpackFieldNamed(block, ":path")
				if want := (hpackRep{"LIT_INCREMENTAL", 4, []byte{0x44}}); !ok || !want.matches(p.In) {
					t.Errorf("request %d: :path %s went out %s, want %s", i+1, p.Value, instrString(p.In), want)
				}
			}
		})
	}
}

// HTTP3Transport's pre-split shares the cookie-split flag, so the WebKit 26
// presets send one QPACK field line per cookie as well, together at the cookie
// slot of their order: after accept-encoding, and last on a GET. No capture has
// shown Safari's QPACK cookie lines yet: the run that logged Safari's HTTP/3
// requests set no cookie, and no QUIC reached the server of the HTTP/2
// capture. So this follows the HTTP/2 capture. safari-18 and chrome-147-ios
// keep one line, in their slot after user-agent.
func TestH3WebKitCookieCrumbs(t *testing.T) {
	type row struct {
		preset string
		want   []string
		after  string // the field right before the cookie lines
	}
	rows := []row{
		{"safari-18", []string{"a=1; b=2"}, "user-agent"},
		{"chrome-147-ios", []string{"a=1; b=2"}, "user-agent"},
	}
	for _, p := range webKit26Presets {
		rows = append(rows, row{p, []string{"a=1", "b=2"}, "accept-encoding"})
	}

	for _, c := range rows {
		t.Run(c.preset, func(t *testing.T) {
			fields, lines := captureH3Request(t, c.preset, map[string][]string{"Cookie": {"a=1; b=2"}})
			var got []string
			first := -1
			for i, f := range fields {
				if f.Name == "cookie" {
					if first < 0 {
						first = i
					}
					got = append(got, f.Value)
				}
			}
			if !slices.Equal(got, c.want) || first != len(fields)-len(c.want) {
				t.Errorf("cookie field lines %q starting at line %d of %d, want %q last\n%s",
					got, first+1, len(fields), c.want, strings.Join(lines, "\n"))
			}
			if first > 0 && fields[first-1].Name != c.after {
				t.Errorf("the cookie lines follow %s, want %s, their slot in the order",
					fields[first-1].Name, c.after)
			}
		})
	}
}

// captureH3Request sends one GET over forced HTTP/3 and returns the field
// section of its HEADERS frame, decoded and as renderQPACK lists it. The
// server is captureH3's, cut down to one request: bare QUIC, an empty
// SETTINGS, so the client has no dynamic table to use, and a :status 200.
func captureH3Request(t *testing.T, preset string, headers map[string][]string) ([]qpack.HeaderField, []string) {
	t.Helper()
	cert := wireCert(t)
	ln, err := quic.ListenAddr("127.0.0.1:0", &utls.Config{
		Certificates: []utls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
		NextProtos:   []string{"h3"}},
		&quic.Config{MaxIdleTimeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	section := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		if s, err := conn.OpenUniStream(); err == nil {
			s.Write([]byte{0x00, 0x04, 0x00}) // control stream, empty SETTINGS
		}
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		defer s.Close()
		r := &quicReader{r: s}
		for {
			ft := r.varint()
			p := r.take(int(r.varint()))
			if r.err != nil {
				return
			}
			if ft == 0x01 {
				section <- p
				break
			}
		}
		s.Write([]byte{0x01, 0x03, 0x00, 0x00, 0xd9}) // HEADERS :status 200
	}()

	tr := wireTransport(preset, ProtocolHTTP3)
	defer tr.Close()
	reqCtx, reqCancel := context.WithTimeout(context.Background(), 15*time.Second)
	resp, err := tr.Do(reqCtx, &Request{Method: "GET", URL: "https://" + ln.Addr().String() + "/c", Headers: headers})
	reqCancel()
	if err != nil {
		t.Logf("request: %v", err)
	} else {
		resp.Close()
	}

	var p []byte
	select {
	case p = <-section:
	case <-time.After(5 * time.Second):
		t.Fatal("no HEADERS frame arrived over HTTP/3")
	}
	var fields []qpack.HeaderField
	next := qpack.NewDecoder().Decode(p)
	for {
		f, err := next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("QPACK field section: %v", err)
		}
		fields = append(fields, f)
	}
	return fields, renderQPACK(p, portOf(ln.Addr()))
}
