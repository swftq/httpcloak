package transport

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// Wire locks on how a connection opens its streams.
//
// Firefox opens client streams from 3, keeping 1 for an HTTP/1.1 Upgrade
// (Http2Session.cpp: "mNextStreamID(3)  // 1 is reserved for Updgrade
// handshakes"). It advertises its push allowance, 131072, as
// SETTINGS_INITIAL_WINDOW_SIZE and follows every HEADERS with a WINDOW_UPDATE
// of 12451840 on that stream, which takes the stream to its 12 MiB pull
// allowance (Http2StreamBase::AdjustInitialWindow). A Firefox 159 capture did
// both on all 106 requests over 9 connections, and the 133 and 148 release
// sources carry the same code and pref values.
//
// Chromium starts at kFirstStreamId = 1 and sends a stream WINDOW_UPDATE only
// once data has been consumed; a Safari 26 capture on macOS and iOS started at
// 1 and sent a WINDOW_UPDATE on stream 0 only.

// firefoxStreamBump is Firefox's pull allowance, 12 MiB, minus the initial
// window it advertises.
const firefoxStreamBump = 12<<20 - 131072

// isFirefoxPreset is the ground truth here, kept apart from the preset
// tables the code under test reads.
func isFirefoxPreset(name string) bool { return strings.HasPrefix(name, "firefox-") }

// Every preset, through a real send: a GET and a POST on one connection. The
// stream IDs and the frame after each HEADERS are what the browser sends.
func TestH2StreamStartPerPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("sends on every preset")
	}
	names := fingerprint.Available()
	sort.Strings(names)
	sem := make(chan struct{}, 6)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()

			s := startH2Server(t, h2Config{ReadToEndStream: true})
			tr := NewTransport(name)
			tr.SetProtocol(ProtocolHTTP2)
			tr.SetInsecureSkipVerify(true)
			defer tr.Close()

			for _, req := range []*Request{
				{Method: "GET", URL: s.url("/a")},
				{Method: "POST", URL: s.url("/b"), Body: []byte(`{"k":1}`),
					Headers: map[string][]string{"Content-Type": {"application/json"}}},
			} {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				_, err := tr.Do(ctx, req)
				cancel()
				if err != nil {
					t.Fatalf("%s %s: %v", req.Method, req.URL, err)
				}
			}
			if n := s.connCount(); n != 1 {
				t.Fatalf("%d connections, want both requests on one", n)
			}

			first := uint32(1)
			if isFirefoxPreset(name) {
				first = 3
			}
			frames := s.recorded()
			var ids []uint32
			for i, f := range frames {
				if f.Type != frHeaders {
					continue
				}
				ids = append(ids, f.StreamID)
				if !isFirefoxPreset(name) {
					continue
				}
				// The next frame on the connection, not merely the next on the
				// stream: the two leave in one write, so nothing can come
				// between them, and a POST's DATA has to come after.
				if i+1 >= len(frames) || frames[i+1].Type != frWindowUpdate ||
					frames[i+1].StreamID != f.StreamID || frames[i+1].increment() != firefoxStreamBump {
					t.Errorf("HEADERS on stream %d is not followed by WINDOW_UPDATE(%d, %d)\n%s",
						f.StreamID, f.StreamID, firefoxStreamBump, s.dump())
				}
			}
			if want := []uint32{first, first + 2}; len(ids) != 2 || ids[0] != want[0] || ids[1] != want[1] {
				t.Errorf("HEADERS on streams %v, want %v", ids, want)
			}

			var updates []h2Frame
			for _, f := range frames {
				if f.Type == frWindowUpdate && f.StreamID != 0 {
					updates = append(updates, f)
				}
			}
			if !isFirefoxPreset(name) && len(updates) > 0 {
				t.Errorf("%d stream-level WINDOW_UPDATEs on two small responses; this client opens streams at the advertised window\n%s",
					len(updates), s.dump())
			}
			if isFirefoxPreset(name) && len(updates) != 2 {
				t.Errorf("%d stream-level WINDOW_UPDATEs, want exactly the two that open the streams\n%s",
					len(updates), s.dump())
			}
		})
	}
}

// The update is credit the server may spend at once, and the transport has to
// account for it. A 1 MiB response is eight times the 131072 Firefox advertises.
// With the update the server sends it without waiting and the client owes no
// refresh; a transport that only advertised 131072 would refresh the stream
// every 64 KiB it read, which Firefox never does at this size.
func TestFirefoxStreamWindowCarriesALargeBody(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 1<<20)
	s := startH2Server(t, h2Config{Body: body, SendContentLength: true})

	tr := NewTransport("firefox-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/big")})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if got, err := resp.Bytes(); err != nil || len(got) != len(body) {
		t.Fatalf("read %d bytes (err %v), want %d", len(got), err, len(body))
	}

	var updates []uint32
	for _, f := range s.recorded() {
		if f.Type == frWindowUpdate && f.StreamID == 3 {
			updates = append(updates, f.increment())
		}
	}
	if len(updates) != 1 || updates[0] != firefoxStreamBump {
		t.Fatalf("stream 3 WINDOW_UPDATEs = %v, want only the opening %d\n%s",
			updates, firefoxStreamBump, s.dump())
	}
}
