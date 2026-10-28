package transport

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/h2build"
)

// Wire locks on when a Firefox preset hands receive credit back.
//
// Firefox counts each DATA frame as its header is parsed
// (Http2Session::ReadyToProcessDataFrame), not when the page reads it. It
// hands credit back once 4 MiB is waiting, or once the window is down to 96
// KiB, with no timer (kMinimumToAck and kEmergencyWindowThreshold in
// Http2Session.h). The session hands back everything it has received. A
// stream holds back what its consumer has not taken beyond the 786432-byte
// response pipe. When both are due on one frame, UpdateLocalRwin queues the
// stream's update before the session's. The 133.0, 148.0 and 159.0 sources
// agree. A 159.0 capture of three 20 MiB transfers matched the rule update for
// update, which the sardanioss/net fork's tests replay.
//
// Chromium's rule, which every other preset keeps, is locked in
// flow_control_wire_test.go.

const (
	firefoxAck      = 4194304 // kMinimumToAck
	firefoxRecvWin  = 12 << 20
	firefoxPipe     = 786432
	frame16k        = 16384
	refreshTestBody = 20 << 20 // 1280 frames of 16 KiB
)

// refreshUpdates returns the WINDOW_UPDATE frames that return credit: every
// one after the first HEADERS except the update that opens a stream, which
// follows its HEADERS directly.
func refreshUpdates(frames []h2Frame) []h2Frame {
	var out []h2Frame
	seen := false
	for i, f := range frames {
		if f.Type == frHeaders {
			seen = true
			continue
		}
		if !seen || f.Type != frWindowUpdate {
			continue
		}
		if f.StreamID != 0 && i > 0 && frames[i-1].Type == frHeaders && frames[i-1].StreamID == f.StreamID {
			continue
		}
		out = append(out, f)
	}
	return out
}

type refreshUpdate struct {
	stream uint32
	inc    uint32
}

func updatesOf(frames []h2Frame) []refreshUpdate {
	var out []refreshUpdate
	for _, f := range frames {
		out = append(out, refreshUpdate{f.StreamID, f.increment()})
	}
	return out
}

func equalUpdates(a, b []refreshUpdate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// lockstepReader drains a body while a server's OnBodyChunk waits for it every
// step bytes, so the client never holds more than step bytes unread when a
// frame arrives.
type lockstepReader struct {
	mu   sync.Mutex
	cond *sync.Cond
	n    int
	done bool
	step int
}

func newLockstepReader(step int) *lockstepReader {
	r := &lockstepReader{step: step}
	r.cond = sync.NewCond(&r.mu)
	return r
}

// onBodyChunk is the server side: it returns once the reader has caught up.
func (r *lockstepReader) onBodyChunk(_ uint32, sent, _ int) {
	if sent%r.step != 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.n < sent && !r.done {
		r.cond.Wait()
	}
}

func (r *lockstepReader) drain(resp *http.Response) int {
	defer func() {
		r.mu.Lock()
		r.done = true
		r.mu.Unlock()
		r.cond.Broadcast()
	}()
	buf := make([]byte, frame16k)
	for {
		n, err := resp.Body.Read(buf)
		r.mu.Lock()
		r.n += n
		total := r.n
		r.mu.Unlock()
		r.cond.Broadcast()
		if err != nil {
			return total
		}
	}
}

func firefoxH2(t *testing.T) *Transport {
	t.Helper()
	tr := NewTransport("firefox-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	t.Cleanup(func() { tr.Close() })
	return tr
}

func streamGet(t *testing.T, tr *Transport, url string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.GetHTTP2Transport().RoundTrip(req)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	return resp
}

// A reader that keeps up never leaves more than the pipe unread, so only
// arrivals matter. Every 4 MiB the stream and then the connection each get
// exactly 4194304, back to back. The server ends the body with an empty DATA
// frame, so the last full frame still counts for the stream.
func TestFirefoxWindowRefreshPromptReader(t *testing.T) {
	reader := newLockstepReader(32 * frame16k)
	s := startH2Server(t, h2Config{
		Body:              make([]byte, refreshTestBody),
		SendContentLength: true,
		OnBodyChunk:       reader.onBodyChunk,
	})
	resp := streamGet(t, firefoxH2(t), s.url("/prompt"))
	if n := reader.drain(resp); n != refreshTestBody {
		t.Fatalf("read %d bytes, want %d", n, refreshTestBody)
	}
	resp.Body.Close()
	time.Sleep(200 * time.Millisecond)

	var want []refreshUpdate
	for range refreshTestBody / firefoxAck {
		want = append(want, refreshUpdate{3, firefoxAck}, refreshUpdate{0, firefoxAck})
	}
	if got := updatesOf(refreshUpdates(s.recorded())); !equalUpdates(got, want) {
		t.Fatalf("refresh updates = %v, want %v\n%s", got, want, s.dump())
	}
}

// A reader that reads nothing: the connection keeps handing back each 4 MiB
// as it arrives. The stream sends nothing until its window falls to the floor,
// at frame 762. It then hands back the pipe plus the frame that arrived with
// it, 802816, which is the plateau Firefox's own log shows when its consumer
// stalls. The server runs the stream window dry at 817 frames, and reading
// afterwards starts it again.
func TestFirefoxWindowRefreshStalledReader(t *testing.T) {
	const frames = (firefoxRecvWin + firefoxPipe + frame16k) / frame16k
	var sent atomic.Int64
	s := startH2Server(t, h2Config{
		Body:              make([]byte, refreshTestBody),
		SendContentLength: true,
		OnBodyChunk:       func(_ uint32, n, _ int) { sent.Store(int64(n)) },
	})
	resp := streamGet(t, firefoxH2(t), s.url("/stalled"))

	deadline := time.Now().Add(20 * time.Second)
	for sent.Load() < frames*frame16k {
		if time.Now().After(deadline) {
			t.Fatalf("server sent %d bytes, want %d\n%s", sent.Load(), frames*frame16k, s.dump())
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // nothing more may follow
	if n := sent.Load(); n != frames*frame16k {
		t.Fatalf("server sent %d bytes, want the %d the stream window allows", n, frames*frame16k)
	}
	want := []refreshUpdate{{0, firefoxAck}, {0, firefoxAck}, {3, 802816}, {0, firefoxAck}}
	if got := updatesOf(refreshUpdates(s.recorded())); !equalUpdates(got, want) {
		t.Fatalf("with the reader stalled, refresh updates = %v, want %v\n%s", got, want, s.dump())
	}

	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil || body.Len() != refreshTestBody {
		t.Fatalf("after the stall, read %d bytes (err %v), want %d", body.Len(), err, refreshTestBody)
	}
	resp.Body.Close()
}

// Through Do, which buffers the whole body, the connection's updates still
// depend on arrivals alone. They are the prefix sums of the frames the server
// sent, cut at each 4 MiB, whatever the reader did.
func TestFirefoxWindowRefreshThroughDo(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	last := 0
	s := startH2Server(t, h2Config{
		Body:              make([]byte, refreshTestBody),
		SendContentLength: true,
		OnBodyChunk: func(_ uint32, n, _ int) {
			mu.Lock()
			sizes = append(sizes, n-last)
			last = n
			mu.Unlock()
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := firefoxH2(t).Do(ctx, &Request{Method: "GET", URL: s.url("/do")})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := resp.Bytes(); err != nil || len(got) != refreshTestBody {
		t.Fatalf("read %d bytes (err %v), want %d", len(got), err, refreshTestBody)
	}
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	var want []refreshUpdate
	waiting := 0
	for _, n := range sizes {
		if waiting += n; waiting >= firefoxAck {
			want = append(want, refreshUpdate{0, uint32(waiting)})
			waiting = 0
		}
	}
	mu.Unlock()
	var got []refreshUpdate
	for _, u := range updatesOf(refreshUpdates(s.recorded())) {
		if u.stream == 0 {
			got = append(got, u)
		}
	}
	if len(want) == 0 || !equalUpdates(got, want) {
		t.Fatalf("connection updates = %v, want %v\n%s", got, want, s.dump())
	}
}

// Only the Firefox presets carry a rule, with Firefox's values, and every
// other preset leaves the fork's default in place. That covers the Chromium
// presets, and Safari and the iOS Chrome presets on WebKit, whose own rule no
// capture has shown yet.
func TestWindowRefreshPerPreset(t *testing.T) {
	names := fingerprint.Available()
	sort.Strings(names)
	for _, name := range names {
		r := h2build.Transport(h2build.Options{Preset: fingerprint.Get(name)}).WindowRefresh
		if !isFirefoxPreset(name) {
			if r != nil {
				t.Errorf("%s: window refresh %+v, want the default", name, *r)
			}
			continue
		}
		if r == nil || !r.OnArrival || r.AckAt != firefoxAck || r.Floor != 98304 ||
			r.Interval != 0 || r.ReadBuffer != firefoxPipe {
			t.Errorf("%s: window refresh %+v, want Firefox's", name, r)
		}
	}
}

// Every preset, through a real send of a 5 MiB body. A Firefox connection
// hands back its first 4 MiB the moment it arrives. Every other preset's
// connection hands back nothing, because its rule waits for more than half
// a window the transport still takes to be 15663105 + 65535.
func TestWindowRefreshConnectionPerPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("sends 5 MiB on every preset")
	}
	const body = 5 << 20
	names := fingerprint.Available()
	sort.Strings(names)
	sem := make(chan struct{}, 6)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()

			s := startH2Server(t, h2Config{Body: make([]byte, body), SendContentLength: true})
			tr := NewTransport(name)
			tr.SetProtocol(ProtocolHTTP2)
			tr.SetInsecureSkipVerify(true)
			defer tr.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			resp, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/five")})
			if err != nil {
				t.Fatal(err)
			}
			if got, err := resp.Bytes(); err != nil || len(got) != body {
				t.Fatalf("read %d bytes (err %v), want %d", len(got), err, body)
			}
			time.Sleep(100 * time.Millisecond)

			var conn []refreshUpdate
			for _, u := range updatesOf(refreshUpdates(s.recorded())) {
				if u.stream == 0 {
					conn = append(conn, u)
				}
			}
			var want []refreshUpdate
			if isFirefoxPreset(name) {
				want = []refreshUpdate{{0, firefoxAck}}
			}
			if !equalUpdates(conn, want) {
				t.Fatalf("connection updates = %v, want %v\n%s", conn, want, s.dump())
			}
		})
	}
}
