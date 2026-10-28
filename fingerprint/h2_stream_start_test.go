package fingerprint

import (
	"strings"
	"testing"
)

// first_stream_id and stream_window_update, through the JSON loader and
// describe. The wire side is locked in transport/h2_stream_start_wire_test.go.

func loadStreamStart(t *testing.T, js string) (*Preset, error) {
	t.Helper()
	return LoadAndBuildPresetFromJSON([]byte(js))
}

func TestStreamStartKeysOverlayBasedOn(t *testing.T) {
	for _, tc := range []struct {
		name      string
		json      string
		wantFirst uint32
		wantBump  uint32
	}{
		{"inherited from firefox", `{"version":1,"preset":{"name":"t-ff","based_on":"firefox-148"}}`,
			3, 12451840},
		{"explicit zeros restore the defaults", `{"version":1,"preset":{"name":"t-ff0","based_on":"firefox-148",
			"http2":{"first_stream_id":0,"stream_window_update":0}}}`,
			1, 0},
		{"set on a preset that has neither", `{"version":1,"preset":{"name":"t-cr","based_on":"chrome-latest",
			"http2":{"first_stream_id":5,"stream_window_update":1000}}}`,
			5, 1000},
	} {
		p, err := loadStreamStart(t, tc.json)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := p.H2FirstStreamID(); got != tc.wantFirst {
			t.Errorf("%s: H2FirstStreamID = %d, want %d", tc.name, got, tc.wantFirst)
		}
		if got := p.H2StreamWindowUpdate(); got != tc.wantBump {
			t.Errorf("%s: H2StreamWindowUpdate = %d, want %d", tc.name, got, tc.wantBump)
		}
	}
}

// A value the wire cannot carry is refused at load time rather than when the
// first connection opens. The window check runs on the built preset, so a
// based_on that supplies one side of the sum is caught too.
func TestStreamStartKeysRejectWhatTheWireCannotCarry(t *testing.T) {
	for _, tc := range []struct {
		name, json, want string
	}{
		{"even first stream", `{"version":1,"preset":{"name":"t-even","based_on":"chrome-latest",
			"http2":{"first_stream_id":2}}}`, "first_stream_id"},
		{"first stream past 31 bits", `{"version":1,"preset":{"name":"t-big","based_on":"chrome-latest",
			"http2":{"first_stream_id":2147483649}}}`, "first_stream_id"},
		{"window past 2^31-1", `{"version":1,"preset":{"name":"t-win","based_on":"chrome-latest",
			"http2":{"stream_window_update":2147483647}}}`, "stream_window_update"},
		{"inherited update, raised initial window", `{"version":1,"preset":{"name":"t-iws","based_on":"firefox-148",
			"http2":{"initial_window_size":2147483647}}}`, "stream_window_update"},
	} {
		_, err := loadStreamStart(t, tc.json)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one naming %s", tc.name, err, tc.want)
		}
	}
}

// Describe writes the keys only where a preset departs from the defaults, so
// every preset that opens streams the usual way describes exactly as before.
func TestDescribeStreamStartOnlyWhenSet(t *testing.T) {
	for _, tc := range []struct {
		preset string
		want   bool
	}{
		{"firefox-148", true},
		{"firefox-133-windows", true},
		{"chrome-latest", false},
		{"safari-latest", false},
	} {
		d, err := Describe(tc.preset)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{`"first_stream_id"`, `"stream_window_update"`} {
			if got := strings.Contains(d, key); got != tc.want {
				t.Errorf("%s: describe has %s = %v, want %v", tc.preset, key, got, tc.want)
			}
		}
	}
}
