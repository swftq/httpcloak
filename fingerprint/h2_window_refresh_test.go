package fingerprint

import (
	"strings"
	"testing"
)

// window_refresh, through the JSON loader and describe. The wire side is
// locked in transport/h2_window_refresh_wire_test.go.

// firefoxWindowRefresh is Firefox's rule, kept apart from firefoxH2Config.
var firefoxWindowRefresh = H2WindowRefresh{
	CreditOn: CreditOnArrival, AckAt: 4194304, Floor: 98304, ReadBuffer: 786432,
}

func TestWindowRefreshOnlyFirefoxSetsOne(t *testing.T) {
	for _, name := range Available() {
		p := Get(name)
		r := p.H2WindowRefresh()
		if !strings.HasPrefix(name, "firefox-") {
			if r != nil {
				t.Errorf("%s: window refresh %+v, want none", name, *r)
			}
			continue
		}
		if r == nil || *r != firefoxWindowRefresh {
			t.Errorf("%s: window refresh %+v, want Firefox's %+v", name, r, firefoxWindowRefresh)
		}
	}
}

func TestWindowRefreshKeyOverlaysBasedOn(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want *H2WindowRefresh
	}{
		{"inherited from firefox", `{"version":1,"preset":{"name":"t-wr-ff","based_on":"firefox-148"}}`,
			&firefoxWindowRefresh},
		{"absent on chrome", `{"version":1,"preset":{"name":"t-wr-cr","based_on":"chrome-latest"}}`,
			nil},
		{"set on chrome, keys left out are zero", `{"version":1,"preset":{"name":"t-wr-set","based_on":"chrome-latest",
			"http2":{"window_refresh":{"ack_at":1048576,"interval_ms":5000}}}}`,
			&H2WindowRefresh{AckAt: 1048576, IntervalMs: 5000}},
		{"replaced whole on firefox", `{"version":1,"preset":{"name":"t-wr-rep","based_on":"firefox-148",
			"http2":{"window_refresh":{"credit_on":"read","interval_ms":5000}}}}`,
			&H2WindowRefresh{CreditOn: CreditOnRead, IntervalMs: 5000}},
	} {
		p, err := LoadAndBuildPresetFromJSON([]byte(tc.json))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got := p.H2WindowRefresh()
		switch {
		case tc.want == nil && got != nil:
			t.Errorf("%s: window refresh %+v, want none", tc.name, *got)
		case tc.want != nil && (got == nil || *got != *tc.want):
			t.Errorf("%s: window refresh %+v, want %+v", tc.name, got, *tc.want)
		}
	}
}

// Building a preset on another copies the rule, so tuning the child's leaves
// the parent's alone.
func TestWindowRefreshIsCopiedByBasedOn(t *testing.T) {
	p, err := LoadAndBuildPresetFromJSON([]byte(`{"version":1,"preset":{"name":"t-wr-copy","based_on":"firefox-148"}}`))
	if err != nil {
		t.Fatal(err)
	}
	p.H2WindowRefresh().AckAt = 1
	if got := Get("firefox-148").H2WindowRefresh(); got.AckAt != firefoxWindowRefresh.AckAt {
		t.Fatalf("tuning a child changed firefox-148's ack_at to %d", got.AckAt)
	}
}

// A rule the transport would refuse is refused at load time instead, when no
// connection is waiting on it. The connection window check runs on the built
// preset, so a based_on that supplies the rule is caught too.
func TestWindowRefreshKeyRejectsWhatTheTransportWould(t *testing.T) {
	for _, tc := range []struct {
		name, json, want string
	}{
		{"unknown credit_on", `{"version":1,"preset":{"name":"t-wr-co","based_on":"chrome-latest",
			"http2":{"window_refresh":{"credit_on":"consume"}}}}`, "credit_on"},
		{"ack_at past 31 bits", `{"version":1,"preset":{"name":"t-wr-ack","based_on":"chrome-latest",
			"http2":{"window_refresh":{"ack_at":2147483648}}}}`, "ack_at"},
		{"floor past 31 bits", `{"version":1,"preset":{"name":"t-wr-fl","based_on":"chrome-latest",
			"http2":{"window_refresh":{"floor":2147483648}}}}`, "floor"},
		{"read_buffer past 31 bits", `{"version":1,"preset":{"name":"t-wr-rb","based_on":"chrome-latest",
			"http2":{"window_refresh":{"credit_on":"arrival","read_buffer":2147483648}}}}`, "read_buffer"},
		{"read_buffer on read", `{"version":1,"preset":{"name":"t-wr-rbr","based_on":"chrome-latest",
			"http2":{"window_refresh":{"read_buffer":786432}}}}`, "read_buffer"},
		{"inherited rule, connection window past 2^31-1", `{"version":1,"preset":{"name":"t-wr-cw","based_on":"firefox-148",
			"http2":{"connection_window_update":2147483647}}}`, "connection_window_update"},
	} {
		_, err := LoadAndBuildPresetFromJSON([]byte(tc.json))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one naming %s", tc.name, err, tc.want)
		}
	}
}

// Describe writes the rule only where a preset sets one, with every key, so
// every other preset describes exactly as before and Firefox's missing timer
// reads as interval_ms 0.
func TestDescribeWindowRefreshOnlyWhenSet(t *testing.T) {
	const firefox = `"window_refresh":{"credit_on":"arrival","ack_at":4194304,"floor":98304,"interval_ms":0,"read_buffer":786432}`
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
		if got := strings.Contains(d, `"window_refresh"`); got != tc.want {
			t.Errorf("%s: describe has window_refresh = %v, want %v", tc.preset, got, tc.want)
		}
		if compact := strings.Join(strings.Fields(d), ""); tc.want && !strings.Contains(compact, firefox) {
			t.Errorf("%s: describe does not carry Firefox's rule as %s\n%s", tc.preset, firefox, d)
		}
	}
}

// A rule round-trips through describe, and an empty credit_on comes back as
// the "read" it means.
func TestWindowRefreshRoundTrip(t *testing.T) {
	p, err := LoadAndBuildPresetFromJSON([]byte(`{"version":1,"preset":{"name":"t-wr-rt","based_on":"chrome-latest",
		"http2":{"window_refresh":{"ack_at":1048576,"floor":4096,"interval_ms":250}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	Register("t-wr-rt", p)
	defer Unregister("t-wr-rt")
	d, err := Describe("t-wr-rt")
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadAndBuildPresetFromJSON([]byte(d))
	if err != nil {
		t.Fatal(err)
	}
	want := H2WindowRefresh{CreditOn: CreditOnRead, AckAt: 1048576, Floor: 4096, IntervalMs: 250}
	if got := again.H2WindowRefresh(); got == nil || *got != want {
		t.Fatalf("after a round trip the rule is %+v, want %+v", got, want)
	}
}
