package fingerprint

import (
	"encoding/json"
	"testing"
)

// The keys for the connection-ID limit and the Initial packets' shape load,
// clone and describe like the other HTTP/3 keys.
func TestHTTP3InitialKeysRoundTrip(t *testing.T) {
	order := "safari"
	spec := &PresetSpec{
		Name: "h3-initial-keys",
		HTTP3: &HTTP3Spec{
			QUICTransportParamOrder:        &order,
			QUICActiveConnectionIDLimit:    ptrUint64(64),
			QUICInitialCryptoDataPerPacket: ptrUint16(999),
			QUICPacketNumbersFromZero:      ptrBool(true),
			QUICShortInitialPacketNumbers:  ptrBool(true),
		},
	}
	p, err := BuildPreset(spec)
	if err != nil {
		t.Fatal(err)
	}
	p.SupportHTTP3 = true
	check := func(label string, p *Preset) {
		t.Helper()
		if p.H3QUICTransportParamOrder() != "safari" ||
			p.H3QUICActiveConnectionIDLimit() != 64 ||
			p.H3QUICInitialCryptoDataPerPacket() != 999 ||
			!p.H3QUICPacketNumbersFromZero() ||
			!p.H3QUICShortInitialPacketNumbers() {
			t.Errorf("%s: order %q, limit %d, crypto per packet %d, from zero %v, short %v", label,
				p.H3QUICTransportParamOrder(), p.H3QUICActiveConnectionIDLimit(),
				p.H3QUICInitialCryptoDataPerPacket(), p.H3QUICPacketNumbersFromZero(),
				p.H3QUICShortInitialPacketNumbers())
		}
	}
	check("built", p)

	c := clonePreset(p)
	*p.H3Config.QUICActiveConnectionIDLimit = 8
	*p.H3Config.QUICShortInitialPacketNumbers = false
	check("clone", c)

	out := flattenHTTP3(c)
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var back HTTP3Spec
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	q, err := BuildPreset(&PresetSpec{Name: "h3-initial-keys-2", HTTP3: &back})
	if err != nil {
		t.Fatal(err)
	}
	check("described and reloaded", q)
}

// A preset that sets none of them describes none of them, so the Chromium
// presets' describe output keeps its keys.
func TestHTTP3InitialKeysOnlyWhenSet(t *testing.T) {
	out := flattenHTTP3(Get("chrome-latest"))
	if out.QUICActiveConnectionIDLimit != nil || out.QUICInitialCryptoDataPerPacket != nil ||
		out.QUICPacketNumbersFromZero != nil || out.QUICShortInitialPacketNumbers != nil {
		t.Errorf("chrome-latest describes keys it doesn't set: %+v", out)
	}
	p := Get("chrome-latest")
	if p.H3QUICActiveConnectionIDLimit() != 0 || p.H3QUICInitialCryptoDataPerPacket() != 0 ||
		p.H3QUICPacketNumbersFromZero() || p.H3QUICShortInitialPacketNumbers() {
		t.Error("chrome-latest changed its Initial packets")
	}
}

func TestBuildPresetValidationActiveConnectionIDLimit(t *testing.T) {
	for _, limit := range []uint64{0, 1} {
		_, err := BuildPreset(&PresetSpec{Name: "bad-limit", HTTP3: &HTTP3Spec{QUICActiveConnectionIDLimit: ptrUint64(limit)}})
		if err == nil {
			t.Errorf("limit %d: expected an error", limit)
		}
	}
	if _, err := BuildPreset(&PresetSpec{Name: "limit-2", HTTP3: &HTTP3Spec{QUICActiveConnectionIDLimit: ptrUint64(2)}}); err != nil {
		t.Errorf("limit 2: %v", err)
	}
}

// Every WebKit preset with HTTP/3 carries Safari 26.3's QUIC settings, through
// safariH3Config, and the iOS Chrome presets built on it in JSON keep them.
func TestWebKitPresetsCarrySafari26QUIC(t *testing.T) {
	for _, name := range []string{"safari-latest", "safari-18", "safari-18-ios", "chrome-143-ios", "chrome-147-ios", "chrome-148-ios", "chrome-latest-ios"} {
		p := Get(name)
		if p == nil {
			t.Fatalf("%s missing", name)
		}
		if p.H3QUICTransportParamOrder() != "safari" ||
			p.H3QUICInitialPacketSize() != 1200 ||
			p.H3QUICMaxIncomingUniStreams() != 8 ||
			p.H3QUICInitialStreamReceiveWindow() != 2097152 ||
			p.H3QUICInitialConnectionReceiveWindow() != 16777216 ||
			p.H3QUICActiveConnectionIDLimit() != 64 ||
			!p.H3QUICDisableHelloScramble() ||
			p.H3QUICInitialCryptoDataPerPacket() != 999 ||
			!p.H3QUICPacketNumbersFromZero() ||
			!p.H3QUICShortInitialPacketNumbers() {
			t.Errorf("%s: %+v", name, *p.H3Config)
		}
	}
}
