package transport

import (
	"bytes"
	"slices"
	"testing"

	"github.com/sardanioss/quic-go"

	"github.com/sardanioss/httpcloak/internal/h3build"
)

// A WebKit preset's QUIC config carries everything Safari 26.3's Initial
// packets need; TestWebKitQUICInitialMatchesSafari26 checks the packets.
func TestQUICConfigSafari(t *testing.T) {
	p := presetOrSkip(t, "safari-latest")
	if p == nil {
		return
	}
	cfg := h3build.QUICConfig(h3build.QUICOptions{Preset: p})
	if cfg.TransportParameterOrder != quic.TransportParameterOrderCustom {
		t.Errorf("TransportParameterOrder = %v, want the custom order", cfg.TransportParameterOrder)
	}
	if want := []uint64{0x9, 0xe, 0xf, 0x4, 0x5, 0x6, 0x7, 0xff080808}; !slices.Equal(cfg.CustomTransportParameterOrder, want) {
		t.Errorf("CustomTransportParameterOrder = %#x, want %#x", cfg.CustomTransportParameterOrder, want)
	}
	if cfg.ActiveConnectionIDLimit != 64 || cfg.InitialPacketSize != 1200 || cfg.MaxIncomingUniStreams != 8 ||
		cfg.InitialStreamReceiveWindow != 2097152 || cfg.InitialConnectionReceiveWindow != 16777216 {
		t.Errorf("limit %d, packet size %d, uni streams %d, windows %d/%d", cfg.ActiveConnectionIDLimit,
			cfg.InitialPacketSize, cfg.MaxIncomingUniStreams, cfg.InitialStreamReceiveWindow, cfg.InitialConnectionReceiveWindow)
	}
	if !cfg.DisableClientHelloScrambling || cfg.ChromeStyleInitialPackets || cfg.InitialCryptoDataPerPacket != 999 ||
		!cfg.PacketNumbersFromZero || !cfg.ShortInitialPacketNumbers {
		t.Errorf("scrambling off %v, Chrome-style %v, crypto per packet %d, from zero %v, short %v",
			cfg.DisableClientHelloScrambling, cfg.ChromeStyleInitialPackets, cfg.InitialCryptoDataPerPacket,
			cfg.PacketNumbersFromZero, cfg.ShortInitialPacketNumbers)
	}

	params := AdditionalTransportParamsForPreset(p, nil, "", 0)
	if len(params) != 1 || !bytes.Equal(params[0xff080808], []byte{0x07}) {
		t.Errorf("additional parameters %x, want only 0xff080808 = 07", params)
	}
}

// The Chromium presets keep quic-go's Initial packets, which are Chrome's.
func TestQUICConfigChromeKeepsItsInitials(t *testing.T) {
	p := presetOrSkip(t, "chrome-latest")
	if p == nil {
		return
	}
	cfg := h3build.QUICConfig(h3build.QUICOptions{Preset: p})
	if cfg.TransportParameterOrder != quic.TransportParameterOrderChrome || cfg.CustomTransportParameterOrder != nil {
		t.Errorf("order %v, custom list %v", cfg.TransportParameterOrder, cfg.CustomTransportParameterOrder)
	}
	if cfg.ActiveConnectionIDLimit != 0 || cfg.InitialCryptoDataPerPacket != 0 ||
		cfg.PacketNumbersFromZero || cfg.ShortInitialPacketNumbers {
		t.Errorf("limit %d, crypto per packet %d, from zero %v, short %v", cfg.ActiveConnectionIDLimit,
			cfg.InitialCryptoDataPerPacket, cfg.PacketNumbersFromZero, cfg.ShortInitialPacketNumbers)
	}
	if _, ok := AdditionalTransportParamsForPreset(p, nil, "", 0)[0xff080808]; ok {
		t.Error("a Chromium preset sends Safari's private parameter")
	}
}

// A MASQUE tunnel's outer connection has to advertise max_datagram_frame_size,
// which Safari's order leaves out.
func TestAdvertiseDatagramsForMASQUE(t *testing.T) {
	p := presetOrSkip(t, "safari-latest")
	if p == nil {
		return
	}
	cfg := h3build.QUICConfig(h3build.QUICOptions{Preset: p, InitialPacketSize: 1350})
	h3build.AdvertiseDatagrams(cfg)
	h3build.AdvertiseDatagrams(cfg)
	if want := []uint64{0x9, 0xe, 0xf, 0x4, 0x5, 0x6, 0x7, 0xff080808, 0x20}; !slices.Equal(cfg.CustomTransportParameterOrder, want) {
		t.Errorf("CustomTransportParameterOrder = %#x, want %#x", cfg.CustomTransportParameterOrder, want)
	}
	if !cfg.EnableDatagrams {
		t.Error("EnableDatagrams is off")
	}
	// The order on a fresh config is untouched.
	if fresh := h3build.QUICConfig(h3build.QUICOptions{Preset: p}); slices.Contains(fresh.CustomTransportParameterOrder, 0x20) {
		t.Error("AdvertiseDatagrams changed the shared Safari order")
	}

	// quic-go's own orders write the parameter already.
	c := presetOrSkip(t, "chrome-latest")
	if c == nil {
		return
	}
	cfg = h3build.QUICConfig(h3build.QUICOptions{Preset: c, InitialPacketSize: 1350})
	h3build.AdvertiseDatagrams(cfg)
	if cfg.CustomTransportParameterOrder != nil {
		t.Errorf("a Chromium config got a custom order %#x", cfg.CustomTransportParameterOrder)
	}
}
