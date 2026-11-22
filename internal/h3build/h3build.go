// Package h3build constructs the QUIC config and the HTTP/3 SETTINGS map for a
// fingerprint preset.
//
// It exists for the same reason internal/h2build does: three entrypoints built
// the quic.Config literal separately and had drifted. The pool path applied
// neither QUICInitialStreamReceiveWindow nor QUICInitialConnectionReceiveWindow,
// so a preset that sets them, which is every iOS Chrome and Safari-family one,
// emitted quic-go's defaults there and the preset's values through the
// transport path. Those are initial_max_stream_data_bidi_remote and
// initial_max_data on the wire: transport parameters the server reads directly
// off the handshake.
package h3build

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"slices"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/quic-go"
	utls "github.com/sardanioss/utls"
)

// H3 SETTINGS identifiers.
const (
	SettingQPACKMaxTableCapacity = 0x1
	SettingMaxFieldSectionSize   = 0x6
	SettingQPACKBlockedStreams   = 0x7
	SettingH3Datagram            = 0x33
)

// DefaultIdleTimeout is what a connection uses when nothing overrides it.
const DefaultIdleTimeout = 30 * time.Second

// QUICOptions are the things a call site knows that the preset does not.
type QUICOptions struct {
	// Preset is the profile being impersonated. Required.
	Preset *fingerprint.Preset

	// IdleTimeout is the QUIC max_idle_timeout. Zero means DefaultIdleTimeout.
	IdleTimeout time.Duration

	// TransportParameterShuffleSeed pins the transport-parameter order, and
	// production leaves it at zero so the order is reshuffled per connection.
	//
	// It is NOT a ClientHello shuffle seed, and the two must not be conflated.
	// Chrome reshuffles transport parameters on every serialization, so a
	// session holding one parameter order means every connection that session
	// opens carries a byte-identical ID sequence. That is detectable with no
	// probability argument at all: strip the GREASE id, length and payload from
	// two connections and compare.
	//
	// An earlier version of this comment claimed Chrome permutes its TLS
	// extensions once per profile, and that one session holding one extension
	// order was therefore right. That is wrong, and the QUIC transport was built
	// to match it: every connection in a session carried the same extension
	// order. Measured on 153.0.8010.52, one browser session opening 7 parallel
	// connections produced 7 different orders, and 3 QUIC connections from one
	// process produced 3. The permutation lives on the handshake, not the
	// profile. See fingerprint.FreshShuffleSeed.
	TransportParameterShuffleSeed int64

	ClientHelloID *utls.ClientHelloID
	CachedSpec    *utls.ClientHelloSpec
	ECHConfigList []byte

	// AdditionalTransportParameters is resolved by the caller, because it can
	// need a context and a live RTT measurement.
	AdditionalTransportParameters map[uint64][]byte

	// InitialPacketSize overrides the preset's value. MASQUE needs 1200.
	InitialPacketSize uint16

	// Tunnelled marks a connection running inside a MASQUE tunnel. The flow
	// control and packet sizing then come from the tunnel's constraints rather
	// than from the profile, because the outer connection is what the server
	// sees and this inner one is not being fingerprinted.
	Tunnelled bool
}

// QUICConfig builds the QUIC config for one preset.
func QUICConfig(o QUICOptions) *quic.Config {
	p := o.Preset

	idle := o.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}

	initialPacketSize := p.H3QUICInitialPacketSize()
	if o.InitialPacketSize > 0 {
		initialPacketSize = o.InitialPacketSize
	}

	cfg := &quic.Config{
		MaxIdleTimeout: idle,

		// The keep-alive PING. Half the idle timeout is what keeps a
		// connection alive while a request is outstanding, which is what a
		// browser does too; what a browser does NOT do is keep pinging once
		// the last stream has closed. That gating lives in the QUIC layer,
		// because only it knows the stream count.
		KeepAlivePeriod: idle / 2,

		MaxIncomingStreams:    p.H3QUICMaxIncomingStreams(),
		MaxIncomingUniStreams: p.H3QUICMaxIncomingUniStreams(),
		Allow0RTT:             p.H3QUICAllow0RTT(),

		// Always on at the QUIC level; the H3 SETTINGS decide what each
		// profile advertises.
		EnableDatagrams: true,

		InitialPacketSize: initialPacketSize,

		// Path MTU discovery is off. Chromium leaves it off unless the
		// embedder asks for it, and nothing on the ordinary navigation path
		// does. Left on, quic-go probes within the first handful of packets,
		// where Chromium's own search would not start until the peer's 100th,
		// and it will probe past 1400, which is Chromium's hard ceiling. Both
		// are visible as datagram lengths with no capture tooling at all.
		DisablePathMTUDiscovery: true,

		DisableClientHelloScrambling:  p.H3QUICDisableHelloScramble(),
		ChromeStyleInitialPackets:     p.H3QUICChromeStyleInitial(),
		ClientHelloID:                 o.ClientHelloID,
		CachedClientHelloSpec:         o.CachedSpec,
		TransportParameterOrder:       TransportParamOrder(p.H3QUICTransportParamOrder()),
		CustomTransportParameterOrder: CustomTransportParamOrder(p.H3QUICTransportParamOrder()),
		TransportParameterShuffleSeed: o.TransportParameterShuffleSeed,
		AdditionalTransportParameters: o.AdditionalTransportParameters,
		MaxDatagramFrameSize:          p.H3QUICMaxDatagramFrameSize(),
		ActiveConnectionIDLimit:       p.H3QUICActiveConnectionIDLimit(),

		// The Initial packets' shape. Zero values are quic-go's, which
		// are Chrome's.
		InitialCryptoDataPerPacket: p.H3QUICInitialCryptoDataPerPacket(),
		PacketNumbersFromZero:      p.H3QUICPacketNumbersFromZero(),
		ShortInitialPacketNumbers:  p.H3QUICShortInitialPacketNumbers(),
	}

	if len(o.ECHConfigList) > 0 {
		cfg.ECHConfigList = o.ECHConfigList
	}

	if o.Tunnelled {
		// The tunnel's numbers, not the profile's. Nothing here is a
		// fingerprint: the observer sees the outer connection.
		cfg.InitialStreamReceiveWindow = 512 * 1024
		cfg.MaxStreamReceiveWindow = 6 * 1024 * 1024
		cfg.InitialConnectionReceiveWindow = 15 * 1024 * 1024 / 2
		cfg.MaxConnectionReceiveWindow = 15 * 1024 * 1024
		return cfg
	}

	// Per-profile flow control. Zero means "leave quic-go's default", which is
	// what the Chrome-family profiles want because they match it already. The
	// Safari and iOS Chrome profiles set their own, and those values go on the
	// wire as initial_max_stream_data_bidi_remote and initial_max_data.
	if v := p.H3QUICInitialStreamReceiveWindow(); v != 0 {
		cfg.InitialStreamReceiveWindow = v
	}
	if v := p.H3QUICInitialConnectionReceiveWindow(); v != 0 {
		cfg.InitialConnectionReceiveWindow = v
	}
	return cfg
}

// TransportParamOrder converts a preset's string to the quic-go mode.
func TransportParamOrder(mode string) quic.TransportParameterOrderMode {
	switch mode {
	case "random":
		return quic.TransportParameterOrderDefault
	case "safari":
		return quic.TransportParameterOrderCustom
	}
	return quic.TransportParameterOrderChrome
}

// SafariTransportParameterOrder is the order, and the whole set, of the
// transport parameters Safari 26.3 sent on macOS 26.3, decrypted from its
// first Initial packets (run-20261121-225724, lo0.pcap packets 34075 and
// 34076): initial_max_streams_uni, active_connection_id_limit,
// initial_source_connection_id, initial_max_data,
// initial_max_stream_data_bidi_local, _bidi_remote and _uni, then
// SafariPrivateParameter.
//
// There's no GREASE parameter, and none of max_idle_timeout,
// max_udp_payload_size, initial_max_streams_bidi and max_datagram_frame_size:
// quic-go writes only the listed ones.
var SafariTransportParameterOrder = []uint64{0x9, 0xe, 0xf, 0x4, 0x5, 0x6, 0x7, SafariPrivateParameter}

// SafariPrivateParameter is the last transport parameter Safari sends, with
// the one-byte value SafariPrivateValue. No RFC assigns 0xff080808, and it is
// no GREASE value, since those are 31*N+27. Most likely it is Apple's own;
// what it means can't be read off the wire.
const SafariPrivateParameter = 0xff080808

// SafariPrivateValue is what Safari 26.3 sent in SafariPrivateParameter.
var SafariPrivateValue = []byte{0x07}

// maxDatagramFrameSizeParameter is max_datagram_frame_size (RFC 9221).
const maxDatagramFrameSizeParameter = 0x20

// CustomTransportParamOrder returns the parameter IDs, in order, that a mode
// quic-go can't build on its own sends. It is nil for the others.
func CustomTransportParamOrder(mode string) []uint64 {
	if mode == "safari" {
		return slices.Clone(SafariTransportParameterOrder)
	}
	return nil
}

// ExtraTransportParams returns the values of the transport parameters a
// non-Chromium preset sends that quic-go doesn't implement: for the Safari
// order, SafariPrivateParameter. The map is never nil, because quic-go reads a
// nil one as "use the process-wide set".
func ExtraTransportParams(p *fingerprint.Preset) map[uint64][]byte {
	if p.H3QUICTransportParamOrder() == "safari" {
		return map[uint64][]byte{SafariPrivateParameter: slices.Clone(SafariPrivateValue)}
	}
	return map[uint64][]byte{}
}

// AdvertiseDatagrams makes a config from QUICConfig advertise
// max_datagram_frame_size, which the outer connection of a MASQUE tunnel needs
// whatever the preset: a proxy may send DATAGRAM frames only to a client that
// advertised them. Safari's order leaves the parameter out, so it goes last,
// and that outer connection sends one parameter Safari's don't: the tunnel
// can't work without it.
func AdvertiseDatagrams(cfg *quic.Config) {
	if cfg.TransportParameterOrder != quic.TransportParameterOrderCustom ||
		slices.Contains(cfg.CustomTransportParameterOrder, maxDatagramFrameSizeParameter) {
		return
	}
	cfg.CustomTransportParameterOrder = append(slices.Clone(cfg.CustomTransportParameterOrder), maxDatagramFrameSizeParameter)
}

// GREASESetting draws the reserved SETTINGS identifier and its value the way
// quiche draws them.
//
// quiche, QuicSendControlStream::MaybeSendSettingsFrame:
//
//	uint32_t result;
//	QuicRandom::GetInstance()->RandBytes(&result, sizeof(result));
//	uint64_t setting_id = 0x1fULL * static_cast<uint64_t>(result) + 0x21ULL;
//	QuicRandom::GetInstance()->RandBytes(&result, sizeof(result));
//	settings.values[setting_id] = result;
//
// Two separate uint32 draws: one behind the identifier, one for the value.
//
// The identifier is the part that was wrong. Drawing N from [1e9, 1e10) puts
// roughly 63 percent of identifiers above 0x1f*2^32 + 0x21, which quiche
// cannot produce at all, and never produces the lower quarter of the range
// that quiche reaches about 23 percent of the time. A server inverts the
// identifier and checks that it fits a uint32. Measured against a live origin
// before the fix: 2 of 5 connections carried an impossible identifier.
//
// The value is a plain uint32 and may be zero. A previous comment claimed
// Chrome never sends zero and excluded it; the source above does not, though
// at one draw in 2^32 that was never observable.
//
// It lives here because both the transport and the pool build SETTINGS through
// Settings below, and each used to carry its own copy of the arithmetic.
func GREASESetting() (id, value uint64) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Unpredictable is the requirement, not secret, and a client that
		// cannot draw would otherwise advertise a fixed identifier.
		binary.LittleEndian.PutUint32(b[0:4], mrand.Uint32())
		binary.LittleEndian.PutUint32(b[4:8], mrand.Uint32())
	}
	id = 0x1f*uint64(binary.LittleEndian.Uint32(b[0:4])) + 0x21
	return id, uint64(binary.LittleEndian.Uint32(b[4:8]))
}

// Settings builds the HTTP/3 SETTINGS map, including the GREASE entry.
//
// greaseID and greaseValue are supplied by the caller so the randomness stays
// in one place and a test can pin it.
func Settings(p *fingerprint.Preset, greaseID, greaseValue uint64) map[uint64]uint64 {
	settings := map[uint64]uint64{
		SettingQPACKMaxTableCapacity: p.H3QPACKMaxTableCapacity(),
		SettingQPACKBlockedStreams:   p.H3QPACKBlockedStreams(),
		greaseID:                     greaseValue,
	}
	if maxField := p.H3MaxFieldSectionSize(); maxField > 0 {
		settings[SettingMaxFieldSectionSize] = maxField
	}
	if p.H3EnableDatagrams() {
		settings[SettingH3Datagram] = 1
	}
	return settings
}
