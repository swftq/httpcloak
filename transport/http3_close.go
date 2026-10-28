package transport

import (
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
)

// chromeCloseReason is what Chromium writes in the CONNECTION_CLOSE of a QUIC
// session it is done with: QUIC_CONNECTION_CANCELLED's number, then the details
// QuicChromiumClientSession::CloseSessionOnError passes, "net error".
const chromeCloseReason = "70:net error"

// CloseQUICConn ends an HTTP/3 connection the way the preset's browser ends one
// it no longer needs. Every deliberate close goes through here: the session's
// Close, Refresh and transport swaps, the 0-RTT retry, a dial that finishes
// after Close, and client.Client's pool, both directly and as the http3
// transport's CloseConn.
//
// Chromium closes every session in its pool with QUIC_CONNECTION_CANCELLED
// when the pool goes away, on exit and when a profile closes
// (~QuicSessionPool). quiche maps that error to a transport close with
// NO_ERROR, so Chrome 156 sent 0x1c, NO_ERROR, "70:net error" on both, in one
// packet with an ACK. Firefox 159 closed with H3_NO_ERROR and no reason, the
// code RFC 9114 gives a close with nothing wrong; WebKit presets send the same,
// since Safari has not been captured. The connections used to get
// CloseWithError(0, ""), and code 0 is not an HTTP/3 code at all.
func CloseQUICConn(preset *fingerprint.Preset, conn *quic.Conn) error {
	if preset != nil && presetIsChromeQUIC(preset) {
		return conn.CloseWithTransportError(quic.NoError, chromeCloseReason)
	}
	return conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
}
