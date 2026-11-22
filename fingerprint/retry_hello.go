package fingerprint

import (
	tls "github.com/sardanioss/utls"
)

// The ClientHello sent again after a HelloRetryRequest.
//
// A TLS 1.3 server that has none of the groups the client sent key shares for,
// but supports one the client lists, answers the first ClientHello with a
// HelloRetryRequest naming that group, and the client sends its hello a second
// time with a share for it (RFC 8446 section 4.1.4).
//
// BoringSSL leaves the padding extension out of that second hello. Since
// commit cd89004847ad ("Don't pad the second ClientHello.", 2021-06-10),
// ssl_add_clienthello_tlsext pads only while !ssl->s3->used_hello_retry_request,
// and do_read_hello_retry_request in tls13_client.cc sets that flag before
// do_send_second_client_hello writes the hello. The commit gives the reason:
// the padding works around bugs in old F5 and WebSphere servers, which do not
// speak TLS 1.3, and a HelloRetryRequest only ever comes from one that does.
//
// Safari 26.3 does the same. Against a Go server accepting P-384 only
// (run-20261121-225724, macOS 26.3), its second hello is its first with one
// P-384 share in place of the GREASE, X25519MLKEM768 and X25519 shares, and
// the record version raised to 0x0303 (tlshrr.log:2-28 and :30-51). Random,
// session ID, cipher suites, GREASE values and extension order are unchanged,
// and there is no padding: 364 bytes, which is inside the 256-511 byte window
// BoringPaddingStyle pads.
//
// utls rebuilds the hello after a HelloRetryRequest (v1.10.5
// handshake_client_tls13.go:473) and recomputes the padding extension on the
// way (u_conn.go:944). So the Safari 18 spec, which HelloIOS_18 builds too and
// which ends with BoringPaddingStyle padding, sent that hello padded to 512
// bytes. Its first hello is above the window and was never padded.

// ApplyRetryHelloPadding makes spec send the hello that answers a
// HelloRetryRequest with or without padding as id's browser does. It changes
// nothing for any other hello, and it is a no-op for every id but those whose
// browser is known to leave that hello unpadded.
//
// spec must be the fresh spec one connection is built from, since the padding
// function this installs keeps state for that connection.
func ApplyRetryHelloPadding(spec *tls.ClientHelloSpec, id tls.ClientHelloID) {
	if spec == nil || !retryHelloUnpadded(id) {
		return
	}
	padFirstHelloOnly(spec.Extensions)
}

// retryHelloUnpadded reports whether the browser behind id sends the hello
// that answers a HelloRetryRequest without the padding extension.
//
// It lists the hellos Safari 26.3 was seen sending, on macOS and on iOS:
// HelloIOS_18 builds the HelloSafari_18 spec. BoringSSL's rule covers every
// Chromium hello too, but the Chromium specs the presets use carry no padding
// extension, so there is nothing to change. HelloIOS_14 (safari-17-ios) pads
// its first hello, and no capture shows what iOS 17 sends after a retry, so it
// keeps utls's behaviour. A Firefox hello must never be listed: NSS pads the
// retry as it pads the first hello. ssl3_SendClientHello builds both, and
// ssl_CalculatePaddingExtLen (lib/ssl/ssl3ext.c) skips only DTLS, SSL 3.0 and
// renegotiation.
func retryHelloUnpadded(id tls.ClientHelloID) bool {
	switch id {
	case tls.HelloSafari_18, tls.HelloIOS_18:
		return true
	}
	return false
}

// padFirstHelloOnly wraps the padding extension in exts so that it pads the
// first ClientHello as before and adds nothing to the hello sent after a
// HelloRetryRequest.
//
// utls has no hook for the retry, so the retry is recognised by what utls does
// to the key_share extension just before it marshals the hello again:
// processHelloRetryRequest replaces KeyShareExtension.KeyShares with a newly
// built list holding the one share it sends now (v1.10.5
// handshake_client_tls13.go:424-430). That happens on every HelloRetryRequest,
// one that carries only a cookie included. Nothing else assigns the list once
// the spec is built: ApplyPreset fills in each share's key in place. So every
// marshal of the first hello sees the list the first marshal saw, and a
// different list means the retry.
//
// Padding with a fixed length (WillPad set, no GetPaddingLen) is not
// recomputed on a retry at all, so it is left alone.
func padFirstHelloOnly(exts []tls.TLSExtension) {
	var pad *tls.UtlsPaddingExtension
	var keyShare *tls.KeyShareExtension
	for _, ext := range exts {
		switch e := ext.(type) {
		case *tls.UtlsPaddingExtension:
			pad = e
		case *tls.KeyShareExtension:
			keyShare = e
		}
	}
	if pad == nil || pad.GetPaddingLen == nil || keyShare == nil {
		return
	}

	padLen := pad.GetPaddingLen
	var first []tls.KeyShare
	marshalled := false
	pad.GetPaddingLen = func(unpaddedLen int) (int, bool) {
		if !marshalled {
			first, marshalled = keyShare.KeyShares, true
		} else if !sameKeyShareList(first, keyShare.KeyShares) {
			return 0, false
		}
		return padLen(unpaddedLen)
	}
}

// sameKeyShareList reports whether a and b are one list, the same backing
// array at the same length, rather than two lists that happen to be equal.
func sameKeyShareList(a, b []tls.KeyShare) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}
