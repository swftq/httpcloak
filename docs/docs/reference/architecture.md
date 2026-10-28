---
title: Architecture
sidebar_position: 4
---

# Architecture

A top-down map of the library. Pull this up when you need to figure out which package owns a particular behaviour, or when you want to trace a request from `Session.Do` down to a TLS ClientHello hitting the wire.

---

## The layering

```
                    +---------------------------------+
   user code  --->  |  httpcloak (root package)       |
                    |  - Client / Session             |
                    |  - WithX option constructors    |
                    |  - Multipart helpers            |
                    +-----------------+---------------+
                                      |
                                      v
                    +---------------------------------+
                    |  session/                       |
                    |  - cookie jar (own + sardanioss)|
                    |  - per-host transport routing   |
                    |  - Refresh / Fork / Warmup      |
                    |  - state save / load            |
                    +-----------------+---------------+
                                      |
              +-----------------------+-----------------------+
              |                       |                       |
              v                       v                       v
      +---------------+       +---------------+       +---------------+
      | HTTP1Transport|       | HTTP2Transport|       | HTTP3Transport|
      | (raw TCP+TLS) |       | (uTLS + h2cc) |       | (quic-go h3)  |
      +---------------+       +---------------+       +---------------+
              |                       |                       |
              v                       v                       v
      +---------------+       +---------------+       +---------------+
      | proxy (HTTP   |       | proxy (HTTP   |       | proxy (UDP    |
      | CONNECT,      |       | CONNECT,      |       | SOCKS5,       |
      | SOCKS5)       |       | SOCKS5)       |       | MASQUE)       |
      +---------------+       +---------------+       +---------------+
              \                       |                      /
               \                      v                     /
                \               +-----+-----+              /
                 +------------> |  network  | <-----------+
                                +-----------+

               +-------------------------------+
   built once, +  fingerprint registry         |
   shared:     |  - Go presets (presets.go)    |
               |  - JSON presets (embedded/)   |
               |  - JA3 / Akamai / TCP fp data |
               +---------------+---------------+
                               |
                               v
               +-------------------------------+
   shared:     |  dns/                         |
               |  - SNI resolution             |
               |  - HTTPS RR / ECH lookup      |
               +-------------------------------+
```

Three transports, one session layer, one fingerprint registry, one DNS layer. The session picks which transport handles a request based on what the host advertises (Alt-Svc for H3) and whatever was forced via options.

---

## Packages

### `httpcloak` (root)

The public Go API. `Client`, `Session`, every `WithX` option constructor, the multipart helpers. Deliberately thin: everything interesting lives in a subpackage. Most options just set fields on a `protocol.SessionConfig` that gets handed to `session.NewSession`.

Files: `httpcloak.go`, `local_proxy.go`.

### `session/`

The stateful session layer. Owns the cookie jar, the per-host transport map, and the lifecycle of `Refresh`, `Fork`, `Warmup`, and state persistence.

The notable pieces:

- One transport per host, lazily created. The first request to `example.com` builds the transport; every later request reuses it.
- `Refresh()` closes connections but keeps the cookie jar and the TLS resumption ticket cache, with an optional protocol switch on the way.
- `Fork(n)` returns `n` child sessions sharing the cookie jar and TLS cache but with their own connections. The mental model is multiple browser tabs.
- `Warmup(ctx, url)` simulates a real page load: fetches the HTML, parses it, then pulls CSS, JS, and image subresources with realistic per-resource priorities and timing.

### `transport/`

The three transports plus the unifying `Transport` wrapper. One transport per protocol family.

- **`HTTP1Transport`**: raw TCP, TLS via uTLS, HTTP/1.1 framing through the `sardanioss/http` fork. Kicks in when a host doesn't speak H2 or when H1 was forced.
- **`HTTP2Transport`**: uTLS for the ClientHello, then a custom `http2.ClientConn` from the `sardanioss/http` fork. The custom conn is what lets the library send Chrome's exact `SETTINGS` order, `PRIORITY` frames, `WINDOW_UPDATE` value, and HPACK indexing policy.
- **`HTTP3Transport`**: `quic-go` from `sardanioss/quic-go` (with the `PRIORITY_UPDATE` fix and Chrome-style initial packet shaping) plus `http3.Transport`.

The other things this package owns:

- **Speculative TLS for proxy CONNECT**: sends the CONNECT request and the TLS ClientHello in one TCP write, saving a round-trip. Off by default because some proxies choke on it. Toggled by `WithEnableSpeculativeTLS`.
- **Happy Eyeballs**: IPv4/IPv6 racing inside the H3 dial functions. The first address to complete the QUIC handshake wins. The losers are dropped without a `CONNECTION_CLOSE`, the way Chromium drops a QUIC session it no longer needs.
- **`raceH3H2`**: protocol racing. When a host advertises H3 via Alt-Svc and no protocol has been forced, an H3 dial and an H2 dial fire in parallel. The first successful handshake wins, and the request goes out on the connection it made. An H3 attempt that loses but still finishes its handshake is dropped without a `CONNECTION_CLOSE`.
- **TLS session ticket cache**: in-memory by default, pluggable via `WithSessionCache(backend, errCb)` for distributed setups (Redis and friends).
- **Connection pool**: per-transport with an idle timeout. H3 idle is set via `WithQuicIdleTimeout`.

### `fingerprint/`

The preset registry and the data structures behind it.

- `presets.go`: Go-defined presets (Chrome 133-146, Firefox 133, Firefox 148, Safari 18, plus iOS and Android variants). Each preset is a `func() *Preset`.
- `embedded/*.json`: JSON-defined presets (Chrome 147 and 148 across every platform). Loaded at package init and registered alongside the Go presets.
- `custom_preset.go`: JSON parsing plus `BuildPreset`. Powers both the embedded JSONs and user-supplied presets through `LoadPresetFromFile` and `LoadPresetFromJSON`.
- `describe.go`: the inverse of `BuildPreset`. Emits canonical JSON from a `*Preset`. Round-trip stable.
- `client_hello_ids.go`: string-to-uTLS ClientHelloID resolution.
- `akamai.go`: Akamai H2 fingerprint string parser. The shorthand format `SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO` is parsed here.
- `ja3.go`: JA3 string parser and TLS spec builder.
- `headers.go`: header order and value handling.
- `preset_pool.go`: round-robin or random rotation across multiple presets.
- `priority_table_test.go`: golden tests for the runtime priority table. The runtime types (`ResourcePrioritySpec`, `PriorityTable map[string]ResourcePrioritySpec`) live alongside the JSON parser in `custom_preset.go`, and `presets.go` exposes the `H2PriorityFor(dest)` accessor that emits the per-request RFC 9218 priority header and RFC 7540 stream weight.

### `proxy/`

Proxy implementations. Three protocols are supported:

- **HTTP CONNECT**: for `http://` and `https://` proxy URLs. Used by H1 and H2.
- **SOCKS5**: for `socks5://` URLs. Used by H1, H2, and, if the proxy supports UDP-associate, H3.
- **MASQUE**: UDP-tunnelled-over-HTTP/3 proxying for H3 through an HTTP-aware UDP proxy. Implements the CONNECT-UDP method.

Proxy chains work (proxy through a proxy). `WithSessionProxy` sets one URL for every protocol. `WithSessionTCPProxy` and `WithSessionUDPProxy` together split it, for example SOCKS5 on H1/H2 and MASQUE on H3.

### `dns/`

DNS resolution.

- A and AAAA lookup with caching.
- HTTPS RR lookup for pulling ECH config. Used by `WithECHFrom` and the default ECH-when-available path.
- Per-resolver overrides (system, DoH, custom).

### `protocol/`

Defines `SessionConfig`, the JSON-shaped struct the root package's `NewSession` builds internally and that the cgo entry points consume from the bindings. Not relevant for direct Go callers. The package docstring still talks about a daemon and stdin/stdout JSON. That was an early design that was never shipped. The bindings (Python, Node.js, .NET) all link the cgo-built shared library directly via FFI / P/Invoke and call `httpcloak_session_new` and friends. There is no daemon binary.

### `client/`

A lower-level client surface that predates the unified root API. New code should stick with the root `httpcloak.Client` and `Session`. The `client/` package still ships its own `WithX` options for backwards compatibility (`client.WithPreset`, `client.WithECHConfig`, and certificate pinning via `PinCertificate`).

### Other directories

- `bindings/`: language SDKs (Python, Node.js, .NET) that link against the cgo-built shared library and call its exported entry points directly.
- `pool/`: connection pooling primitives. **Internal / advanced.** The package exports `HostPool`, `QUICHostPool`, `Manager`, and `QUICManager` plus their methods because the transport layer needs them, but they're not part of the supported user-facing surface. Most callers reach the pools through `Session` and `Transport`. Reach into `pool/` only when building a custom transport on top of the lib.
- `streaming/`: streaming-body request helpers.
- `extensions/`: uTLS extension shims.

The same caveat applies to `proxy/socks5_*.go` (`SOCKS5Dialer`, `SOCKS5UDPConn` and friends), `proxy/masque.go` (`MASQUEConn` and the connection-establishment helpers), and the lower-level transport entry points listed in [Observability](../connection-lifecycle/observability). They show up in GoDoc because Go has no friend-package mechanism, but treat them as internal unless you're explicitly extending the lib's transport stack.



---

## Forked dependencies

httpcloak rides on four forks. Each one patches upstream to expose fingerprint-relevant knobs that the original libraries don't.

| Fork | Upstream | What we changed |
|---|---|---|
| `sardanioss/http` | `golang.org/x/net/http2` | Custom `http2.ClientConn` that lets us control `SETTINGS` order, `WINDOW_UPDATE`, `PRIORITY` frames, HPACK indexing policy, pseudo-header order, cookie splitting. |
| `sardanioss/utls` | `refraction-networking/utls` | Additional ClientHello presets for newer Chrome / iOS / Safari versions, QUIC ClientHello variants, PSK variants, key share count control. |
| `sardanioss/quic-go` | `quic-go/quic-go` | Chrome-style initial packet shaping, transport parameter order control, `PRIORITY_UPDATE` frame fix, GREASE frame emission. |
| `sardanioss/net` | `golang.org/x/net` | Various small fixes for the `http2` interaction. |

These are pinned in `go.mod`. For local development, point a `go.work` file at a local checkout of any fork.

---

## Request flow

A normal `Session.Get(ctx, "https://example.com/")` walks this path:

1. **Cookie injection**: `session/` looks up cookies for the URL and attaches them as a `Cookie:` header, unless `WithoutCookieJar` is set or the caller already passed their own.
2. **Header building**: the preset's header order, the preset's values, and request-level overrides merge into one ordered list. `User-Agent`, `sec-ch-ua`, `accept-language`, and so on come from the preset.
3. **Transport selection**: `session/` looks up the per-host transport. If none exists yet, it builds one based on what the host has advertised (H3 via Alt-Svc cache) or whatever protocol was forced.
4. **Connect / dial**: the transport opens a connection if needed. For H1 and H2, that's TCP and then TLS via uTLS with the preset's ClientHello. For H3, UDP and then a QUIC handshake with the preset's QUIC ClientHello plus transport parameters.
   - Happy Eyeballs races IPv4 and IPv6.
   - Protocol racing fires H3 and H2 in parallel when the host advertises both.
   - Through a proxy, CONNECT / SOCKS5 / MASQUE runs first, then the handshake.
5. **DNS / ECH**: handled by `dns/`. The ECH HTTPS RR is fetched unless ECH is disabled.
6. **Wire send**: the transport writes request frames (HTTP/2 `HEADERS` + `DATA`, or the HTTP/3 equivalent). Frame ordering, settings, and priorities all come from the preset.
7. **Response**: read, parsed, and the body delivered as an `io.ReadCloser`.
8. **Cookie storage**: `Set-Cookie` headers from the response go into the jar, unless `WithoutCookieJar` is set.
9. **Redirect**: if the response is 3xx and follow is on, the flow jumps back to step 1 with the new URL.

---

## Threading and concurrency

- `Session` is goroutine-safe for concurrent requests. Internal state (cookie jar, transport map, TLS cache) is mutex-protected.
- `Fork(n)` returns sessions sharing the cookie jar mutex with the parent. Concurrent requests across forks contend on the jar but ride independent connections.
- Transport `Close()` paths are wrapped in `closeWithTimeout` because QUIC `Close` can hang forever on a half-closed UDP socket. One of the timeout patterns we watch closely.
- Per-request context propagates down to the transport. Cancel the context and the in-flight read, handshake, or dial cancels with it.

---

## Where to look when something's wrong

Map of common symptoms to the package that owns the relevant code.

| Symptom | Look in |
|---|---|
| Wrong JA3 / cipher order | `fingerprint/presets.go` or `fingerprint/embedded/*.json` for the preset's TLS section. Cross-check uTLS ClientHello ID. |
| Wrong HTTP/2 SETTINGS / pseudo order | `fingerprint/presets.go` H2 settings + `chromeH2Config` / `firefoxH2Config` / `safariH2Config`. |
| Wrong header order | Preset's `HeaderOrder` field. Verify against `tls.peet.ws/api/all`. |
| H3 not used | Check the host's Alt-Svc, the preset's `SupportHTTP3`, and whether `WithDisableHTTP3` was called. |
| Proxy doesn't connect | `proxy/`. Check the proxy URL scheme matches what the proxy speaks. |
| Hangs on close | `transport/` close paths. Check the QUIC close timeout wrapping. |
| Timeout not respected | `session/` and `transport/`. Context propagation, deadline computation. |

For everything else, the source reads easier than this map. Start at `httpcloak.NewSession` and follow the calls.
