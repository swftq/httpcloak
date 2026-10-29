package session

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
	"golang.org/x/net/publicsuffix"
)

// generateID generates a random session ID (16 bytes = 32 hex chars)
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var (
	ErrSessionClosed = errors.New("session is closed")
)

// SessionOptions contains additional options that can't be expressed in protocol.SessionConfig
// (e.g., interfaces and callbacks that can't be JSON serialized)
type SessionOptions struct {
	// SessionCacheBackend is an optional distributed cache for TLS sessions
	SessionCacheBackend transport.SessionCacheBackend

	// SessionCacheErrorCallback is called when backend operations fail
	SessionCacheErrorCallback transport.ErrorCallback

	// CustomJA3 is a JA3 fingerprint string for custom TLS fingerprinting
	CustomJA3 string

	// CustomJA3Extras provides extension data that JA3 cannot capture
	CustomJA3Extras *fingerprint.JA3Extras

	// CustomH2Settings overrides the preset's HTTP/2 settings (from Akamai fingerprint)
	CustomH2Settings *fingerprint.HTTP2Settings

	// CustomPseudoOrder overrides the pseudo-header order (from Akamai fingerprint)
	CustomPseudoOrder []string

	// CustomTCPFingerprint overrides individual TCP/IP fingerprint fields from the preset
	CustomTCPFingerprint *fingerprint.TCPFingerprint
}

// cacheEntry stores cache validation headers for a URL
type cacheEntry struct {
	etag         string // ETag header value
	lastModified string // Last-Modified header value
}

// Session represents a persistent HTTP session with connection affinity
type Session struct {
	ID           string
	CreatedAt    time.Time
	LastUsed     time.Time
	RequestCount int64
	Config       *protocol.SessionConfig

	// Session's own transport with dedicated connection pool
	transport *transport.Transport
	cookies   *CookieJar

	// Cache validation headers per URL (for If-None-Match, If-Modified-Since)
	cacheEntries map[string]*cacheEntry

	// conditionalCacheEnabled controls whether ETag / If-Modified-Since handling
	// is active for this session. Initialised from !Config.WithoutConditionalCache
	// and toggleable at runtime via SetConditionalCacheEnabled.
	conditionalCacheEnabled bool

	// Client hints requested by each host via Accept-CH header
	// Key: host (e.g., "example.com"), Value: set of requested hint names
	clientHints map[string]map[string]bool

	// clientHintsEnabled gates ALL UA client hints (the always-on sec-ch-ua trio
	// AND high-entropy). Initialised from !Config.WithoutClientHints; toggle at
	// runtime with SetClientHintsEnabled. When false the request is marked so the
	// transport strips the preset trio and no high-entropy hints are injected.
	clientHintsEnabled bool

	// highEntropyClientHintsEnabled gates only the high-entropy hints (the ones
	// sent after Accept-CH). Initialised from !Config.WithoutHighEntropyClientHints;
	// toggle at runtime with SetHighEntropyClientHintsEnabled.
	highEntropyClientHintsEnabled bool

	// Key log writer for TLS traffic decryption (Wireshark)
	keyLogWriter io.WriteCloser

	// draining is set by CloseGraceful: the session is inactive but its
	// transport may still hold connections finishing in-flight responses, so a
	// later Close must still reach the transport to force them.
	draining bool

	// refreshed indicates Refresh() was called - adds cache-control: max-age=0 to requests
	refreshed bool

	// switchProtocol is the protocol to switch to on Refresh()
	switchProtocol transport.Protocol

	mu     sync.RWMutex
	active bool
}

// NewSession creates a new session with its own connection pool
func NewSession(id string, config *protocol.SessionConfig) *Session {
	return NewSessionWithOptions(id, config, nil)
}

// NewSessionWithOptions creates a new session with additional options for distributed caching etc.
func NewSessionWithOptions(id string, config *protocol.SessionConfig, opts *SessionOptions) *Session {
	if id == "" {
		id = generateID()
	}

	presetName := "chrome-latest"
	if config != nil && config.Preset != "" {
		presetName = config.Preset
	}

	if config == nil {
		config = &protocol.SessionConfig{
			Preset:  presetName,
			Timeout: 30,
		}
	}

	// Create key log writer if KeyLogFile is specified
	var keyLogWriter io.WriteCloser
	if config.KeyLogFile != "" {
		var err error
		keyLogWriter, err = transport.NewKeyLogFileWriter(config.KeyLogFile)
		if err != nil {
			// Log error but continue - key logging is optional
			keyLogWriter = nil
		}
	}

	// Create transport config with ConnectTo, ECH, TLS-only, QUIC timeout, localAddr, and session cache settings
	var transportConfig *transport.TransportConfig
	needsConfig := len(config.ConnectTo) > 0 || config.ECHConfigDomain != "" || config.TLSOnly || config.QuicIdleTimeout > 0 || config.LocalAddress != "" || keyLogWriter != nil || config.EnableSpeculativeTLS
	if opts != nil && (opts.SessionCacheBackend != nil || opts.CustomJA3 != "" || opts.CustomH2Settings != nil || len(opts.CustomPseudoOrder) > 0 || opts.CustomTCPFingerprint != nil) {
		needsConfig = true
	}

	if needsConfig {
		transportConfig = &transport.TransportConfig{
			ConnectTo:            config.ConnectTo,
			ECHConfigDomain:      config.ECHConfigDomain,
			TLSOnly:              config.TLSOnly,
			QuicIdleTimeout:      time.Duration(config.QuicIdleTimeout) * time.Second,
			LocalAddr:            config.LocalAddress,
			KeyLogWriter:         keyLogWriter,
			EnableSpeculativeTLS: config.EnableSpeculativeTLS,
		}
		// Add session cache backend if provided
		if opts != nil {
			transportConfig.SessionCacheBackend = opts.SessionCacheBackend
			transportConfig.SessionCacheErrorCallback = opts.SessionCacheErrorCallback
			// Add custom fingerprint settings
			transportConfig.CustomJA3 = opts.CustomJA3
			transportConfig.CustomJA3Extras = opts.CustomJA3Extras
			transportConfig.CustomH2Settings = opts.CustomH2Settings
			transportConfig.CustomPseudoOrder = opts.CustomPseudoOrder
			transportConfig.CustomTCPFingerprint = opts.CustomTCPFingerprint
		}
	}

	// Create transport with optional proxy and config
	var t *transport.Transport
	var proxy *transport.ProxyConfig
	if config.Proxy != "" || config.TCPProxy != "" || config.UDPProxy != "" {
		proxy = &transport.ProxyConfig{
			URL:      config.Proxy,
			TCPProxy: config.TCPProxy,
			UDPProxy: config.UDPProxy,
		}
	}
	t = transport.NewTransportWithConfig(presetName, proxy, transportConfig)

	// Wire the session timeout into the transport so it actually bounds requests
	// (dial + proxy CONNECT + TLS handshake + response). Without this the
	// transport stays on its 30s default and a stalled proxy ignores the
	// session timeout entirely. config.Timeout is in seconds (see the writers in
	// httpcloak.go and the cgo layer; the per-request override still wins).
	if config.Timeout > 0 {
		t.SetTimeout(time.Duration(config.Timeout) * time.Second)
	}

	// Disable TLS certificate verification if requested
	if config.InsecureSkipVerify {
		t.SetInsecureSkipVerify(true)
	}

	// Install caller-supplied TLS verification hooks (issue #85)
	if config.TLSVerifyPeerCertificate != nil || config.TLSVerifyConnection != nil || config.TLSRootCAs != nil {
		t.SetTLSVerify(&transport.TLSVerify{
			VerifyPeerCertificate: config.TLSVerifyPeerCertificate,
			VerifyConnection:      config.TLSVerifyConnection,
			RootCAs:               config.TLSRootCAs,
		})
	}

	// Set protocol preference
	if config.ForceHTTP1 {
		t.SetProtocol(transport.ProtocolHTTP1)
	} else if config.ForceHTTP2 {
		t.SetProtocol(transport.ProtocolHTTP2)
	} else if config.ForceHTTP3 {
		t.SetProtocol(transport.ProtocolHTTP3)
	} else if config.DisableHTTP3 {
		// Auto mode without HTTP/3, not forced HTTP/2: forcing HTTP/2 lost
		// the fallback to HTTP/1.1 for servers that only offer that (#121).
		t.SetDisableHTTP3(true)
	}

	// Set IPv4 preference
	if config.PreferIPv4 {
		if dnsCache := t.GetDNSCache(); dnsCache != nil {
			dnsCache.SetPreferIPv4(true)
		}
	}

	// Disable ECH lookup for faster first request
	if config.DisableECH {
		t.SetDisableECH(true)
	}

	// Parse switch protocol if configured
	switchProto := transport.ProtocolAuto
	if config.SwitchProtocol != "" {
		p, err := parseProtocol(config.SwitchProtocol)
		if err == nil {
			switchProto = p
		}
	}

	return &Session{
		ID:                            id,
		CreatedAt:                     time.Now(),
		LastUsed:                      time.Now(),
		RequestCount:                  0,
		Config:                        config,
		transport:                     t,
		cookies:                       NewCookieJar(),
		cacheEntries:                  make(map[string]*cacheEntry),
		conditionalCacheEnabled:       !config.WithoutConditionalCache,
		clientHints:                   make(map[string]map[string]bool),
		clientHintsEnabled:            !config.WithoutClientHints,
		highEntropyClientHintsEnabled: !config.WithoutHighEntropyClientHints,
		keyLogWriter:                  keyLogWriter,
		switchProtocol:                switchProto,
		active:                        true,
	}
}

// Request executes an HTTP request within this session
func (s *Session) Request(ctx context.Context, req *transport.Request) (*transport.Response, error) {
	return s.requestWithRedirects(ctx, req, 0, nil, nil)
}

// cloneHeaders returns a deep copy of a header map (keys + value slices).
// A nil input yields a fresh empty map, so callers can mutate the result
// freely without ever touching the source.
func cloneHeaders(h map[string][]string) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		vc := make([]string, len(v))
		copy(vc, v)
		out[k] = vc
	}
	return out
}

// requestWithRedirects handles the actual request with redirect following.
// chain is nil on the first request and carries the chain's Origin state to
// every hop after it.
func (s *Session) requestWithRedirects(ctx context.Context, req *transport.Request, redirectCount int, history []*transport.RedirectInfo, chain *redirectOrigin) (*transport.Response, error) {
	// Work on a private copy of the caller's request. The session mutates
	// req.Headers (cache-control, conditional-cache validators, cookies, client
	// hints) outside any lock the caller knows about; if a caller shares one
	// Request (and its Headers map) across goroutines on this session, those
	// mutations would race — concurrent map writes are an unrecoverable fatal
	// error, and across cgo that surfaces as a silent process crash. Copying
	// also stops cross-request contamination of the caller's map. Redirect hops
	// already build their own Request, so only the caller-supplied one is copied.
	if redirectCount == 0 {
		reqCopy := *req
		reqCopy.Headers = cloneHeaders(req.Headers)
		req = &reqCopy
		s.pinPageFetchHeaders(req)

		// Derive a replay source before anything reads the body. Without one, a
		// 307/308 hop and a retried attempt both re-send an exhausted reader:
		// an empty body under the caller's Content-Type, with no error anywhere.
		// This is the one seam every path crosses — Session.Request takes a
		// transport.Request directly, so deriving in the root package instead
		// would miss it.
		if req.BodyReader != nil && req.GetBody == nil {
			req.GetBody = transport.DeriveGetBody(req.BodyReader)
		}

		// Establish ONE overall deadline for the whole logical request. Every
		// redirect hop and every retry attempt shares it: transport.Do re-derives
		// a fresh WithTimeout(ctx, timeout) on each call, so without a single
		// parent deadline the per-attempt budgets STACK — a 1s timeout was seen
		// riding to ~4.8s across a redirect + retry burst. The per-request Timeout
		// wins; otherwise the session/transport timeout. context.WithTimeout takes
		// the earlier deadline, so transport.Do's inner wrap harmlessly clamps to
		// this and can no longer extend it. Recursion and the retry loop below
		// both use this bounded ctx; the top frame's defer keeps it alive until
		// the entire chain returns (bodies are buffered before Do returns).
		overall := req.Timeout
		if overall <= 0 && s.transport != nil {
			overall = s.transport.Timeout()
		}
		if overall > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, overall)
			defer cancel()
		}
	}

	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return nil, ErrSessionClosed
	}
	s.LastUsed = time.Now()
	s.RequestCount++

	if req.Headers == nil {
		req.Headers = make(map[string][]string)
	}

	// Add cache-control: max-age=0 if session was refreshed (simulates browser F5)
	if s.refreshed {
		req.Headers["cache-control"] = []string{"max-age=0"}
	}

	// Add cache validation headers (If-None-Match, If-Modified-Since) when
	// the conditional cache is enabled session-wide AND the per-request flag
	// hasn't opted out. Skipping here also means a fresh fetch on this URL.
	if s.conditionalCacheEnabled && !req.DisableConditionalCache {
		if cached, exists := s.cacheEntries[req.URL]; exists {
			if cached.etag != "" {
				req.Headers["If-None-Match"] = []string{cached.etag}
			}
			if cached.lastModified != "" {
				req.Headers["If-Modified-Since"] = []string{cached.lastModified}
			}
		}
	}
	s.mu.Unlock()

	// Execute request with retry logic if configured
	var resp *transport.Response
	var err error

	maxRetries := 0
	retryWaitMin := 500 * time.Millisecond
	retryWaitMax := 10 * time.Second
	var retryOnStatus []int

	if s.Config != nil && s.Config.RetryEnabled && s.Config.MaxRetries > 0 {
		maxRetries = s.Config.MaxRetries
		if s.Config.RetryWaitMin > 0 {
			retryWaitMin = time.Duration(s.Config.RetryWaitMin) * time.Millisecond
		}
		if s.Config.RetryWaitMax > 0 {
			retryWaitMax = time.Duration(s.Config.RetryWaitMax) * time.Millisecond
		}
		if len(s.Config.RetryOnStatus) > 0 {
			retryOnStatus = s.Config.RetryOnStatus
		} else {
			// Default retry status codes
			retryOnStatus = []int{429, 500, 502, 503, 504}
		}
	}

	// Extract host for client hints
	host := extractHost(req.URL)

	// Parse request URL for cookie matching
	requestHost := extractHost(req.URL)
	requestPath := extractPath(req.URL)
	requestSecure := isSecureURL(req.URL)

	// Save original per-request Cookie header before retry loop to prevent accumulation
	var origCookie string
	if c := req.Headers["Cookie"]; len(c) > 0 {
		origCookie = c[0]
	}

	// A one-shot streaming body cannot go on the wire twice. Unlike a redirect,
	// a retry is optional — we already hold a response or a real error — so a
	// non-replayable body disables the retry rather than corrupting it or
	// failing the request. Body []byte needs nothing: the transport rebuilds a
	// bytes.Reader over it on every Do.
	bodyReplayable := req.BodyReader == nil || req.GetBody != nil

	// Whether this response's Accept-CH is remembered; see learnsAcceptCH.
	learnsCH := s.learnsAcceptCH(req)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Build Cookie header fresh each attempt from original + session cookies.
		// Skip the jar lookup entirely when WithoutCookieJar — caller-provided
		// Cookie headers still pass through unchanged.
		if !s.Config.WithoutCookieJar {
			sessionCookies := s.cookies.BuildCookieHeader(requestHost, requestPath, requestSecure)
			if sessionCookies != "" {
				if origCookie != "" {
					req.Headers["Cookie"] = []string{origCookie + "; " + sessionCookies}
				} else {
					req.Headers["Cookie"] = []string{sessionCookies}
				}
			} else if origCookie != "" {
				req.Headers["Cookie"] = []string{origCookie}
			}
		}

		// Resolve client-hint policy (opt-outs + high-entropy injection). This
		// also marks req for the transport to strip the preset trio on a full
		// opt-out.
		s.applyClientHintPolicy(host, req)

		// Re-arm the streaming body for this attempt; the previous one drained
		// it. Guarded by bodyReplayable at the bottom of the loop, so GetBody is
		// never nil here.
		if attempt > 0 && req.BodyReader != nil {
			fresh, gerr := req.GetBody()
			if gerr != nil {
				return nil, fmt.Errorf("httpcloak: reopen request body for retry: %w", gerr)
			}
			req.BodyReader = fresh
		}

		resp, err = s.transport.Do(ctx, req)

		// If no error and no retry config, or this is the last attempt, break
		if maxRetries == 0 {
			break
		}

		// Extract cookies from EVERY response (even 429s, 500s, etc.)
		// This mimics browser behavior where cookies are stored regardless of status.
		// Skip when WithoutCookieJar — caller manages cookies externally.
		if resp != nil {
			if !s.Config.WithoutCookieJar {
				s.extractCookies(resp.Headers, req.URL)
			}
			// Also parse Accept-CH from intermediate responses
			if learnsCH {
				s.parseAcceptCH(host, resp.Headers)
			}
		}

		// Check if we should retry
		shouldRetry := false
		if err != nil {
			// Retry on network errors
			shouldRetry = true
		} else if resp != nil {
			// Check if status code is in retry list
			for _, status := range retryOnStatus {
				if resp.StatusCode == status {
					shouldRetry = true
					break
				}
			}
		}

		if !shouldRetry || !bodyReplayable || attempt >= maxRetries {
			break
		}

		// Calculate wait time with exponential backoff and jitter
		waitTime := retryWaitMin * time.Duration(1<<uint(attempt))
		if waitTime > retryWaitMax {
			waitTime = retryWaitMax
		}

		// Add some jitter (±25%)
		jitter := time.Duration(float64(waitTime) * 0.25)
		waitTime = waitTime - jitter + time.Duration(randInt64(int64(jitter*2)))

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(waitTime):
			// Continue to next retry attempt
		}
	}

	if err != nil {
		return nil, err
	}

	// Extract cookies from final response (in case we didn't retry or it's a success)
	if !s.Config.WithoutCookieJar {
		s.extractCookies(resp.Headers, req.URL)
	}

	// Parse Accept-CH header to store requested client hints for this host
	if learnsCH {
		s.parseAcceptCH(host, resp.Headers)
	}

	// Store cache validation headers from response for future requests, unless
	// the conditional cache is disabled session-wide or the caller asked to
	// skip it for this request.
	if s.conditionalCacheEnabled && !req.DisableConditionalCache {
		s.storeCacheHeaders(req.URL, resp.Headers)
	}

	// Handle redirects
	if isRedirectStatus(resp.StatusCode) {
		// Per-request override (req.FollowRedirects, when non-nil) wins over the
		// session-level Config.FollowRedirects. Default is to follow.
		followRedirects := true
		maxRedirects := 10
		if s.Config != nil {
			followRedirects = s.Config.FollowRedirects
			if s.Config.MaxRedirects > 0 {
				maxRedirects = s.Config.MaxRedirects
			}
		}
		if req.FollowRedirects != nil {
			followRedirects = *req.FollowRedirects
		}

		if followRedirects {
			if redirectCount >= maxRedirects {
				// Hand back the response carrying the last Location alongside
				// the error, the way net/http.Client.do does when CheckRedirect
				// fails. No socket rides on it — transport.Do has already
				// buffered the body into a NopCloser — so a caller that ignores
				// resp leaks nothing, and one that wants to know where the chain
				// ended up can read it.
				resp.History = history
				return resp, fmt.Errorf("%w (max %d)", transport.ErrTooManyRedirects, maxRedirects)
			}

			// Get Location header (first value from slice)
			location := ""
			if locs := resp.Headers["Location"]; len(locs) > 0 {
				location = locs[0]
			}
			if location == "" {
				if locs := resp.Headers["location"]; len(locs) > 0 {
					location = locs[0]
				}
			}
			if location == "" {
				// No Location header, set history and return as-is
				resp.History = history
				return resp, nil
			}

			// Resolve relative URL
			redirectURL := resolveURL(req.URL, location)

			// Determine new method
			newMethod := req.Method
			if resp.StatusCode == 303 || ((resp.StatusCode == 301 || resp.StatusCode == 302) && req.Method == "POST") {
				newMethod = "GET"
			}

			// Browser-parity credential policy for the new hop: a cross-origin
			// hop (any scheme change or host/port change), which includes every
			// https → http downgrade, strips Authorization and
			// Proxy-Authorization. Chrome, Firefox, curl (≥7.58) and Fetch's
			// "HTTP-redirect fetch" all do this to prevent credential leaks.
			// The Referer follows its own rule, judged against the Referer
			// itself rather than the URL that issued the 3xx; see
			// redirectReferer. Computed here rather than beside the header loop
			// because the callback below is handed both.
			schemeDowngrade := isSchemeDowngrade(req.URL, redirectURL)
			crossOrigin := !sameOrigin(req.URL, redirectURL)

			// Ask the caller before taking the hop. This runs after the cap
			// check on purpose: the cap is a resource bound, not a policy
			// question, and letting a veto answer it first would turn a
			// "too many redirects" error into a silent success.
			//
			// history still holds only the hops BEFORE this one, because the
			// append below has not run yet — so a halted 3xx does not appear in
			// its own History, matching the no-Location return above.
			if req.OnRedirect != nil {
				hop := &transport.Redirect{
					Hop:             redirectCount + 1,
					StatusCode:      resp.StatusCode,
					Headers:         resp.Headers,
					From:            req.URL,
					To:              redirectURL,
					Method:          newMethod,
					CrossOrigin:     crossOrigin,
					SchemeDowngrade: schemeDowngrade,
				}
				if err := req.OnRedirect(hop); err != nil {
					if errors.Is(err, transport.ErrUseLastResponse) {
						resp.History = history
						return resp, nil
					}
					// Unwrapped, so errors.Is against the caller's own sentinel
					// matches exactly what they returned.
					return nil, err
				}
			}

			// An exact header list keeps its Referer pair to the same rule as the
			// header below. Leaving a lone Referer out would empty the list,
			// and an empty list switches exact mode off, so that hop would go
			// out with the whole preset pipeline the caller replaced; stop
			// instead.
			exactHeaders, ok := exactHeadersForHop(req.ExactHeaders, redirectURL, req.DisableRedirectReferer)
			if !ok {
				resp.History = history
				return resp, fmt.Errorf("cannot follow %d redirect to %s: the hop drops the "+
					"Referer, the only pair in ExactHeaders, and an empty list would send "+
					"the preset's headers instead", resp.StatusCode, redirectURL)
			}
			// The hop's Origin is worked out afresh, from the request's origin
			// and mode as the first request set them, this hop's method, and the
			// URLs the chain has been through; see redirectOrigin. An exact
			// header list keeps its Origin pair to the same rule, in its own slot
			// and spelling.
			if chain == nil {
				chain = s.newRedirectOrigin(req)
			}
			hopOrigin, sendOrigin := chain.next(req.URL, redirectURL, newMethod)
			if chain.mode != "" {
				exactHeaders = exactOriginForHop(exactHeaders, hopOrigin, sendOrigin)
			}

			// Create redirect request. Everything below the first four fields is
			// a property of the caller's request rather than of one hop, and
			// dropping them silently downgraded every hop after the first back to
			// the session-wide defaults: a request that asked for TLS-only or no
			// client hints got it on hop 0 only, FollowRedirects: &true against a
			// session defaulting to false stopped after one hop, and the
			// per-request Timeout fell back to the transport's. HeaderOrder rides
			// along because the caller's headers do (see the copy loop below): a
			// header they slotted explicitly on this hop would otherwise be
			// re-placed by the preset table or the sorted tail on the next one,
			// so the ordering has to follow the headers it orders or the two
			// disagree mid-chain.
			newReq := &transport.Request{
				Method:                        newMethod,
				URL:                           redirectURL,
				Headers:                       make(map[string][]string),
				HeaderOrder:                   req.HeaderOrder,
				Timeout:                       req.Timeout,
				TLSOnly:                       req.TLSOnly,
				FollowRedirects:               req.FollowRedirects,
				DisableConditionalCache:       req.DisableConditionalCache,
				DisableClientHints:            req.DisableClientHints,
				DisableHighEntropyClientHints: req.DisableHighEntropyClientHints,
				DisableRedirectReferer:        req.DisableRedirectReferer,
				OnRedirect:                    req.OnRedirect,

				// A browser settles a hop's Referer differently from a first
				// request's, and Firefox orders the hop's headers to match. The
				// page API that made the request is the same on every hop.
				RedirectHop: true,
				Initiator:   req.Initiator,

				// ExactHeaders has to survive the hop. Its whole contract is that
				// nothing else is added, and dropping it here meant a caller
				// mirroring a captured request got their exact bytes on the first
				// request and the full preset pipeline on every hop after it,
				// silently. The transport ignores Headers in that mode, so a
				// Referer pair and an Origin pair are the only things in it the
				// hop rewrites, each in its own slot and spelling; see
				// exactHeadersForHop and exactOriginForHop.
				ExactHeaders: exactHeaders,
			}

			// Copy safe headers
			for k, v := range req.Headers {
				// Don't copy Content-* headers on method change
				if newMethod != req.Method && (k == "Content-Type" || k == "Content-Length" || k == "content-type" || k == "content-length") {
					continue
				}
				// Don't copy Cookie header (will be re-added from session)
				if k == "Cookie" || k == "cookie" {
					continue
				}
				lk := strings.ToLower(k)
				// Referer is worked out below, from this request's value.
				if lk == "referer" {
					continue
				}
				if (crossOrigin || schemeDowngrade) && (lk == "authorization" || lk == "proxy-authorization") {
					continue
				}
				// Origin is worked out below, unless the chain leaves it alone.
				if lk == "origin" && chain.mode != "" {
					continue
				}
				newReq.Headers[k] = v
			}

			// The next hop's Referer is this request's Referer with the
			// referrer policy applied again for the new URL. Chrome, Firefox
			// and WebKit all do this; Fetch's main fetch runs "determine
			// request's referrer" on every hop. It is never the URL that issued
			// the 3xx: a page whose fetch() is redirected names the page on
			// both hops, and a typed navigation that redirects sends no Referer
			// on either. Each hop starts from what the hop before it sent, so a
			// Referer trimmed to its origin stays trimmed and one dropped on an
			// https->http hop stays dropped, even when the chain comes back to
			// where it started. The caller's spelling of the name is kept.
			//
			// DisableRedirectReferer sends no Referer on any hop, including one
			// the caller set on the original request: carrying that forward
			// would hand the new host exactly what the caller asked us not to
			// send.
			if key, ref := refererHeader(req.Headers); key != "" && !req.DisableRedirectReferer {
				if next := redirectReferer(ref, redirectURL); next != "" {
					newReq.Headers[key] = []string{next}
				}
			}

			// The next hop's Sec-Fetch-Site follows from the value this hop
			// carried; see redirectFetchSite. Only a value the caller set can
			// move. A preset's own is none for a navigation and cross-site for
			// a request sniffed as fetch(), neither of which a hop changes, and
			// the transport writes it again on the hop. The value is replaced
			// under the caller's spelling of the name: a second spelling would
			// leave the transport two values to pick from.
			for k, v := range newReq.Headers {
				if len(v) == 0 || !strings.EqualFold(k, "Sec-Fetch-Site") {
					continue
				}
				if next := redirectFetchSite(v[0], req.URL, redirectURL); next != v[0] {
					newReq.Headers[k] = []string{next}
				}
			}
			// The transport never reads Headers under ExactHeaders, so there
			// the pair in the list is the one that reaches the wire.
			newReq.ExactHeaders = exactHeadersFetchSiteForHop(newReq.ExactHeaders, req.URL, redirectURL)
			// The Origin worked out above goes under the caller's spelling of
			// the name, or the canonical one on a hop that gains it.
			if chain.mode != "" && sendOrigin {
				key, _ := headerEntry(req.Headers, "Origin")
				if key == "" {
					key = "Origin"
				}
				newReq.Headers[key] = []string{hopOrigin}
			}
			// A chain the transport sniffed into cors mode stays in it. The sniff
			// reads each hop afresh, and once a 303 has turned a fetch-shaped
			// POST into a bare GET it would send the hop as a navigation, with a
			// navigation's Accept, while Chrome and Firefox keep the request's
			// mode. Naming the mode keeps the hop's Sec-Fetch-* and its Origin
			// in step. A hop that keeps its method sniffs the same as before, so
			// only a method change needs it.
			if chain.sniffed && newMethod != req.Method {
				newReq.Headers["Sec-Fetch-Mode"] = []string{"cors"}
			}

			// 307/308 preserve the method and the body. Precedence matches the
			// transport's own: BodyReader wins over Body.
			//
			// A streaming BodyReader was drained by the hop that just finished,
			// so it is re-opened from GetBody — which rides along too, or a
			// second 307 in the same chain would find nothing to re-open. With
			// neither, stop: this used to copy Body alone, and since Session.Do
			// only ever populates BodyReader, every 307 through the root session
			// sent the next hop with no body at all under the caller's
			// Content-Type. Nothing errored and nothing short-wrote.
			if resp.StatusCode == 307 || resp.StatusCode == 308 {
				switch {
				case req.BodyReader != nil && req.GetBody != nil:
					fresh, gerr := req.GetBody()
					if gerr != nil {
						resp.History = history
						return resp, fmt.Errorf("httpcloak: reopen request body for %d redirect to %s: %w",
							resp.StatusCode, redirectURL, gerr)
					}
					newReq.BodyReader = fresh
					newReq.GetBody = req.GetBody
				case req.BodyReader != nil:
					resp.History = history
					return resp, fmt.Errorf("cannot follow %d redirect to %s: %w",
						resp.StatusCode, redirectURL, transport.ErrBodyNotReplayable)
				default:
					newReq.Body = req.Body
				}
			}

			// Add this response to the history only now that the hop is
			// certain to be taken. Every early return above therefore sees a
			// history of the hops before it, and no response ever appears in
			// its own History.
			history = append(history, &transport.RedirectInfo{
				StatusCode: resp.StatusCode,
				URL:        req.URL,
				Headers:    resp.Headers,
			})

			// Release the intermediate 3xx. The body is a NopCloser over a
			// buffer the transport already drained, so this frees nothing today;
			// it stops being a no-op the moment body streaming reaches Do.
			resp.Close()

			// Follow redirect with accumulated history
			return s.requestWithRedirects(ctx, newReq, redirectCount+1, history, chain)
		}
	}

	// Set history on final response
	resp.History = history
	return resp, nil
}

// randInt64 generates a random int64 in range [0, n)
func randInt64(n int64) int64 {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 8)
	rand.Read(b)
	v := int64(b[0]) | int64(b[1])<<8 | int64(b[2])<<16 | int64(b[3])<<24 |
		int64(b[4])<<32 | int64(b[5])<<40 | int64(b[6])<<48 | int64(b[7]&0x7f)<<56
	return v % n
}

// Get performs a GET request
func (s *Session) Get(ctx context.Context, url string, headers map[string][]string) (*transport.Response, error) {
	return s.Request(ctx, &transport.Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// Post performs a POST request
func (s *Session) Post(ctx context.Context, url string, body []byte, headers map[string][]string) (*transport.Response, error) {
	return s.Request(ctx, &transport.Request{
		Method:  "POST",
		URL:     url,
		Body:    body,
		Headers: headers,
	})
}

// extractCookies extracts cookies with full metadata from response headers
// requestURL is the URL that was requested (needed for domain scoping)
func (s *Session) extractCookies(headers map[string][]string, requestURL string) {
	// Try both cases - some responses might have different casing
	setCookies, exists := headers["set-cookie"]
	if !exists {
		setCookies, exists = headers["Set-Cookie"]
	}
	if !exists || len(setCookies) == 0 {
		return
	}

	requestHost := extractHost(requestURL)
	requestSecure := isSecureURL(requestURL)

	// Each Set-Cookie header is now a separate element in the slice
	for _, line := range setCookies {
		line = trim(line)
		if line == "" {
			continue
		}

		cookie := &CookieData{}

		// Split by semicolon to get name=value and attributes
		parts := splitBySemicolon(line)
		if len(parts) == 0 {
			continue
		}

		// First part is name=value
		firstPart := trim(parts[0])
		eqIdx := indexOf(firstPart, "=")
		if eqIdx == -1 {
			continue
		}
		cookie.Name = trim(firstPart[:eqIdx])
		cookie.Value = trim(firstPart[eqIdx+1:])
		if cookie.Name == "" {
			continue
		}

		// Parse attributes
		for i := 1; i < len(parts); i++ {
			attr := trim(parts[i])
			if attr == "" {
				continue
			}

			attrLower := toLowerASCII(attr)

			// Check for flag attributes (no value)
			if attrLower == "secure" {
				cookie.Secure = true
				continue
			}
			if attrLower == "httponly" {
				cookie.HttpOnly = true
				continue
			}

			// Check for key=value attributes
			attrEqIdx := indexOf(attr, "=")
			if attrEqIdx == -1 {
				continue
			}

			attrName := toLowerASCII(trim(attr[:attrEqIdx]))
			attrValue := trim(attr[attrEqIdx+1:])

			switch attrName {
			case "domain":
				cookie.Domain = attrValue
			case "path":
				cookie.Path = attrValue
			case "expires":
				// Parse expiration time
				if t, err := parseHTTPDate(attrValue); err == nil {
					cookie.Expires = &t
				}
			case "max-age":
				// RFC 6265 Section 5.2.2: a Max-Age of 0 or less expires the
				// cookie, and MaxAge 0 means none, so it is stored as -1. As
				// in Chrome and Firefox, the last Max-Age decides, and an
				// invalid one leaves none.
				maxAge, ok := parseIntSimple(attrValue)
				if !ok {
					maxAge = 0
				} else if maxAge <= 0 {
					maxAge = -1
				}
				cookie.MaxAge = maxAge
			case "samesite":
				// Normalize to capitalized form
				sameSiteLower := toLowerASCII(attrValue)
				switch sameSiteLower {
				case "strict":
					cookie.SameSite = "Strict"
				case "lax":
					cookie.SameSite = "Lax"
				case "none":
					cookie.SameSite = "None"
				default:
					cookie.SameSite = attrValue
				}
			}
		}

		// Max-Age takes precedence over Expires (RFC 6265 Section 5.3). The
		// jar checks only Expires, so Max-Age becomes one here.
		if cookie.MaxAge != 0 {
			expires := time.Unix(0, 0)
			if cookie.MaxAge > 0 {
				// A Max-Age longer than a time.Duration can hold gets the longest one
				lifetime := time.Duration(1<<63 - 1)
				if int64(cookie.MaxAge) < int64(lifetime/time.Second) {
					lifetime = time.Duration(cookie.MaxAge) * time.Second
				}
				expires = time.Now().Add(lifetime)
			}
			cookie.Expires = &expires
		}

		// Use CookieJar to store with proper domain scoping
		s.cookies.Set(requestHost, cookie, requestSecure)
	}
}

// splitBySemicolon splits a string by semicolon
func splitBySemicolon(s string) []string {
	var result []string
	var current string
	for i := 0; i < len(s); i++ {
		if s[i] == ';' {
			result = append(result, current)
			current = ""
		} else {
			current += string(s[i])
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// parseIntSimple parses a decimal integer with an optional leading "-". ok is
// false for anything else, such as "", "-", "+1" or "1abc". A value too large
// for an int stops at the largest one, so that it cannot wrap around
func parseIntSimple(s string) (int, bool) {
	const maxInt = int(^uint(0) >> 1)
	result := 0
	negative := false
	start := 0
	if len(s) > 0 && s[0] == '-' {
		negative = true
		start = 1
	}
	if start == len(s) {
		return 0, false
	}
	for i := start; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		if d := int(s[i] - '0'); result <= (maxInt-d)/10 {
			result = result*10 + d
		} else {
			result = maxInt
		}
	}
	if negative {
		result = -result
	}
	return result, true
}

// parseHTTPDate parses an HTTP date string (RFC1123 format)
func parseHTTPDate(s string) (time.Time, error) {
	// Try RFC1123 format first (most common)
	if t, err := time.Parse(time.RFC1123, s); err == nil {
		return t, nil
	}
	// Try RFC1123Z (with numeric timezone)
	if t, err := time.Parse(time.RFC1123Z, s); err == nil {
		return t, nil
	}
	// Try RFC850 (obsolete but still used)
	if t, err := time.Parse(time.RFC850, s); err == nil {
		return t, nil
	}
	// Try ANSI C format
	if t, err := time.Parse(time.ANSIC, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unable to parse date: %s", s)
}

// storeCacheHeaders extracts and stores cache validation headers from response
// These headers will be sent on subsequent requests to the same URL
func (s *Session) storeCacheHeaders(url string, headers map[string][]string) {
	// Helper to get first value from header (case-insensitive)
	getHeader := func(key string) string {
		if values := headers[key]; len(values) > 0 {
			return values[0]
		}
		return ""
	}

	// Look for ETag header (case-insensitive)
	etag := getHeader("etag")
	if etag == "" {
		etag = getHeader("ETag")
	}

	// Look for Last-Modified header (case-insensitive)
	lastModified := getHeader("last-modified")
	if lastModified == "" {
		lastModified = getHeader("Last-Modified")
	}

	// Only store if we have at least one cache header
	if etag == "" && lastModified == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cacheEntries[url] = &cacheEntry{
		etag:         etag,
		lastModified: lastModified,
	}
}

// learnsAcceptCH reports whether the Accept-CH on the response to req is
// remembered. Chrome parses Accept-CH only on the response to an outermost
// main-frame navigation (ParseAndPersistAcceptCHForNavigation in
// content/browser/client_hints/client_hints.cc), so a frame's document, a
// fetch and a subresource can ask for hints and get none. That is the request
// sent with Sec-Fetch-Dest: document. One sent with no Sec-Fetch-Dest at all,
// TLS-only or a preset that sends no Sec-Fetch metadata, says nothing either
// way and is treated as a navigation, as every request used to be.
func (s *Session) learnsAcceptCH(req *transport.Request) bool {
	dest := s.transport.SentFetchDest(req)
	return dest == "" || strings.EqualFold(dest, "document")
}

// parseAcceptCH parses the Accept-CH response header and stores the requested client hints
// for the given host. On subsequent requests to this host, the session will send the
// high-entropy client hints that were requested.
func (s *Session) parseAcceptCH(host string, headers map[string][]string) {
	// Helper to get first value from header (case-insensitive)
	getHeader := func(key string) string {
		if values := headers[key]; len(values) > 0 {
			return values[0]
		}
		return ""
	}

	// Look for Accept-CH header (case-insensitive)
	acceptCH := getHeader("accept-ch")
	if acceptCH == "" {
		acceptCH = getHeader("Accept-CH")
	}
	if acceptCH == "" {
		return
	}
	// A browser without UA client hints does not act on Accept-CH at all; see
	// resolveClientHints.
	if s.resolveClientHints().UA == "" {
		return
	}

	// Parse the comma-separated list of hint names
	hints := make(map[string]bool)
	for _, hint := range splitByComma(acceptCH) {
		hint = trim(toLowerASCII(hint))
		if hint != "" {
			hints[hint] = true
		}
	}

	if len(hints) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.clientHints[host] = hints
}

// applyClientHintPolicy resolves the per-request client-hint gating (the
// session-wide toggles combined with the per-request flags), mutates req so the
// transport strips the always-on sec-ch-ua trio on a full opt-out, and injects
// the high-entropy hints when they are allowed and the host has advertised
// Accept-CH. Shared by the buffered and streaming dispatch paths so both behave
// identically.
func (s *Session) applyClientHintPolicy(host string, req *transport.Request) {
	s.mu.RLock()
	chEnabled := s.clientHintsEnabled
	heEnabled := s.highEntropyClientHintsEnabled
	s.mu.RUnlock()

	// Full opt-out (per-request flag OR session-wide): the transport strips the
	// preset sec-ch-* trio when req.DisableClientHints is set, and a full opt-out
	// implies no high-entropy hints either.
	if req.DisableClientHints || !chEnabled {
		req.DisableClientHints = true
		return
	}

	// High-entropy opt-out: keep the always-on trio, skip the Accept-CH hints.
	if req.DisableHighEntropyClientHints || !heEnabled {
		return
	}

	if req.Headers == nil {
		req.Headers = make(map[string][]string)
	}
	s.applyClientHints(host, req.Headers)
}

// clientHintsFor returns the high-entropy client hints host has advertised via
// Accept-CH, header name to value. The values come from the resolved preset
// (Preset.ResolveClientHints), so they stay coherent with the preset's sec-ch-ua
// trio and User-Agent. applyClientHints sends exactly these and ClientHintsFor
// reports them, so the injector and the getter cannot drift apart.
func (s *Session) clientHintsFor(host string) map[string]string {
	s.mu.RLock()
	hints, exists := s.clientHints[host]
	s.mu.RUnlock()

	if !exists || len(hints) == 0 {
		return nil
	}

	ch := s.resolveClientHints()

	// Map of Accept-CH hint names to their header name and resolved value.
	hintValues := map[string]struct {
		header string
		value  string
	}{
		"sec-ch-ua-arch":              {"Sec-Ch-Ua-Arch", ch.UAArch},
		"sec-ch-ua-bitness":           {"Sec-Ch-Ua-Bitness", ch.UABitness},
		"sec-ch-ua-full-version":      {"Sec-Ch-Ua-Full-Version", ch.UAFullVersion},
		"sec-ch-ua-full-version-list": {"Sec-Ch-Ua-Full-Version-List", ch.UAFullVersionList},
		"sec-ch-ua-model":             {"Sec-Ch-Ua-Model", ch.UAModel},
		"sec-ch-ua-platform-version":  {"Sec-Ch-Ua-Platform-Version", ch.UAPlatformVersion},
		"sec-ch-ua-wow64":             {"Sec-Ch-Ua-Wow64", ch.UAWow64},
	}

	out := make(map[string]string, len(hints))
	for hintName, hintInfo := range hintValues {
		if !hints[hintName] || hintInfo.value == "" {
			continue
		}
		out[hintInfo.header] = hintInfo.value
	}
	return out
}

// applyClientHints adds the high-entropy client hints to the request if the host
// has previously advertised them via Accept-CH; see clientHintsFor. A hint the
// caller already set explicitly is never overwritten (matched
// case-insensitively), which makes per-request overrides deterministic.
func (s *Session) applyClientHints(host string, headers map[string][]string) {
	for name, value := range s.clientHintsFor(host) {
		// Don't clobber a value the caller supplied (any header case).
		if headerKeyPresent(headers, name) {
			continue
		}
		headers[name] = []string{value}
	}
}

// resolveClientHints returns the coherent UA client hints for this session's
// preset. Looking the preset up by name mirrors how the transport built it, so
// the hints reflect the projected identity rather than the local machine.
//
// A preset that sends no sec-ch-ua gets none at all. Only Chromium implements
// UA client hints: Firefox and Safari send no sec-ch-* header and ignore
// Accept-CH, and Chrome on iOS runs on WebKit. Firefox 159, asked for three
// high-entropy hints by a navigation's Accept-CH, sent no sec-ch-* on that page
// or after it. The resolved high-entropy values are platform defaults, which
// filled in for those presets and went out as five headers no such browser
// sends.
func (s *Session) resolveClientHints() fingerprint.ClientHints {
	presetName := "chrome-latest"
	if s.Config != nil && s.Config.Preset != "" {
		presetName = s.Config.Preset
	}
	if p := fingerprint.Get(presetName); p != nil {
		if ch := p.ResolveClientHints(); ch.UA != "" {
			return ch
		}
	}
	return fingerprint.ClientHints{}
}

// headerKeyPresent reports whether headers already contains key, comparing keys
// case-insensitively (callers may pass "sec-ch-ua-..." while we store the
// canonical "Sec-Ch-Ua-...").
func headerKeyPresent(headers map[string][]string, key string) bool {
	if _, ok := headers[key]; ok {
		return true
	}
	for k := range headers {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

// SetClientHintsEnabled toggles all UA client hints (trio + high-entropy) at
// runtime. When disabled, requests carry only the sec-ch-* headers the caller
// sets explicitly.
func (s *Session) SetClientHintsEnabled(enabled bool) {
	s.mu.Lock()
	s.clientHintsEnabled = enabled
	s.mu.Unlock()
}

// ClientHintsEnabled reports whether UA client hints are currently enabled.
func (s *Session) ClientHintsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientHintsEnabled
}

// SetHighEntropyClientHintsEnabled toggles only the high-entropy hints at
// runtime; the always-on sec-ch-ua trio is unaffected.
func (s *Session) SetHighEntropyClientHintsEnabled(enabled bool) {
	s.mu.Lock()
	s.highEntropyClientHintsEnabled = enabled
	s.mu.Unlock()
}

// HighEntropyClientHintsEnabled reports whether the high-entropy hints are
// currently enabled.
func (s *Session) HighEntropyClientHintsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.highEntropyClientHintsEnabled
}

// AcceptCH returns the client hints host asked for in Accept-CH, lowercase and
// sorted, or nil when it has asked for none. host is a host name, or a URL,
// matched the way a request's URL is.
func (s *Session) AcceptCH(host string) []string {
	host = extractHost(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.clientHints[host]) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(s.clientHints[host]))
}

// SetAcceptCH records hints as what host asked for in Accept-CH, replacing what
// the session had from it, as a new Accept-CH does. Chrome keeps each host's
// Accept-CH across restarts, so a host that asked last week gets the hints on
// the first request of the next visit; this is how a session rebuilt from
// stored state does the same, or how one is warmed for a host that is known to
// ask. Empty forgets the host.
func (s *Session) SetAcceptCH(host string, hints []string) {
	host = extractHost(host)
	set := make(map[string]bool, len(hints))
	for _, hint := range hints {
		if hint = trim(toLowerASCII(hint)); hint != "" {
			set[hint] = true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(set) == 0 {
		delete(s.clientHints, host)
		return
	}
	s.clientHints[host] = set
}

// ClientHintsFor returns the high-entropy client hints the session adds to a
// request to host, lowercase header name to value: what host asked for in
// Accept-CH, with the preset's values. It is nil when host asked for none, or
// when the session's client hints or high-entropy hints are turned off. A
// request's own DisableClientHints or DisableHighEntropyClientHints, and a hint
// it sets itself, still take precedence on that request.
func (s *Session) ClientHintsFor(host string) map[string]string {
	s.mu.RLock()
	on := s.clientHintsEnabled && s.highEntropyClientHintsEnabled
	s.mu.RUnlock()
	if !on {
		return nil
	}
	hints := s.clientHintsFor(extractHost(host))
	if len(hints) == 0 {
		return nil
	}
	out := make(map[string]string, len(hints))
	for name, value := range hints {
		out[strings.ToLower(name)] = value
	}
	return out
}

// exportAcceptCH returns what each host asked for in Accept-CH, for the saved
// state. The caller holds s.mu.
func (s *Session) exportAcceptCH() map[string][]string {
	if len(s.clientHints) == 0 {
		return nil
	}
	out := make(map[string][]string, len(s.clientHints))
	for host, hints := range s.clientHints {
		if len(hints) > 0 {
			out[host] = slices.Sorted(maps.Keys(hints))
		}
	}
	return out
}

// importAcceptCH restores what exportAcceptCH saved. The caller holds s.mu.
func (s *Session) importAcceptCH(saved map[string][]string) {
	for host, hints := range saved {
		set := make(map[string]bool, len(hints))
		for _, hint := range hints {
			if hint = trim(toLowerASCII(hint)); hint != "" {
				set[hint] = true
			}
		}
		if len(set) > 0 {
			s.clientHints[host] = set
		}
	}
}

// Helper functions for client hints
func splitByComma(s string) []string {
	var result []string
	var current string
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(s[i])
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func toLowerASCII(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + 32
		}
		result[i] = c
	}
	return string(result)
}

func contains(s, substr string) bool {
	return indexOf(s, substr) != -1
}

// extractHost extracts the host from a URL string
func extractHost(urlStr string) string {
	// Remove protocol prefix
	host := urlStr
	if idx := indexOf(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	// Remove path
	if idx := indexOf(host, "/"); idx != -1 {
		host = host[:idx]
	}
	// Remove port for matching (IPv6-aware)
	if len(host) > 0 && host[0] == '[' {
		// IPv6 bracketed: [::1]:443 → ::1
		if idx := indexOf(host, "]"); idx != -1 {
			host = host[1:idx]
		}
	} else if idx := indexOf(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}

// extractPath extracts the path from a URL string
func extractPath(urlStr string) string {
	// Remove protocol prefix
	path := urlStr
	if idx := indexOf(path, "://"); idx != -1 {
		path = path[idx+3:]
	}
	// Find path start
	if idx := indexOf(path, "/"); idx != -1 {
		path = path[idx:]
		// Remove query string
		if qIdx := indexOf(path, "?"); qIdx != -1 {
			path = path[:qIdx]
		}
		// Remove fragment
		if fIdx := indexOf(path, "#"); fIdx != -1 {
			path = path[:fIdx]
		}
		return path
	}
	return "/"
}

// isSecureURL returns true if the URL uses HTTPS
func isSecureURL(urlStr string) bool {
	return len(urlStr) >= 8 && urlStr[:8] == "https://"
}

// IsActive returns whether the session is active
func (s *Session) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

// Close marks the session as inactive and closes connections immediately,
// including any left draining by an earlier CloseGraceful.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active && !s.draining {
		return
	}
	s.active = false
	s.draining = false

	if s.transport != nil {
		s.transport.Close()
	}
	s.closeKeyLog()
}

// CloseGraceful marks the session as inactive and closes its connections
// without interrupting requests that are in flight: idle connections close
// now, and a connection with a response body still streaming closes when the
// body finishes. It returns immediately. Close may be called afterwards to
// force whatever is still draining.
func (s *Session) CloseGraceful() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return
	}
	s.active = false
	s.draining = true

	if s.transport != nil {
		s.transport.CloseGraceful()
	}
	// No handshake happens after this point, so nothing more is logged.
	s.closeKeyLog()
}

// closeKeyLog closes the key log writer if we opened one. Caller holds s.mu.
func (s *Session) closeKeyLog() {
	if s.keyLogWriter != nil {
		s.keyLogWriter.Close()
		s.keyLogWriter = nil
	}
}

// parseProtocol converts a protocol string to transport.Protocol.
func parseProtocol(proto string) (transport.Protocol, error) {
	switch proto {
	case "h1", "http1", "1":
		return transport.ProtocolHTTP1, nil
	case "h2", "http2", "2":
		return transport.ProtocolHTTP2, nil
	case "h3", "http3", "3":
		return transport.ProtocolHTTP3, nil
	case "auto", "":
		return transport.ProtocolAuto, nil
	default:
		return transport.ProtocolAuto, fmt.Errorf("invalid protocol %q: must be h1, h2, h3, or auto", proto)
	}
}

// Refresh closes all connections but keeps TLS session caches and cookies intact.
// This simulates a browser page refresh - new TCP/QUIC connections but TLS resumption.
// If a switchProtocol was configured, the session switches to that protocol.
func (s *Session) Refresh() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return
	}

	// Set refreshed flag - adds cache-control: max-age=0 to subsequent requests
	s.refreshed = true

	if s.transport != nil {
		if s.switchProtocol != transport.ProtocolAuto {
			s.transport.RefreshWithProtocol(s.switchProtocol)
		} else {
			s.transport.Refresh()
		}
	}
}

// RefreshWithProtocol closes all connections and switches to a new protocol.
// The protocol change persists for future Refresh() calls as well.
// Valid protocols: "h1", "h2", "h3", "auto".
func (s *Session) RefreshWithProtocol(proto string) error {
	p, err := parseProtocol(proto)
	if err != nil {
		return err
	}

	// Validate H3 support if switching to H3
	if p == transport.ProtocolHTTP3 && s.Config != nil {
		preset := fingerprint.Get(s.Config.Preset)
		if preset != nil && !preset.SupportHTTP3 {
			return fmt.Errorf("preset %q does not support HTTP/3", s.Config.Preset)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return ErrSessionClosed
	}

	s.refreshed = true
	s.switchProtocol = p

	if s.transport != nil {
		s.transport.RefreshWithProtocol(p)
	}

	return nil
}

// Touch updates the last used timestamp
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastUsed = time.Now()
}

// GetCookies returns all cookies with full metadata
func (s *Session) GetCookies() []CookieState {
	return s.cookies.GetAll()
}

// GetCookiesDetailed is an alias for GetCookies, returning full cookie metadata.
func (s *Session) GetCookiesDetailed() []CookieState {
	return s.cookies.GetAll()
}

// SetCookie sets a cookie with full metadata.
// If domain is empty, creates a global cookie (sent to all domains).
func (s *Session) SetCookie(name, value, domain, path string, secure, httpOnly bool, sameSite string, maxAge int, expires *time.Time) {
	s.cookies.SetSimple(name, value, domain, path, secure, httpOnly, sameSite, maxAge, expires)
}

// SetCookies sets multiple cookies from CookieState entries
func (s *Session) SetCookies(cookies []CookieState) {
	for _, c := range cookies {
		s.cookies.SetSimple(c.Name, c.Value, c.Domain, c.Path, c.Secure, c.HttpOnly, c.SameSite, c.MaxAge, c.Expires)
	}
}

// DeleteCookie removes cookies by name. If domain is empty, removes from all domains.
func (s *Session) DeleteCookie(name, domain string) {
	s.cookies.Delete(name, domain)
}

// ClearCookies removes all cookies from this session
func (s *Session) ClearCookies() {
	s.cookies.Clear()
}

// ClearCache clears all cached URLs (removes If-None-Match/If-Modified-Since headers)
func (s *Session) ClearCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cacheEntries = make(map[string]*cacheEntry)
}

// SetConditionalCacheEnabled toggles the session's ETag / If-Modified-Since
// handling at runtime. When false, the session stops injecting cache
// validators and stops storing them from responses; the existing cache map
// is preserved (re-enabling will resume using it). To wipe the stored
// validators, pair this with ClearCache.
func (s *Session) SetConditionalCacheEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conditionalCacheEnabled = enabled
}

// ConditionalCacheEnabled reports whether the session is currently injecting
// and storing ETag / If-Modified-Since validators.
func (s *Session) ConditionalCacheEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.conditionalCacheEnabled
}

// SetFollowRedirects toggles the session's redirect-following policy at
// runtime. Per-request overrides via transport.Request.FollowRedirects still
// take precedence over this value.
func (s *Session) SetFollowRedirects(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Config == nil {
		s.Config = &protocol.SessionConfig{}
	}
	s.Config.FollowRedirects = enabled
}

// SetMaxRedirects updates the session's redirect cap at runtime. A value of
// zero or below leaves the cap at the prior setting (or the default of 10
// if none was configured).
func (s *Session) SetMaxRedirects(max int) {
	if max <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Config == nil {
		s.Config = &protocol.SessionConfig{}
	}
	s.Config.MaxRedirects = max
}

// FollowRedirects reports the session's current redirect-following policy.
// Returns true when the session will follow redirects by default; per-request
// overrides can still flip the behaviour for a single call.
func (s *Session) FollowRedirects() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.Config == nil {
		return true
	}
	return s.Config.FollowRedirects
}

// MaxRedirects reports the session's current redirect cap. Returns the
// configured value, or 10 (the default applied in requestWithRedirects)
// when nothing has been set.
func (s *Session) MaxRedirects() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.Config == nil || s.Config.MaxRedirects <= 0 {
		return 10
	}
	return s.Config.MaxRedirects
}

// SetProxy sets or updates the proxy for all protocols (HTTP/1.1, HTTP/2, HTTP/3)
// This closes existing connections and recreates transports with the new proxy
func (s *Session) SetProxy(proxyURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.transport != nil {
		var proxy *transport.ProxyConfig
		if proxyURL != "" {
			proxy = &transport.ProxyConfig{URL: proxyURL}
		}
		s.transport.SetProxy(proxy)
	}

	// Update config
	if s.Config != nil {
		s.Config.Proxy = proxyURL
		s.Config.TCPProxy = ""
		s.Config.UDPProxy = ""
	}
}

// SetTCPProxy sets the proxy for TCP protocols (HTTP/1.1, HTTP/2)
func (s *Session) SetTCPProxy(proxyURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.transport != nil {
		// Get current UDP proxy
		udpProxy := ""
		if s.Config != nil {
			udpProxy = s.Config.UDPProxy
		}

		proxy := &transport.ProxyConfig{
			TCPProxy: proxyURL,
			UDPProxy: udpProxy,
		}
		s.transport.SetProxy(proxy)
	}

	// Update config
	if s.Config != nil {
		s.Config.TCPProxy = proxyURL
		s.Config.Proxy = ""
	}
}

// SetUDPProxy sets the proxy for UDP protocols (HTTP/3 via SOCKS5 or MASQUE)
func (s *Session) SetUDPProxy(proxyURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.transport != nil {
		// Get current TCP proxy
		tcpProxy := ""
		if s.Config != nil {
			tcpProxy = s.Config.TCPProxy
		}

		proxy := &transport.ProxyConfig{
			TCPProxy: tcpProxy,
			UDPProxy: proxyURL,
		}
		s.transport.SetProxy(proxy)
	}

	// Update config
	if s.Config != nil {
		s.Config.UDPProxy = proxyURL
		s.Config.Proxy = ""
	}
}

// GetProxy returns the current proxy URL (unified proxy or TCP proxy)
func (s *Session) GetProxy() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Config == nil {
		return ""
	}
	if s.Config.Proxy != "" {
		return s.Config.Proxy
	}
	return s.Config.TCPProxy
}

// GetTCPProxy returns the current TCP proxy URL
func (s *Session) GetTCPProxy() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Config == nil {
		return ""
	}
	if s.Config.TCPProxy != "" {
		return s.Config.TCPProxy
	}
	return s.Config.Proxy
}

// GetUDPProxy returns the current UDP proxy URL
func (s *Session) GetUDPProxy() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Config == nil {
		return ""
	}
	if s.Config.UDPProxy != "" {
		return s.Config.UDPProxy
	}
	return s.Config.Proxy
}

// SetHeaderOrder sets a custom header order for all requests.
// Pass nil or empty slice to reset to preset's default order.
// Order should contain lowercase header names.
func (s *Session) SetHeaderOrder(order []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.transport != nil {
		s.transport.SetHeaderOrder(order)
	}
}

// GetHeaderOrder returns the current header order.
// Returns preset's default order if no custom order is set.
func (s *Session) GetHeaderOrder() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.transport != nil {
		return s.transport.GetHeaderOrder()
	}
	return nil
}

// IdleTime returns how long since the session was last used
func (s *Session) IdleTime() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.LastUsed)
}

// GetTransport returns the session's transport
func (s *Session) GetTransport() *transport.Transport {
	return s.transport
}

// SetSessionIdentifier sets a session identifier for TLS cache key isolation.
// This is used when the session is registered with a LocalProxy to ensure
// TLS sessions are isolated per proxy/session configuration.
func (s *Session) SetSessionIdentifier(sessionId string) {
	if s.transport != nil {
		s.transport.SetSessionIdentifier(sessionId)
	}
}

// Stats returns session statistics
func (s *Session) Stats() SessionStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var transportStats map[string]interface{}
	if s.transport != nil {
		transportStats = s.transport.Stats()
	}

	return SessionStats{
		ID:              s.ID,
		Preset:          s.Config.Preset,
		CreatedAt:       s.CreatedAt,
		LastUsed:        s.LastUsed,
		RequestCount:    s.RequestCount,
		Active:          s.active,
		CookieCount:     s.cookies.Count(),
		CacheEntryCount: len(s.cacheEntries),
		Age:             time.Since(s.CreatedAt),
		IdleTime:        time.Since(s.LastUsed),
		TransportStats:  transportStats,
	}
}

// SessionStats contains session statistics
type SessionStats struct {
	ID              string
	Preset          string
	CreatedAt       time.Time
	LastUsed        time.Time
	RequestCount    int64
	Active          bool
	CookieCount     int
	CacheEntryCount int // Number of cached URLs (for If-None-Match/If-Modified-Since)
	Age             time.Duration
	IdleTime        time.Duration
	TransportStats  map[string]interface{}
}

// Helper functions
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func splitByNewline(s string) []string {
	var result []string
	var current string
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			result = append(result, current)
			current = ""
		} else if s[i] != '\r' { // Skip carriage returns
			current += string(s[i])
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func trim(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func splitCookies(s string) []string {
	var result []string
	var current string
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			// Check if this looks like a date separator
			rest := s[i+1:]
			if len(rest) > 0 && rest[0] == ' ' && len(rest) > 3 {
				next := rest[1:4]
				if len(next) > 0 && isDigit(next[0]) {
					current += ","
					continue
				}
			}
			result = append(result, trim(current))
			current = ""
		} else {
			current += string(s[i])
		}
	}
	if current != "" {
		result = append(result, trim(current))
	}
	return result
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// isRedirectStatus returns true for 3xx redirect status codes
func isRedirectStatus(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// StreamResponse wraps transport.StreamResponse for session-level streaming
type StreamResponse = transport.StreamResponse

// RequestStream executes an HTTP request and returns a streaming response
// The caller is responsible for closing the response when done
// Note: Streaming does NOT support redirects - use Request() for redirect handling
func (s *Session) RequestStream(ctx context.Context, req *transport.Request) (*StreamResponse, error) {
	// Private copy: the session mutates req.Headers (cookies, client hints)
	// below, so never touch the caller's Request or its map. See the note in
	// requestWithRedirects — sharing a Request across goroutines would otherwise
	// race with concurrent map writes (fatal, and silent across cgo).
	reqCopy := *req
	reqCopy.Headers = cloneHeaders(req.Headers)
	req = &reqCopy
	s.pinPageFetchHeaders(req)

	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return nil, ErrSessionClosed
	}
	s.LastUsed = time.Now()
	s.RequestCount++

	if req.Headers == nil {
		req.Headers = make(map[string][]string)
	}

	// Add session cookies to request headers using proper domain/path matching.
	// Skip when WithoutCookieJar — caller-provided Cookie headers still pass through.
	if !s.Config.WithoutCookieJar {
		requestHost := extractHost(req.URL)
		requestPath := extractPath(req.URL)
		requestSecure := isSecureURL(req.URL)
		sessionCookies := s.cookies.BuildCookieHeader(requestHost, requestPath, requestSecure)
		if sessionCookies != "" {
			existingCookies := req.Headers["Cookie"]
			if len(existingCookies) > 0 && existingCookies[0] != "" {
				req.Headers["Cookie"] = []string{existingCookies[0] + "; " + sessionCookies}
			} else {
				req.Headers["Cookie"] = []string{sessionCookies}
			}
		}
	}
	s.mu.Unlock()

	// Resolve client-hint policy for parity with the buffered path: emit coherent
	// high-entropy hints once the host has advertised Accept-CH, honor the opt-out
	// knobs, and mark req so the transport strips the trio on a full opt-out.
	host := extractHost(req.URL)
	s.applyClientHintPolicy(host, req)

	// Execute streaming request (no retry or redirect support for streams)
	resp, err := s.transport.DoStream(ctx, req)
	if err != nil {
		return nil, err
	}

	// Extract cookies from response — skip when WithoutCookieJar.
	if !s.Config.WithoutCookieJar {
		s.extractCookies(resp.Headers, req.URL)
	}

	// Parse Accept-CH so subsequent requests to this host (buffered or streaming)
	// send the high-entropy hints, matching the buffered path.
	s.parseAcceptCH(host, resp.Headers)

	return resp, nil
}

// GetStream performs a streaming GET request
func (s *Session) GetStream(ctx context.Context, url string, headers map[string][]string) (*StreamResponse, error) {
	return s.RequestStream(ctx, &transport.Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

// PostStream performs a streaming POST request
func (s *Session) PostStream(ctx context.Context, url string, body []byte, headers map[string][]string) (*StreamResponse, error) {
	return s.RequestStream(ctx, &transport.Request{
		Method:  "POST",
		URL:     url,
		Body:    body,
		Headers: headers,
	})
}

// parseOrigin returns (scheme, host, port) for origin comparison. Missing
// ports are filled in with the scheme default so http://x:80 and http://x
// compare equal. Returned values are lowercased.
// sameOriginReferer returns a Referer URL as Chrome puts it in the header on a
// same-origin hop: the full URL minus the fragment and any userinfo
// (credentials), with a redundant default port dropped. Chrome never leaks the
// fragment or credentials in Referer, and serializes the document URL with the
// default port omitted (https://h:443/a -> https://h/a).
func sameOriginReferer(referrer string) string {
	u, err := url.Parse(referrer)
	if err != nil {
		return ""
	}
	u.Fragment = ""
	u.RawFragment = ""
	u.User = nil
	scheme := strings.ToLower(u.Scheme)
	if p := u.Port(); (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
		host := u.Hostname()
		if strings.Contains(host, ":") { // IPv6 literal needs brackets
			host = "[" + host + "]"
		}
		u.Host = host
	}
	return u.String()
}

func parseOrigin(urlStr string) (scheme, host, port string) {
	u, err := url.Parse(urlStr)
	if err != nil || u.Scheme == "" {
		return "", "", ""
	}
	scheme = strings.ToLower(u.Scheme)
	host = strings.ToLower(u.Hostname())
	port = u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme, host, port
}

// redirectReferer returns the Referer to send on the next redirect hop: the
// Referer the current hop carried, with Chrome's default
// strict-origin-when-cross-origin policy applied again for nextURL. Returns ""
// when the next hop should carry none.
//   - an https Referer going to a non-https URL: none
//   - nextURL on the Referer's own origin: the Referer as it was, minus any
//     fragment and credentials
//   - any other origin: the Referer's ORIGIN only, serialized with a trailing
//     slash (e.g. "https://example.com/")
//   - a Referer that is not an http or https URL: none, as a browser never
//     sends one it cannot parse
//
// Both checks look at the Referer, not at the URL that issued the 3xx, and
// referrer is what the current hop actually sent, which is how Chrome, Firefox
// and WebKit carry it. So a Referer trimmed on one hop stays trimmed, and one
// dropped on a downgrade stays dropped.
func redirectReferer(referrer, nextURL string) string {
	scheme, host, port := parseOrigin(referrer)
	if (scheme != "http" && scheme != "https") || host == "" {
		return ""
	}
	if isSchemeDowngrade(referrer, nextURL) {
		return ""
	}
	if sameOrigin(referrer, nextURL) {
		return sameOriginReferer(referrer)
	}
	if strings.Contains(host, ":") { // IPv6 literal needs brackets
		host = "[" + host + "]"
	}
	origin := scheme + "://" + host
	if !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		origin += ":" + port
	}
	return origin + "/"
}

// exactHeadersForHop returns the exact header pairs for the next redirect hop.
// A Referer pair is carried the way the Referer header is (see
// redirectReferer): its value is worked out again for nextURL in the pair's
// own slot and spelling, and the pair is left out when the hop should carry
// none, which disableReferer makes every hop. Every other pair goes as given,
// none is ever added, and exact is not modified.
//
// ok is false when leaving the Referer out would leave no pairs at all.
func exactHeadersForHop(exact []fingerprint.HeaderPair, nextURL string, disableReferer bool) (hop []fingerprint.HeaderPair, ok bool) {
	var out []fingerprint.HeaderPair // nil until a Referer pair is found
	for i, hp := range exact {
		if !strings.EqualFold(hp.Key, "Referer") {
			if out != nil {
				out = append(out, hp)
			}
			continue
		}
		if out == nil {
			out = append(make([]fingerprint.HeaderPair, 0, len(exact)), exact[:i]...)
		}
		if disableReferer {
			continue
		}
		if v := redirectReferer(hp.Value, nextURL); v != "" {
			out = append(out, fingerprint.HeaderPair{Key: hp.Key, Value: v})
		}
	}
	if out == nil {
		return exact, true
	}
	return out, len(out) > 0
}

// refererHeader returns the name under which h holds a Referer, as the caller
// spelled it, and its first value. The name is "" when h has none. Should a
// caller have set it under two spellings, the canonical one wins, then the
// lowest, so the choice does not change with map iteration order.
func refererHeader(h map[string][]string) (key, value string) {
	if v, ok := h["Referer"]; ok {
		key = "Referer"
		if len(v) > 0 {
			value = v[0]
		}
		return key, value
	}
	for k, v := range h {
		if strings.EqualFold(k, "Referer") && (key == "" || k < key) {
			key, value = k, ""
			if len(v) > 0 {
				value = v[0]
			}
		}
	}
	return key, value
}

// sameOrigin reports whether two URLs share scheme+host+port.
func sameOrigin(a, b string) bool {
	as, ah, ap := parseOrigin(a)
	bs, bh, bp := parseOrigin(b)
	if as == "" || bs == "" {
		return false
	}
	return as == bs && ah == bh && ap == bp
}

// isSchemeDowngrade reports whether going from one URL to the other is
// https → http. Fetch semantics strip any Authorization on such a redirect,
// and Chrome's default strict-origin-when-cross-origin referrer policy sends
// no Referer when the Referer is https and the destination is not.
func isSchemeDowngrade(from, to string) bool {
	fs, _, _ := parseOrigin(from)
	ts, _, _ := parseOrigin(to)
	return fs == "https" && ts == "http"
}

// redirectFetchSite returns the Sec-Fetch-Site to send on a redirect hop from
// fromURL to toURL, given the value the request to fromURL carried.
//
// A browser sends the most cross-site relation between the request's
// initiator and any URL in its redirect chain, the new one included. Chrome's
// GetRelationOfURLChainToOrigin, Firefox's SecFetch::AddSecFetchSite and
// WebKit's computeFetchMetadataSiteAfterRedirection all do this. The session
// never learns the initiator, but the value the last hop carried pins down as
// much of it as the next hop needs:
//   - same-origin: every URL so far was on the initiator's origin, so the
//     initiator is fromURL's origin. The hop stays same-origin on that
//     origin, becomes same-site on its site, and cross-site anywhere else.
//   - same-site: every URL so far was on the initiator's site, which is
//     fromURL's site. The hop stays same-site there, even back on the
//     initiator's own origin, and becomes cross-site anywhere else.
//   - none, sent for a navigation the user started, stays none on every hop,
//     and cross-site stays cross-site. So does a value no browser sends.
//
// That is how WebKit works it out, hop by hop. Chrome 156 and Firefox 159 sent
// the same values on every hop when captured across a.test, sub.a.test and
// b.test.
func redirectFetchSite(site, fromURL, toURL string) string {
	switch strings.ToLower(strings.TrimSpace(site)) {
	case "same-origin":
		if sameOrigin(fromURL, toURL) {
			return site
		}
		if sameSite(fromURL, toURL) {
			return "same-site"
		}
		return "cross-site"
	case "same-site":
		if sameSite(fromURL, toURL) {
			return site
		}
		return "cross-site"
	}
	return site
}

// exactHeadersFetchSiteForHop returns the exact header pairs for the next
// redirect hop. A Sec-Fetch-Site pair gets the value redirectFetchSite works
// out for it, in its own slot and spelling. Every other pair goes as given and
// none is added, so a list without the pair gains none. exact is the caller's
// slice and is never modified.
func exactHeadersFetchSiteForHop(exact []fingerprint.HeaderPair, fromURL, toURL string) []fingerprint.HeaderPair {
	var out []fingerprint.HeaderPair // nil until a value changes
	for i, hp := range exact {
		if !strings.EqualFold(hp.Key, "Sec-Fetch-Site") {
			continue
		}
		next := redirectFetchSite(hp.Value, fromURL, toURL)
		if next == hp.Value {
			continue
		}
		if out == nil {
			out = slices.Clone(exact)
		}
		out[i].Value = next
	}
	if out == nil {
		return exact
	}
	return out
}

// redirectOrigin is what a redirect chain's Origin header depends on, carried
// from hop to hop.
//
// Fetch never copies Origin onto a hop. HTTP-redirect fetch appends the new URL
// to the request's URL list and runs main fetch again, which appends Origin for
// the new request from scratch. So a hop's Origin follows from the request's
// origin and mode, the hop's method and the URLs the chain has passed through.
// Chrome 156 and Firefox 159 did exactly this for fetch(), XHR, no-cors
// fetch(), iframes, navigations and form POSTs redirected with 302, 303, 307
// and 308 within one origin, to another origin and back, and from https to
// http:
//   - A cors request carries Origin once any URL in the chain is off the
//     request's origin (Fetch's response tainting "cors"), whatever its method,
//     and before that only when the method is not GET or HEAD. So a fetch() GET
//     to its own origin gains Origin when redirected away, and the GET after a
//     fetch() POST's 303 carries it only off that origin.
//   - Any other request carries Origin only when its method is not GET or
//     HEAD: none on a navigation's or iframe's GET hops, none on the GET after
//     a form POST's 303.
//   - The value is "null" once a hop has left a URL off the request's origin
//     for another origin: Fetch's redirect-taint, and WebKit's opaque origin in
//     SubresourceLoader.
//   - Outside cors mode it is also "null" on a hop from an https origin to a
//     URL that is not https, by Fetch's default referrer policy.
//
// Chromium differs outside cors mode. Its network stack sets an Origin the
// request carries to "null" on every redirect to another origin, so a form or
// no-cors POST answered with 307 or 308 sends "null" from its first hop off
// the page's origin, where Firefox and Fetch keep the page's origin. Only
// Chromium presets do that; see chromiumPreset.
type redirectOrigin struct {
	// mode is the Sec-Fetch-Mode the first request went out with; see
	// transport.FetchMode. A request that went out with none, a TLS-only one
	// or one on a preset without Sec-Fetch-*, does not say which browser
	// request it is, so mode is "" and every hop carries the caller's Origin
	// unchanged.
	mode string
	// origin is the request's origin, serialized: the caller's Origin on the
	// first request, else the first URL's origin, since a browser sends a cors
	// GET without Origin only to its own origin.
	origin   string
	chromium bool
	// sniffed is set when mode is "cors" only because the transport sniffed it
	// from the request's shape.
	sniffed bool

	tainted bool // a hop has left a URL off origin for another origin
	crossed bool // a hop has gone to another origin than the URL it left
	cors    bool // a URL in the chain is off origin: response tainting "cors"
}

// newRedirectOrigin starts the Origin state for the chain req begins.
func (s *Session) newRedirectOrigin(req *transport.Request) *redirectOrigin {
	ro := &redirectOrigin{mode: s.transport.FetchMode(req), chromium: s.chromiumPreset()}
	var callerMode string
	if len(req.ExactHeaders) > 0 {
		for _, hp := range req.ExactHeaders {
			if strings.EqualFold(hp.Key, "Origin") {
				ro.origin = hp.Value
				break
			}
		}
	} else {
		_, ro.origin = headerEntry(req.Headers, "Origin")
		_, callerMode = headerEntry(req.Headers, "Sec-Fetch-Mode")
	}
	if ro.origin == "" {
		ro.origin = serializeOrigin(req.URL)
	}
	if ro.origin == "" {
		ro.mode = "" // no origin to send, so leave the caller's Origin as it is
	}
	ro.sniffed = ro.mode == "cors" && len(req.ExactHeaders) == 0 && callerMode == ""
	ro.cors = ro.mode == "cors" && !sameOrigin(ro.origin, req.URL)
	return ro
}

// next moves the chain on by the hop from the URL that answered with a
// redirect to the URL it named, taken with method, and returns the Origin
// that hop carries; ok is false when it carries none. Meaningless when mode
// is "".
func (ro *redirectOrigin) next(from, to, method string) (origin string, ok bool) {
	if !sameOrigin(from, to) {
		ro.crossed = true
		if !sameOrigin(ro.origin, from) {
			ro.tainted = true
		}
	}
	if ro.mode == "cors" && !sameOrigin(ro.origin, to) {
		ro.cors = true
	}
	serialized := ro.origin
	if ro.tainted {
		serialized = "null"
	}
	method = strings.ToUpper(method)
	switch {
	case ro.cors:
		return serialized, true
	case method == "" || method == "GET" || method == "HEAD":
		return "", false
	case ro.mode == "cors":
		return serialized, true
	case ro.chromium:
		// Chromium's network stack keeps the Origin a request carries and
		// sets it to "null" on a redirect to another origin.
		if ro.crossed {
			return "null", true
		}
		return ro.origin, true
	case isHTTPS(ro.origin) && !isHTTPS(to):
		return "null", true
	}
	return serialized, true
}

// chromiumPreset reports whether the session's preset is desktop or Android
// Chrome. The TLS identity is the signal, as it is for Chrome's QUIC transport
// parameters: Firefox, Safari and Chrome on iOS, which runs on WebKit, all
// present another.
func (s *Session) chromiumPreset() bool {
	presetName := ""
	if s.Config != nil {
		presetName = s.Config.Preset
	}
	p := fingerprint.Get(presetName)
	return p != nil && p.ClientHelloID.Client == "Chrome"
}

// exactOriginForHop returns the exact header pairs for the next redirect hop,
// with an Origin pair carried the way the Origin header is (see
// redirectOrigin): given the hop's value in its own slot and spelling, or left
// out when send is false. Every other pair goes as given, none is ever added,
// and exact is not modified.
//
// The result is never empty, which would switch exact mode off. The chain only
// judges Origin under ExactHeaders when the list names a Sec-Fetch-Mode, and
// that pair always stays.
func exactOriginForHop(exact []fingerprint.HeaderPair, origin string, send bool) []fingerprint.HeaderPair {
	var out []fingerprint.HeaderPair // nil until an Origin pair is found
	for i, hp := range exact {
		if !strings.EqualFold(hp.Key, "Origin") {
			if out != nil {
				out = append(out, hp)
			}
			continue
		}
		if out == nil {
			out = append(make([]fingerprint.HeaderPair, 0, len(exact)), exact[:i]...)
		}
		if send {
			out = append(out, fingerprint.HeaderPair{Key: hp.Key, Value: origin})
		}
	}
	if out == nil {
		return exact
	}
	return out
}

// sameSite reports whether two URLs are on the same site, as Chrome's
// SchemefulSite and the HTML spec define it: the same scheme and the same
// registrable domain, which is the eTLD+1 by the public suffix list with
// private suffixes such as github.io included. A host with no registrable
// domain, such as an IP address, localhost or a public suffix itself, is a
// site of its own. The port never matters.
func sameSite(a, b string) bool {
	as, ah, _ := parseOrigin(a)
	bs, bh, _ := parseOrigin(b)
	if as == "" || as != bs || ah == "" || bh == "" {
		return false
	}
	return registrableDomain(ah) == registrableDomain(bh)
}

// registrableDomain returns host's eTLD+1, or host itself when it has none.
// host must be lowercase, as parseOrigin returns it.
func registrableDomain(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// headerEntry returns the name under which h holds the header called name,
// as the caller spelled it, and its first value; key is "" when h has none.
// name must be in canonical form. Should a caller have set the header under
// two spellings, the canonical one wins, then the lowest, so the choice does
// not change with map iteration order.
func headerEntry(h map[string][]string, name string) (key, value string) {
	if v, ok := h[name]; ok {
		if len(v) > 0 {
			value = v[0]
		}
		return name, value
	}
	for k, v := range h {
		if strings.EqualFold(k, name) && (key == "" || k < key) {
			key, value = k, ""
			if len(v) > 0 {
				value = v[0]
			}
		}
	}
	return key, value
}

// serializeOrigin returns the origin of u the way an Origin header carries
// it, scheme and host with the port only when it is not the scheme's default,
// or "" when u is not an http or https URL.
func serializeOrigin(u string) string {
	scheme, host, port := parseOrigin(u)
	if (scheme != "http" && scheme != "https") || host == "" {
		return ""
	}
	if strings.Contains(host, ":") { // IPv6 literal needs brackets
		host = "[" + host + "]"
	}
	origin := scheme + "://" + host
	if !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		origin += ":" + port
	}
	return origin
}

// isHTTPS reports whether u, a URL or a serialized origin, is https.
func isHTTPS(u string) bool {
	scheme, _, _ := parseOrigin(u)
	return scheme == "https"
}

// resolveURL resolves a possibly relative URL against a base URL (RFC 3986)
func resolveURL(base, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	// Fix percent-encoded query separators in Location headers.
	// Some servers send Location: /path%3Ffoo=bar where %3F is meant as
	// the query separator ?. Go's url.Parse decodes %3F to ? in Path but
	// keeps RawQuery empty, causing RequestURI() to re-encode ? as %3F.
	// Browsers treat ? as a query separator regardless of encoding, so
	// split the path on ? when RawQuery is empty to match browser behavior.
	if refURL.RawQuery == "" {
		if idx := strings.IndexByte(refURL.Path, '?'); idx >= 0 {
			refURL.RawQuery = refURL.Path[idx+1:]
			refURL.Path = refURL.Path[:idx]
			refURL.RawPath = ""
		}
	}
	return baseURL.ResolveReference(refURL).String()
}

// ==================== Session Persistence ====================

// exportCookies exports all cookies in v5 format (domain-keyed)
func (s *Session) exportCookies() map[string][]CookieState {
	return s.cookies.Export()
}

// importCookies imports cookies from v5 format (domain-keyed)
func (s *Session) importCookies(cookies map[string][]CookieState) {
	s.cookies.Import(cookies)
}

// importCookiesV4 imports cookies from v4 format (flat list)
func (s *Session) importCookiesV4(cookies []CookieState) {
	s.cookies.ImportV4(cookies)
}

// exportTLSSessions exports TLS sessions from all transport caches
func (s *Session) exportTLSSessions() (map[string]transport.TLSSessionState, error) {
	allSessions := make(map[string]transport.TLSSessionState)

	// Export from HTTP/1.1 transport session cache
	if h1 := s.transport.GetHTTP1Transport(); h1 != nil {
		if cache, ok := h1.GetSessionCache().(*transport.PersistableSessionCache); ok {
			sessions, err := cache.Export()
			if err == nil {
				for k, v := range sessions {
					allSessions["h1:"+k] = v
				}
			}
		}
	}

	// Export from HTTP/2 transport session cache
	if h2 := s.transport.GetHTTP2Transport(); h2 != nil {
		if cache, ok := h2.GetSessionCache().(*transport.PersistableSessionCache); ok {
			sessions, err := cache.Export()
			if err == nil {
				for k, v := range sessions {
					allSessions["h2:"+k] = v
				}
			}
		}
	}

	// Export from HTTP/3 transport session cache
	if h3 := s.transport.GetHTTP3Transport(); h3 != nil {
		if cache, ok := h3.GetSessionCache().(*transport.PersistableSessionCache); ok {
			sessions, err := cache.Export()
			if err == nil {
				for k, v := range sessions {
					allSessions["h3:"+k] = v
				}
			}
		}
	}

	return allSessions, nil
}

// importTLSSessions imports TLS sessions into transport caches
func (s *Session) importTLSSessions(sessions map[string]transport.TLSSessionState) error {
	// Group sessions by protocol
	h1Sessions := make(map[string]transport.TLSSessionState)
	h2Sessions := make(map[string]transport.TLSSessionState)
	h3Sessions := make(map[string]transport.TLSSessionState)

	for key, session := range sessions {
		if len(key) > 3 && key[2] == ':' {
			prefix := key[:2]
			actualKey := key[3:]
			switch prefix {
			case "h1":
				h1Sessions[actualKey] = session
			case "h2":
				h2Sessions[actualKey] = session
			case "h3":
				h3Sessions[actualKey] = session
			}
		}
	}

	// Import to HTTP/1.1 transport
	if h1 := s.transport.GetHTTP1Transport(); h1 != nil && len(h1Sessions) > 0 {
		if cache, ok := h1.GetSessionCache().(*transport.PersistableSessionCache); ok {
			cache.Import(h1Sessions)
		}
	}

	// Import to HTTP/2 transport
	if h2 := s.transport.GetHTTP2Transport(); h2 != nil && len(h2Sessions) > 0 {
		if cache, ok := h2.GetSessionCache().(*transport.PersistableSessionCache); ok {
			cache.Import(h2Sessions)
		}
	}

	// Import to HTTP/3 transport
	if h3 := s.transport.GetHTTP3Transport(); h3 != nil && len(h3Sessions) > 0 {
		if cache, ok := h3.GetSessionCache().(*transport.PersistableSessionCache); ok {
			cache.Import(h3Sessions)
		}
	}

	return nil
}

// exportECHConfigs exports ECH configs from HTTP/3 transport
// These are essential for session resumption - the same ECH config must be used
func (s *Session) exportECHConfigs() map[string]string {
	h3 := s.transport.GetHTTP3Transport()
	if h3 == nil {
		return nil
	}

	rawConfigs := h3.GetECHConfigCache()
	if len(rawConfigs) == 0 {
		return nil
	}

	// Base64 encode the configs for JSON storage
	result := make(map[string]string, len(rawConfigs))
	for host, config := range rawConfigs {
		result[host] = base64.StdEncoding.EncodeToString(config)
	}
	return result
}

// importECHConfigs imports ECH configs into HTTP/3 transport
// This must be called BEFORE importing TLS sessions
func (s *Session) importECHConfigs(configs map[string]string) {
	if len(configs) == 0 {
		return
	}

	h3 := s.transport.GetHTTP3Transport()
	if h3 == nil {
		return
	}

	// Decode base64 configs
	rawConfigs := make(map[string][]byte, len(configs))
	for host, b64Config := range configs {
		if decoded, err := base64.StdEncoding.DecodeString(b64Config); err == nil {
			rawConfigs[host] = decoded
		}
	}

	h3.SetECHConfigCache(rawConfigs)
}

// Marshal exports session state to JSON bytes
func (s *Session) Marshal() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Export TLS sessions
	tlsSessions, err := s.exportTLSSessions()
	if err != nil {
		// Continue without TLS sessions - cookies are more important
		tlsSessions = make(map[string]transport.TLSSessionState)
	}

	// Export cookies
	cookies := s.exportCookies()

	// Export ECH configs from HTTP/3 transport
	// This is critical for session resumption - we must save the ECH configs
	// that were used when creating the TLS session tickets
	echConfigs := s.exportECHConfigs()

	// Save the full config
	config := s.Config
	if config == nil {
		config = &protocol.SessionConfig{
			Preset: "chrome-latest",
		}
	}

	state := &SessionState{
		Version:     SessionStateVersion,
		CreatedAt:   s.CreatedAt,
		UpdatedAt:   time.Now(),
		Config:      config,
		Cookies:     cookies,
		TLSSessions: tlsSessions,
		ECHConfigs:  echConfigs,
		AcceptCH:    s.exportAcceptCH(),
		TLSVerify:   tlsVerifyStateOf(config),
	}

	return json.MarshalIndent(state, "", "  ")
}

// tlsVerifyStateOf records which verification hooks a config carries. Returns
// nil when it carries none, so the key stays out of the file entirely for the
// common case.
func tlsVerifyStateOf(config *protocol.SessionConfig) *TLSVerifyState {
	if config == nil {
		return nil
	}
	v := &TLSVerifyState{
		PeerCertificate: config.TLSVerifyPeerCertificate != nil,
		Connection:      config.TLSVerifyConnection != nil,
		RootCAs:         config.TLSRootCAs != nil,
	}
	if !v.PeerCertificate && !v.Connection && !v.RootCAs {
		return nil
	}
	return v
}

// Save exports session state to a file
func (s *Session) Save(path string) error {
	data, err := s.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	// Write with restrictive permissions (owner read/write only)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	return nil
}

// SessionLoadOptions supplies the parts of a session's configuration that JSON
// cannot carry.
//
// Certificate verification hooks are Go functions and a *x509.CertPool, so a
// saved session can only record THAT they were configured, never what they did.
// Pass the same ones here to restore the session with the posture it was saved
// with. Anything left nil here that the file recorded is an error, not a
// silent downgrade.
type SessionLoadOptions struct {
	TLSVerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	TLSVerifyConnection      func(cs tls.ConnectionState) error
	TLSRootCAs               *x509.CertPool
}

// applyTo installs the supplied hooks on the config the session will be built
// from, so they travel the same path as hooks passed to NewSession directly.
func (o *SessionLoadOptions) applyTo(config *protocol.SessionConfig) {
	if o == nil || config == nil {
		return
	}
	if o.TLSVerifyPeerCertificate != nil {
		config.TLSVerifyPeerCertificate = o.TLSVerifyPeerCertificate
	}
	if o.TLSVerifyConnection != nil {
		config.TLSVerifyConnection = o.TLSVerifyConnection
	}
	if o.TLSRootCAs != nil {
		config.TLSRootCAs = o.TLSRootCAs
	}
}

// missingFrom names the recorded hooks the options do not supply.
func (v *TLSVerifyState) missingFrom(o *SessionLoadOptions) []string {
	if v == nil {
		return nil
	}
	var missing []string
	if v.PeerCertificate && (o == nil || o.TLSVerifyPeerCertificate == nil) {
		missing = append(missing, "TLSVerifyPeerCertificate")
	}
	if v.Connection && (o == nil || o.TLSVerifyConnection == nil) {
		missing = append(missing, "TLSVerifyConnection")
	}
	if v.RootCAs && (o == nil || o.TLSRootCAs == nil) {
		missing = append(missing, "TLSRootCAs")
	}
	return missing
}

// LoadSession loads a session from a file.
//
// Fails if the saved session had certificate verification hooks configured,
// because those cannot be serialised and restoring without them would hand back
// a session that verifies less than the one that was saved. Use
// LoadSessionWithOptions to supply them.
func LoadSession(path string) (*Session, error) {
	return LoadSessionWithOptions(path, nil)
}

// LoadSessionWithOptions loads a session from a file, re-supplying the parts of
// its configuration that JSON cannot carry.
func LoadSessionWithOptions(path string, opts *SessionLoadOptions) (*Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	return UnmarshalSessionWithOptions(data, opts)
}

// sessionStateV3 represents the old v3 session format for backwards compatibility
type sessionStateV3 struct {
	Version         int                                  `json:"version"`
	Preset          string                               `json:"preset"`
	ForceHTTP3      bool                                 `json:"force_http3"`
	ECHConfigDomain string                               `json:"ech_config_domain,omitempty"`
	CreatedAt       time.Time                            `json:"created_at"`
	UpdatedAt       time.Time                            `json:"updated_at"`
	Cookies         []CookieState                        `json:"cookies"`
	TLSSessions     map[string]transport.TLSSessionState `json:"tls_sessions"`
	ECHConfigs      map[string]string                    `json:"ech_configs,omitempty"`
	Proxy           string                               `json:"proxy,omitempty"`
	TCPProxy        string                               `json:"tcp_proxy,omitempty"`
	UDPProxy        string                               `json:"udp_proxy,omitempty"`
}

// UnmarshalSession loads a session from JSON bytes.
//
// Fails if the saved session had certificate verification hooks configured. See
// LoadSession.
func UnmarshalSession(data []byte) (*Session, error) {
	return UnmarshalSessionWithOptions(data, nil)
}

// UnmarshalSessionWithOptions loads a session from JSON bytes, re-supplying the
// parts of its configuration that JSON cannot carry.
func UnmarshalSessionWithOptions(data []byte, opts *SessionLoadOptions) (*Session, error) {
	// First, check the version and what the file says about verification
	var versionCheck struct {
		Version   int             `json:"version"`
		TLSVerify *TLSVerifyState `json:"tls_verify"`
	}
	if err := json.Unmarshal(data, &versionCheck); err != nil {
		return nil, fmt.Errorf("failed to parse session data: %w", err)
	}

	if versionCheck.Version > SessionStateVersion {
		return nil, fmt.Errorf("session file version %d is newer than supported version %d",
			versionCheck.Version, SessionStateVersion)
	}

	// Fail closed. Restoring a session whose verification hooks were dropped
	// gives back something that accepts certificates the saved session would
	// have rejected, with nothing at any layer to say so.
	if missing := versionCheck.TLSVerify.missingFrom(opts); len(missing) > 0 {
		return nil, fmt.Errorf("session was saved with certificate verification configured (%s) and "+
			"those cannot be serialised; load it with LoadSessionWithOptions/UnmarshalSessionWithOptions "+
			"and pass the same hooks, otherwise the restored session would verify less than the one you saved",
			strings.Join(missing, ", "))
	}

	// Handle v3 format (backwards compatibility)
	if versionCheck.Version <= 3 {
		return unmarshalSessionV3(data, opts)
	}

	// Handle v4 format (flat cookie list)
	if versionCheck.Version == 4 {
		return unmarshalSessionV4(data, opts)
	}

	// Handle v5 format (domain-keyed cookies)
	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse session data: %w", err)
	}

	// Use the full config from the saved state
	config := state.Config
	if config == nil {
		config = &protocol.SessionConfig{
			Preset: "chrome-latest",
		}
	}
	opts.applyTo(config)

	session := NewSession("", config)
	session.CreatedAt = state.CreatedAt

	// Import cookies (v5 format) and what each host asked for in Accept-CH
	session.mu.Lock()
	session.importCookies(state.Cookies)
	session.importAcceptCH(state.AcceptCH)
	session.mu.Unlock()

	// Import ECH configs FIRST - this must be done before TLS sessions
	// because the TLS session tickets need the correct ECH config for resumption
	session.importECHConfigs(state.ECHConfigs)

	// Import TLS sessions
	if err := session.importTLSSessions(state.TLSSessions); err != nil {
		// Log but don't fail - cookies are the main thing
	}

	return session, nil
}

// unmarshalSessionV4 handles loading v4 format sessions (flat cookie list)
func unmarshalSessionV4(data []byte, opts *SessionLoadOptions) (*Session, error) {
	var state SessionStateV4
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse v4 session data: %w", err)
	}

	// Use the full config from the saved state
	config := state.Config
	if config == nil {
		config = &protocol.SessionConfig{
			Preset: "chrome-latest",
		}
	}
	opts.applyTo(config)

	session := NewSession("", config)
	session.CreatedAt = state.CreatedAt

	// Import cookies from v4 format (flat list)
	session.mu.Lock()
	session.importCookiesV4(state.Cookies)
	session.mu.Unlock()

	// Import ECH configs FIRST
	session.importECHConfigs(state.ECHConfigs)

	// Import TLS sessions
	if err := session.importTLSSessions(state.TLSSessions); err != nil {
		// Log but don't fail
	}

	return session, nil
}

// unmarshalSessionV3 handles loading old v3 format sessions
func unmarshalSessionV3(data []byte, opts *SessionLoadOptions) (*Session, error) {
	var state sessionStateV3
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse v3 session data: %w", err)
	}

	// Convert v3 fields to full config
	config := &protocol.SessionConfig{
		Preset:          state.Preset,
		ForceHTTP3:      state.ForceHTTP3,
		ECHConfigDomain: state.ECHConfigDomain,
		Proxy:           state.Proxy,
		TCPProxy:        state.TCPProxy,
		UDPProxy:        state.UDPProxy,
	}
	opts.applyTo(config)

	session := NewSession("", config)
	session.CreatedAt = state.CreatedAt

	// Import cookies from v3 format (flat list, same as v4)
	session.mu.Lock()
	session.importCookiesV4(state.Cookies)
	session.mu.Unlock()

	// Import ECH configs
	session.importECHConfigs(state.ECHConfigs)

	// Import TLS sessions
	if err := session.importTLSSessions(state.TLSSessions); err != nil {
		// Log but don't fail
	}

	return session, nil
}

// ValidateSessionFile validates a session file without loading it
func ValidateSessionFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read session file: %w", err)
	}

	// Check version first
	var versionCheck struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &versionCheck); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	if versionCheck.Version > SessionStateVersion {
		return fmt.Errorf("session file version %d is newer than supported version %d",
			versionCheck.Version, SessionStateVersion)
	}

	// Validate based on version
	if versionCheck.Version <= 3 {
		var state sessionStateV3
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if state.Preset == "" {
			return fmt.Errorf("missing preset in session file")
		}
	} else if versionCheck.Version == 4 {
		var state SessionStateV4
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if state.Config == nil || state.Config.Preset == "" {
			return fmt.Errorf("missing preset in session file")
		}
	} else {
		// v5+
		var state SessionState
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if state.Config == nil || state.Config.Preset == "" {
			return fmt.Errorf("missing preset in session file")
		}
	}

	return nil
}
