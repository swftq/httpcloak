package session

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/internal/cookieorder"
)

// CookieJar manages cookies with proper domain and path scoping
// Cookies are stored by domain, then by (path, name) tuple
type CookieJar struct {
	mu sync.RWMutex
	// Primary key: domain (normalized)
	// Secondary key: path + "\x00" + name
	cookies map[string]map[string]*CookieData

	// order is the Cookie header order of the preset's browser, and clock
	// gives every store a time later than the one before. Both are guarded
	// by mu.
	order cookieorder.Order
	clock cookieorder.Clock
}

// CookieData extends CookieState with the times the jar orders cookies by
type CookieData struct {
	Name      string
	Value     string
	Domain    string // Normalized domain (with leading dot for domain cookies)
	HostOnly  bool   // True if cookie should only be sent to exact host
	Path      string
	Expires   *time.Time
	MaxAge    int
	Secure    bool
	HttpOnly  bool
	SameSite  string
	CreatedAt time.Time // the first store; a live cookie set again keeps it where the preset's browser does
	StoredAt  time.Time // the last store, which the cookies of one response share
}

// NewCookieJar creates a new empty cookie jar. It orders cookies as RFC 6265
// does; a session's own jar takes the order of its preset's browser.
func NewCookieJar() *CookieJar {
	return &CookieJar{
		cookies: make(map[string]map[string]*CookieData),
	}
}

// newCookieJar creates an empty jar with the given Cookie header order.
func newCookieJar(order cookieorder.Order) *CookieJar {
	j := NewCookieJar()
	j.order = order
	return j
}

// cookieKey generates a unique key for a cookie within a domain
func cookieKey(path, name string) string {
	return path + "\x00" + name
}

// orderKey is what the jar's order reads from the cookie.
func (c *CookieData) orderKey() cookieorder.Key {
	return cookieorder.Key{Name: c.Name, Domain: c.Domain, Path: c.Path, Created: c.CreatedAt, Stored: c.StoredAt}
}

// Set adds or updates a cookie from a Set-Cookie header
// requestHost is the host that sent the Set-Cookie header
// requestSecure is true if the request was over HTTPS
func (j *CookieJar) Set(requestHost string, cookie *CookieData, requestSecure bool) {
	j.setAll(requestHost, []*CookieData{cookie}, requestSecure)
}

// setAll stores the cookies of one response, in Set-Cookie order, as one store:
// they share a store time, and each gets a creation time of its own.
func (j *CookieJar) setAll(requestHost string, cookies []*CookieData, requestSecure bool) {
	if len(cookies) == 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	now := j.clock.Next()
	for _, cookie := range cookies {
		j.set(requestHost, cookie, requestSecure, now)
	}
}

// set scopes one cookie from a Set-Cookie header and stores it at now. The
// caller must hold j.mu.
func (j *CookieJar) set(requestHost string, cookie *CookieData, requestSecure bool, now time.Time) {
	// Normalize the request host (lowercase, no port)
	requestHost = strings.ToLower(requestHost)
	if idx := strings.LastIndex(requestHost, ":"); idx != -1 {
		// Check if it's not an IPv6 address
		if !strings.Contains(requestHost, "]") || idx > strings.Index(requestHost, "]") {
			requestHost = requestHost[:idx]
		}
	}

	// Determine effective domain
	var domain string
	var hostOnly bool

	if cookie.Domain == "" {
		// No Domain attribute: host-only cookie
		domain = requestHost
		hostOnly = true
	} else {
		// Domain attribute specified
		domain = strings.ToLower(cookie.Domain)

		// Remove leading dot for comparison (we'll add it back for storage)
		domainWithoutDot := strings.TrimPrefix(domain, ".")

		// Validate: request host must be the domain or a subdomain of it
		if !isDomainMatch(requestHost, domainWithoutDot) {
			return // Reject: can't set cookie for unrelated domain
		}

		// Store with leading dot to indicate it's a domain cookie
		domain = "." + domainWithoutDot
		hostOnly = false
	}

	// Secure cookies can only be set over HTTPS
	if cookie.Secure && !requestSecure {
		return // Reject
	}

	// Default path if not specified
	path := cookie.Path
	if path == "" || path[0] != '/' {
		path = "/"
	}

	// Create the stored cookie
	stored := &CookieData{
		Name:     cookie.Name,
		Value:    cookie.Value,
		Domain:   domain,
		HostOnly: hostOnly,
		Path:     path,
		Expires:  cookie.Expires,
		MaxAge:   cookie.MaxAge,
		Secure:   cookie.Secure,
		HttpOnly: cookie.HttpOnly,
		SameSite: cookie.SameSite,
	}
	j.store(stored, now)
}

// store inserts an already scoped cookie as stored at now, the time the
// cookies of one store share. It is created at a time of its own, later than
// any before, unless it replaces a live cookie whose creation time the
// preset's browser keeps. The caller must hold j.mu.
func (j *CookieJar) store(cookie *CookieData, now time.Time) {
	key := cookieKey(cookie.Path, cookie.Name)
	created := j.clock.NotBefore(now)
	// RFC 6265 Section 5.3 step 11.3. An expired cookie counts as gone, as
	// in Firefox, so its replacement is a new cookie.
	if old := j.cookies[cookie.Domain][key]; old != nil &&
		(old.Expires == nil || old.Expires.After(now)) &&
		j.order.KeepsCreation(old.Value, cookie.Value) {
		created = old.CreatedAt
	}
	cookie.CreatedAt, cookie.StoredAt = created, now.Round(0)

	if j.cookies[cookie.Domain] == nil {
		j.cookies[cookie.Domain] = make(map[string]*CookieData)
	}
	j.cookies[cookie.Domain][key] = cookie
}

// Get returns all cookies that should be sent for a request
// requestHost is the target host
// requestPath is the request path
// requestSecure is true if the request is over HTTPS
func (j *CookieJar) Get(requestHost, requestPath string, requestSecure bool) []*CookieData {
	j.mu.RLock()
	defer j.mu.RUnlock()

	// Normalize
	requestHost = strings.ToLower(requestHost)
	if idx := strings.LastIndex(requestHost, ":"); idx != -1 {
		if !strings.Contains(requestHost, "]") || idx > strings.Index(requestHost, "]") {
			requestHost = requestHost[:idx]
		}
	}

	if requestPath == "" {
		requestPath = "/"
	}

	now := time.Now()
	var matches []*CookieData

	// Check all domains that might match
	for domain, domainCookies := range j.cookies {
		// Check if this domain matches the request host
		if !j.domainMatchesHost(domain, requestHost) {
			continue
		}

		for _, cookie := range domainCookies {
			// Host-only check
			if cookie.HostOnly && domain != requestHost {
				continue
			}

			// Path match
			if !isPathMatch(requestPath, cookie.Path) {
				continue
			}

			// Secure check
			if cookie.Secure && !requestSecure {
				continue
			}

			// Expiration check
			if cookie.Expires != nil && cookie.Expires.Before(now) {
				continue
			}

			matches = append(matches, cookie)
		}
	}

	// Sort in the order of the preset's browser: longer path first, then the
	// oldest on Chrome and Firefox presets, or the most recently stored on
	// WebKit presets. The order is total, so ties don't come out in map order.
	sort.Slice(matches, func(i, k int) bool {
		return j.order.Less(matches[i].orderKey(), matches[k].orderKey())
	})

	return matches
}

// GetAll returns all non-expired cookies with full metadata
func (j *CookieJar) GetAll() []CookieState {
	j.mu.RLock()
	defer j.mu.RUnlock()

	now := time.Now()
	var result []CookieState

	for _, domainCookies := range j.cookies {
		for _, c := range domainCookies {
			// Skip expired cookies
			if c.Expires != nil && c.Expires.Before(now) {
				continue
			}

			createdAt, storedAt := c.CreatedAt, c.StoredAt
			result = append(result, CookieState{
				Name:      c.Name,
				Value:     c.Value,
				Domain:    c.Domain,
				Path:      c.Path,
				Expires:   c.Expires,
				MaxAge:    c.MaxAge,
				Secure:    c.Secure,
				HttpOnly:  c.HttpOnly,
				SameSite:  c.SameSite,
				CreatedAt: &createdAt,
				StoredAt:  &storedAt,
			})
		}
	}

	// Sort by domain, then path, then name for deterministic output
	sort.Slice(result, func(i, k int) bool {
		if result[i].Domain != result[k].Domain {
			return result[i].Domain < result[k].Domain
		}
		if result[i].Path != result[k].Path {
			return result[i].Path < result[k].Path
		}
		return result[i].Name < result[k].Name
	})

	return result
}

// SetSimple sets a cookie with full metadata.
// If domain is empty, creates a global cookie (sent to all domains).
// If domain is provided, normalizes it and stores as a domain-scoped cookie.
func (j *CookieJar) SetSimple(name, value, domain, path string, secure, httpOnly bool, sameSite string, maxAge int, expires *time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()

	hostOnly := false
	if domain == "" {
		// Global cookie — matches all domains
	} else {
		// Normalize domain
		domain = strings.ToLower(domain)
		if !strings.HasPrefix(domain, ".") {
			// Bare domain → host-only cookie
			hostOnly = true
		}
	}

	if path == "" {
		path = "/"
	}

	// One call is one store.
	j.store(&CookieData{
		Name:     name,
		Value:    value,
		Domain:   domain,
		HostOnly: hostOnly,
		Path:     path,
		Expires:  expires,
		MaxAge:   maxAge,
		Secure:   secure,
		HttpOnly: httpOnly,
		SameSite: sameSite,
	}, j.clock.Next())
}

// Delete removes cookies by name. If domain is empty, removes ALL cookies with
// that name across all domains. If domain is provided, removes only from that domain.
func (j *CookieJar) Delete(name, domain string) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if domain == "" {
		// Delete from all domains
		for d, domainCookies := range j.cookies {
			for key, cookie := range domainCookies {
				if cookie.Name == name {
					delete(domainCookies, key)
				}
			}
			if len(domainCookies) == 0 {
				delete(j.cookies, d)
			}
		}
	} else {
		// Normalize and delete from specific domain
		domain = strings.ToLower(domain)
		domainCookies, ok := j.cookies[domain]
		if !ok {
			return
		}
		for key, cookie := range domainCookies {
			if cookie.Name == name {
				delete(domainCookies, key)
			}
		}
		if len(domainCookies) == 0 {
			delete(j.cookies, domain)
		}
	}
}

// Clear removes all cookies
func (j *CookieJar) Clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = make(map[string]map[string]*CookieData)
}

// ClearExpired removes all expired cookies
func (j *CookieJar) ClearExpired() {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()
	for domain, domainCookies := range j.cookies {
		for key, cookie := range domainCookies {
			if cookie.Expires != nil && cookie.Expires.Before(now) {
				delete(domainCookies, key)
			}
		}
		if len(domainCookies) == 0 {
			delete(j.cookies, domain)
		}
	}
}

// Count returns the total number of cookies across all domains
func (j *CookieJar) Count() int {
	j.mu.RLock()
	defer j.mu.RUnlock()

	count := 0
	for _, domainCookies := range j.cookies {
		count += len(domainCookies)
	}
	return count
}

// Export exports all cookies grouped by domain for serialization
func (j *CookieJar) Export() map[string][]CookieState {
	j.mu.RLock()
	defer j.mu.RUnlock()

	now := time.Now()
	result := make(map[string][]CookieState)

	for domain, domainCookies := range j.cookies {
		var cookies []CookieState
		for _, c := range domainCookies {
			// Skip expired cookies
			if c.Expires != nil && c.Expires.Before(now) {
				continue
			}

			createdAt, storedAt := c.CreatedAt, c.StoredAt
			cookies = append(cookies, CookieState{
				Name:      c.Name,
				Value:     c.Value,
				Domain:    c.Domain,
				Path:      c.Path,
				Expires:   c.Expires,
				MaxAge:    c.MaxAge,
				Secure:    c.Secure,
				HttpOnly:  c.HttpOnly,
				SameSite:  c.SameSite,
				CreatedAt: &createdAt,
				StoredAt:  &storedAt,
			})
		}
		if len(cookies) > 0 {
			result[domain] = cookies
		}
	}

	return result
}

// Import imports cookies from the v5 format (domain-keyed)
func (j *CookieJar) Import(cookies map[string][]CookieState) {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()

	// Domains in a fixed order, so that cookies without saved times get
	// their store times in the same order on every load.
	domains := make([]string, 0, len(cookies))
	for domain := range cookies {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	for _, domain := range domains {
		domainCookies := cookies[domain]
		if j.cookies[domain] == nil {
			j.cookies[domain] = make(map[string]*CookieData)
		}

		for _, c := range domainCookies {
			// Skip expired cookies
			if c.Expires != nil && c.Expires.Before(now) {
				continue
			}

			path := c.Path
			if path == "" {
				path = "/"
			}

			// Determine if host-only based on domain format
			hostOnly := !strings.HasPrefix(c.Domain, ".")

			// Use the saved times if available, and have the clock hand
			// out later ones (Clock.Saw, up to a second past the system
			// clock), so that a cookie stored after the load is newer than
			// these. A file written before stored_at existed re-stamped
			// created_at on every store, so it is the last store there. A
			// cookie with neither is a store of its own, in list order.
			var createdAt time.Time
			if c.CreatedAt != nil {
				createdAt = *c.CreatedAt
				j.clock.Saw(createdAt)
			} else {
				createdAt = j.clock.Next()
			}
			storedAt := createdAt
			if c.StoredAt != nil {
				storedAt = *c.StoredAt
				j.clock.Saw(storedAt)
			}

			j.cookies[domain][cookieKey(path, c.Name)] = &CookieData{
				Name:      c.Name,
				Value:     c.Value,
				Domain:    c.Domain,
				HostOnly:  hostOnly,
				Path:      path,
				Expires:   c.Expires,
				MaxAge:    c.MaxAge,
				Secure:    c.Secure,
				HttpOnly:  c.HttpOnly,
				SameSite:  c.SameSite,
				CreatedAt: createdAt,
				StoredAt:  storedAt,
			}
		}
	}
}

// ImportV4 imports cookies from the v4 format (flat list)
func (j *CookieJar) ImportV4(cookies []CookieState) {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()

	for _, c := range cookies {
		// Skip expired cookies
		if c.Expires != nil && c.Expires.Before(now) {
			continue
		}

		// Determine domain key
		domain := c.Domain
		hostOnly := false

		if domain == "" {
			// No domain in v4 means it was stored by name only
			// We'll store it as a "global" cookie
			domain = ""
		} else {
			// Normalize domain
			domain = strings.ToLower(domain)
			if !strings.HasPrefix(domain, ".") {
				hostOnly = true
			}
		}

		path := c.Path
		if path == "" {
			path = "/"
		}

		if j.cookies[domain] == nil {
			j.cookies[domain] = make(map[string]*CookieData)
		}

		// v4 kept no times: each cookie is a store of its own, in list order.
		t := j.clock.Next()
		j.cookies[domain][cookieKey(path, c.Name)] = &CookieData{
			Name:      c.Name,
			Value:     c.Value,
			Domain:    domain,
			HostOnly:  hostOnly,
			Path:      path,
			Expires:   c.Expires,
			MaxAge:    c.MaxAge,
			Secure:    c.Secure,
			HttpOnly:  c.HttpOnly,
			SameSite:  c.SameSite,
			CreatedAt: t,
			StoredAt:  t,
		}
	}
}

// domainMatchesHost checks if a cookie domain matches a request host
func (j *CookieJar) domainMatchesHost(cookieDomain, requestHost string) bool {
	// Empty domain (global cookies) matches everything
	if cookieDomain == "" {
		return true
	}

	// Exact match (for host-only cookies stored without dot)
	if cookieDomain == requestHost {
		return true
	}

	// Domain cookie (with leading dot)
	if strings.HasPrefix(cookieDomain, ".") {
		domainWithoutDot := cookieDomain[1:]
		// Matches the domain itself
		if requestHost == domainWithoutDot {
			return true
		}
		// Matches subdomains
		if strings.HasSuffix(requestHost, cookieDomain) {
			return true
		}
	}

	return false
}

// isDomainMatch checks if host is equal to or a subdomain of domain
func isDomainMatch(host, domain string) bool {
	if host == domain {
		return true
	}
	// host must be a subdomain of domain
	if strings.HasSuffix(host, "."+domain) {
		return true
	}
	return false
}

// isPathMatch checks if request path matches cookie path
func isPathMatch(requestPath, cookiePath string) bool {
	if requestPath == cookiePath {
		return true
	}

	// Cookie path must be a prefix of request path
	if strings.HasPrefix(requestPath, cookiePath) {
		// Exact prefix match with /
		if strings.HasSuffix(cookiePath, "/") {
			return true
		}
		// Or the next char in request path is /
		if len(requestPath) > len(cookiePath) && requestPath[len(cookiePath)] == '/' {
			return true
		}
	}

	return false
}

// BuildCookieHeader builds the Cookie header value for a request
func (j *CookieJar) BuildCookieHeader(requestHost, requestPath string, requestSecure bool) string {
	cookies := j.Get(requestHost, requestPath, requestSecure)
	if len(cookies) == 0 {
		return ""
	}

	var parts []string
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}

	return strings.Join(parts, "; ")
}
