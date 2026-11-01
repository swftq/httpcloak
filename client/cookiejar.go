package client

import (
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/cookieorder"
)

// CookieJar stores cookies and provides thread-safe access
type CookieJar struct {
	mu      sync.RWMutex
	cookies map[string][]storedCookie // domain -> cookies

	// order is the Cookie header order of the preset's browser, and clock
	// gives every store a time later than the one before. Both are guarded
	// by mu.
	order cookieorder.Order
	clock cookieorder.Clock
}

// storedCookie is a cookie in the jar with the times its order reads, the
// first and the last store (internal/cookieorder). The times are the jar's
// own: it never writes into the Cookie, which stays the caller's and can be
// handed to several jars.
type storedCookie struct {
	*Cookie
	created, stored time.Time
}

// NewCookieJar creates a new empty cookie jar. It orders cookies as RFC 6265
// does; a Client's own jar takes the order of its preset's browser.
func NewCookieJar() *CookieJar {
	return &CookieJar{
		cookies: make(map[string][]storedCookie),
	}
}

// newCookieJarFor creates an empty jar that orders cookies as the browser of
// preset p does.
func newCookieJarFor(p *fingerprint.Preset) *CookieJar {
	j := NewCookieJar()
	j.order = cookieOrderOf(p)
	return j
}

// setOrder makes the jar order cookies as the browser of preset p does, for a
// Client whose preset changed.
func (j *CookieJar) setOrder(p *fingerprint.Preset) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.order = cookieOrderOf(p)
}

// cookieOrderOf is the Cookie header order of the engine of p's User-Agent.
func cookieOrderOf(p *fingerprint.Preset) cookieorder.Order {
	if p == nil {
		return cookieorder.RFC6265
	}
	return cookieorder.Of(p.UserAgent)
}

// orderKey is what the jar's order reads from the cookie.
func (c storedCookie) orderKey() cookieorder.Key {
	return cookieorder.Key{Name: c.Name, Domain: c.Domain, Path: c.Path, Created: c.created, Stored: c.stored}
}

// SetCookies adds cookies from Set-Cookie headers to the jar. One call is one
// response's cookies, so it is one store: they share a store time, and each
// gets a creation time of its own, in list order.
func (j *CookieJar) SetCookies(u *url.URL, cookies []*Cookie) {
	if len(cookies) == 0 {
		return
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	now := j.clock.Next()
	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" {
			continue
		}

		// Get the domain key
		domain := j.domainKey(cookie.Domain)

		// Remove existing cookie with same name, domain, and path
		existing := j.cookies[domain]
		filtered := make([]storedCookie, 0, len(existing))
		var old *storedCookie
		for i, c := range existing {
			if c.Name != cookie.Name || c.Path != cookie.Path {
				filtered = append(filtered, c)
			} else {
				old = &existing[i]
			}
		}

		// Add new cookie if not expired
		if !cookie.IsExpired() {
			// RFC 6265 Section 5.3 step 11.3: a cookie that replaces a live
			// one keeps its creation time where the preset's browser does.
			created := j.clock.NotBefore(now)
			if old != nil && !old.IsExpired() && j.order.KeepsCreation(old.Value, cookie.Value) {
				created = old.created
			}
			filtered = append(filtered, storedCookie{Cookie: cookie, created: created, stored: now})
		}

		j.cookies[domain] = filtered
	}
}

// SetCookiesFromHeaders parses Set-Cookie headers and adds them to the jar
func (j *CookieJar) SetCookiesFromHeaders(u *url.URL, headers map[string]string) {
	// Look for Set-Cookie header (case-insensitive)
	for key, value := range headers {
		if strings.ToLower(key) == "set-cookie" {
			// Single Set-Cookie header
			if cookie := ParseSetCookie(value, u); cookie != nil {
				j.SetCookies(u, []*Cookie{cookie})
			}
		}
	}
}

// SetCookiesFromHeaderList handles multiple Set-Cookie headers
func (j *CookieJar) SetCookiesFromHeaderList(u *url.URL, setCookieHeaders []string) {
	cookies := make([]*Cookie, 0, len(setCookieHeaders))
	for _, header := range setCookieHeaders {
		if cookie := ParseSetCookie(header, u); cookie != nil {
			cookies = append(cookies, cookie)
		}
	}
	j.SetCookies(u, cookies)
}

// Cookies returns the cookies to send for the given URL
func (j *CookieJar) Cookies(u *url.URL) []*Cookie {
	j.mu.RLock()
	defer j.mu.RUnlock()

	now := time.Now()
	var matched []storedCookie

	// Check all domains that could match
	host := u.Host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	host = strings.ToLower(host)

	// Get cookies from exact domain and parent domains
	domains := j.getMatchingDomains(host)

	for _, domain := range domains {
		cookies := j.cookies[domain]
		for _, cookie := range cookies {
			// Check expiration
			if cookie.MaxAge < 0 {
				continue
			}
			if !cookie.Expires.IsZero() && now.After(cookie.Expires) {
				continue
			}

			// Check if cookie matches URL
			if cookie.Matches(u) {
				matched = append(matched, cookie)
			}
		}
	}

	// Sort in the order of the preset's browser: longer path first, then the
	// oldest on Chrome and Firefox presets, or the most recently stored on
	// WebKit presets. The order is total, so it doesn't depend on the order
	// the jar holds the cookies in.
	sort.Slice(matched, func(a, b int) bool {
		return j.order.Less(matched[a].orderKey(), matched[b].orderKey())
	})

	var result []*Cookie
	for _, c := range matched {
		result = append(result, c.Cookie)
	}
	return result
}

// CookieHeader returns the Cookie header value for the given URL
func (j *CookieJar) CookieHeader(u *url.URL) string {
	cookies := j.Cookies(u)
	if len(cookies) == 0 {
		return ""
	}

	parts := make([]string, len(cookies))
	for i, c := range cookies {
		parts[i] = c.String()
	}

	return strings.Join(parts, "; ")
}

// Clear removes all cookies from the jar
func (j *CookieJar) Clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = make(map[string][]storedCookie)
}

// ClearDomain removes all cookies for a specific domain
func (j *CookieJar) ClearDomain(domain string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.cookies, j.domainKey(domain))
}

// ClearExpired removes all expired cookies
func (j *CookieJar) ClearExpired() {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()
	for domain, cookies := range j.cookies {
		filtered := make([]storedCookie, 0, len(cookies))
		for _, c := range cookies {
			if c.MaxAge >= 0 && (c.Expires.IsZero() || now.Before(c.Expires)) {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) > 0 {
			j.cookies[domain] = filtered
		} else {
			delete(j.cookies, domain)
		}
	}
}

// Count returns the total number of cookies in the jar
func (j *CookieJar) Count() int {
	j.mu.RLock()
	defer j.mu.RUnlock()

	count := 0
	for _, cookies := range j.cookies {
		count += len(cookies)
	}
	return count
}

// AllCookies returns all cookies in the jar (for debugging)
func (j *CookieJar) AllCookies() map[string][]*Cookie {
	j.mu.RLock()
	defer j.mu.RUnlock()

	result := make(map[string][]*Cookie)
	for domain, cookies := range j.cookies {
		copied := make([]*Cookie, len(cookies))
		for i, c := range cookies {
			copied[i] = c.Cookie
		}
		result[domain] = copied
	}
	return result
}

// domainKey normalizes domain for map key
func (j *CookieJar) domainKey(domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimPrefix(domain, ".")
	return domain
}

// getMatchingDomains returns all domain keys that could have matching cookies
func (j *CookieJar) getMatchingDomains(host string) []string {
	var domains []string

	// Exact domain
	if _, ok := j.cookies[host]; ok {
		domains = append(domains, host)
	}

	// Parent domains
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if _, ok := j.cookies[parent]; ok {
			domains = append(domains, parent)
		}
	}

	return domains
}

// SetCookie adds a single cookie to the jar
func (j *CookieJar) SetCookie(u *url.URL, name, value string) {
	cookie := &Cookie{
		Name:   name,
		Value:  value,
		Domain: u.Host,
		Path:   "/",
	}
	j.SetCookies(u, []*Cookie{cookie})
}
