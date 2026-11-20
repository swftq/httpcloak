// Package cookieorder is the order in which a browser lists the cookies of a
// Cookie header, shared by the session's cookie jar and client.Client's. The
// order follows the browser engine, so it comes from the preset's User-Agent
// through internal/engine.
package cookieorder

import (
	"time"

	"github.com/sardanioss/httpcloak/internal/engine"
)

// Order is how a browser orders the cookies of one Cookie header.
type Order uint8

const (
	// RFC6265 is RFC 6265 Section 5.4 step 2: longer paths first, then the
	// cookie created first. A cookie set again while it is live keeps its
	// creation time (Section 5.3 step 11.3). Firefox 159 sends this order and
	// keeps the creation time on every replacement (CookieStorage::AddCookie,
	// "Preserve creation time of cookie for ordering purposes"). It is the
	// order of every engine but Chromium and WebKit, and the zero value.
	RFC6265 Order = iota

	// Chromium sorts as RFC6265 does (CookieMonster::CookieSorter: longer
	// path first, then the older CreationDate), but a cookie set again keeps
	// its creation time only when its value is unchanged
	// (MaybeDeleteEquivalentCookieAndUpdateStatus inherits it only behind
	// IsValueEqual). With a new value it gets a new one and goes behind the
	// cookies stored before it, as headless Chrome 156 sent it.
	Chromium

	// WebKit is Safari's order: the most recently stored cookie first, and the
	// cookies one response stored by name. That fits all 618 requests with two
	// or more cookies in a capture of Safari 26.3 on macOS
	// (run-20261031-234946). Every cookie there had Path=/, so the
	// longer-paths-first rule ahead of it is RFC 6265's, kept and not captured
	// for Safari.
	WebKit
)

// Of returns the order of the browser whose User-Agent is userAgent: WebKit
// for Safari and every browser on iOS, Chromium for Chrome, and RFC6265 for
// Firefox and anything else.
func Of(userAgent string) Order {
	switch engine.Of(userAgent) {
	case engine.WebKit:
		return WebKit
	case engine.Chromium:
		return Chromium
	}
	return RFC6265
}

// Key is what an order reads from one cookie.
type Key struct {
	Name, Domain, Path string

	// Created is when the cookie was first stored; a cookie set again while
	// it is live keeps it as KeepsCreation says. No two cookies of one jar
	// share it unless a file gave them one, so it orders even the cookies of
	// one response.
	Created time.Time

	// Stored is when the cookie was last stored. The cookies one response
	// stored share it.
	Stored time.Time
}

// Less reports whether the cookie a goes before b in a Cookie header. It is a
// total order over cookies with different (Domain, Path, Name), so neither the
// jar's map order nor the sort's stability shows on the wire.
func (o Order) Less(a, b Key) bool {
	if len(a.Path) != len(b.Path) {
		// Every order. For WebKit this is RFC 6265's rule, not captured.
		return len(a.Path) > len(b.Path)
	}
	if o == WebKit {
		if !a.Stored.Equal(b.Stored) {
			return a.Stored.After(b.Stored)
		}
		// In byte order, so uppercase first. Every captured name was
		// lowercase.
		if a.Name != b.Name {
			return a.Name < b.Name
		}
	}
	if !a.Created.Equal(b.Created) {
		return a.Created.Before(b.Created)
	}
	// Equal creation times come only from a file: files written before the
	// jars had a clock of their own can give the cookies of one response one
	// time. A store after a load is later than every time loaded (Clock.Saw),
	// except a time more than a second ahead of the clock, which a store can
	// then fall before or, by chance, equal.
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Domain != b.Domain {
		return a.Domain < b.Domain
	}
	return a.Path < b.Path
}

// KeepsCreation reports whether a cookie that replaces a live one with the
// same name, domain and path keeps the old one's creation time. WebKit keeps
// it too, by RFC 6265's rule; Safari's replacement rule is not captured. Its
// order reads the store time, so the creation time only orders same-named
// cookies of different domains stored together.
func (o Order) KeepsCreation(oldValue, newValue string) bool {
	if o == Chromium {
		return oldValue == newValue
	}
	return true
}

// Clock hands out one jar's store times, each later than every one it handed
// out or saw before. Two stores then never tie, however coarse the system
// clock is: Go's time.Now on Windows only moves on the timer interrupt, so the
// cookies of one response, and of several responses in a row, used to read
// one time in the session's jar and go out in map order. A Clock's zero value
// is ready to use; the jar that owns it guards it with its own lock.
type Clock struct {
	// Now is where store times come from; nil means time.Now. Tests freeze it.
	Now func() time.Time

	last time.Time
}

// now reads the clock's time source.
func (c *Clock) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Next returns the time of a new store: now, or a nanosecond after the last
// time handed out or seen when now is not later.
func (c *Clock) Next() time.Time {
	return c.NotBefore(c.now())
}

// Saw makes the times handed out from now on later than t, a time loaded from
// a file, so that a store right after a load comes after the loaded cookies
// even within one tick of the system clock. A t more than a second ahead of
// the clock's time source is left out, so a file written where the clock ran
// ahead can't move the store times more than a second ahead of the system
// clock.
func (c *Clock) Saw(t time.Time) {
	t = t.Round(0)
	if t.After(c.now().Add(time.Second)) {
		return
	}
	if t.After(c.last) {
		c.last = t
	}
}

// NotBefore returns t, or a nanosecond after the last time handed out or seen
// when t is not later, and remembers it. The time is wall clock only
// (Round(0)), so live times and times loaded from a file compare the same way.
func (c *Clock) NotBefore(t time.Time) time.Time {
	t = t.Round(0)
	if !t.After(c.last) {
		t = c.last.Add(time.Nanosecond)
	}
	c.last = t
	return t
}
