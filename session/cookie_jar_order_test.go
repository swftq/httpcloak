package session

import (
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/internal/cookieorder"
)

// TestCookieJarStore pins store(cookie, now), the insert helper upstream #139
// adds under the same name: a time later than every earlier one is taken as
// given, a cookie that replaces a live one keeps its creation time where the
// order says so (always on RFC 6265's and WebKit's, only for an unchanged
// value on Chromium's), and one that replaces an expired cookie is new.
func TestCookieJarStore(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	for _, tc := range []struct {
		name          string
		order         cookieorder.Order
		keepsNewValue bool
	}{
		{"rfc6265", cookieorder.RFC6265, true},
		{"chromium", cookieorder.Chromium, false},
		{"webkit", cookieorder.WebKit, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jar := newCookieJar(tc.order)
			sid := func(value string, expires *time.Time) *CookieData {
				return &CookieData{Name: "sid", Value: value, Domain: "example.test", HostOnly: true, Path: "/", Expires: expires}
			}
			check := func(step string, created, stored time.Time) {
				t.Helper()
				c := jar.cookies["example.test"][cookieKey("/", "sid")]
				if c == nil || !c.CreatedAt.Equal(created) || !c.StoredAt.Equal(stored) {
					t.Fatalf("%s: stored %+v, want CreatedAt %v and StoredAt %v", step, c, created, stored)
				}
			}

			jar.store(sid("a", nil), at(0))
			check("first store", at(0), at(0))
			jar.store(sid("a", nil), at(5))
			check("same value", at(0), at(5))
			jar.store(sid("b", nil), at(10))
			if tc.keepsNewValue {
				check("new value", at(0), at(10))
			} else {
				check("new value", at(10), at(10))
			}

			expires := at(15)
			jar.store(sid("c", &expires), at(12))
			jar.store(sid("c", nil), at(20))
			check("after expiry", at(20), at(20))
		})
	}
}
