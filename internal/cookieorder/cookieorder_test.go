package cookieorder

import (
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// TestOfFollowsTheEngine checks the order each built-in preset gets from its
// User-Agent: WebKit for Safari and Chrome on iOS, Chromium for every other
// Chrome, and RFC 6265's for Firefox. A User-Agent of no browser engine gets
// RFC 6265's too.
func TestOfFollowsTheEngine(t *testing.T) {
	for _, name := range fingerprint.Available() {
		p := fingerprint.Get(name)
		var want Order
		switch {
		case strings.Contains(name, "ios"), strings.Contains(name, "safari"):
			want = WebKit
		case strings.Contains(name, "chrome"):
			want = Chromium
		case strings.Contains(name, "firefox"):
			want = RFC6265
		default:
			t.Errorf("%s: no browser in the name; add it to this test", name)
			continue
		}
		if got := Of(p.UserAgent); got != want {
			t.Errorf("%s: order %d, want %d (User-Agent %q)", name, got, want, p.UserAgent)
		}
	}
	for _, ua := range []string{"", "curl/8.11.1", "MyApp/2.1 CFNetwork/3826.400.120 Darwin/25.3.0"} {
		if got := Of(ua); got != RFC6265 {
			t.Errorf("Of(%q) = %d, want RFC6265", ua, got)
		}
	}
}

// TestLessIsTotal checks that every order is a strict total order over keys
// with different (Domain, Path, Name), with equal and different times, so a
// sort never leaves two cookies in the order the jar happened to hold them.
func TestLessIsTotal(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	var keys []Key
	for _, domain := range []string{"example.com", ".example.com"} {
		for _, path := range []string{"/", "/a", "/b", "/ab"} {
			for _, name := range []string{"a", "b"} {
				for _, created := range []int{0, 1} {
					for _, stored := range []int{0, 2} {
						keys = append(keys, Key{
							Name: name, Domain: domain, Path: path,
							Created: t0.Add(time.Duration(created) * time.Second),
							Stored:  t0.Add(time.Duration(stored) * time.Second),
						})
					}
				}
			}
		}
	}
	for _, o := range []Order{RFC6265, Chromium, WebKit} {
		for _, a := range keys {
			if o.Less(a, a) {
				t.Fatalf("order %d: Less(a, a) for %+v", o, a)
			}
			for _, b := range keys {
				same := a.Name == b.Name && a.Domain == b.Domain && a.Path == b.Path
				if !same && o.Less(a, b) == o.Less(b, a) {
					t.Fatalf("order %d: Less(a, b) == Less(b, a) for %+v and %+v", o, a, b)
				}
				for _, c := range keys {
					if o.Less(a, b) && o.Less(b, c) && !o.Less(a, c) {
						t.Fatalf("order %d: not transitive over %+v, %+v, %+v", o, a, b, c)
					}
				}
			}
		}
	}
}

// TestLessOrders pins what each order reads: longer paths first everywhere,
// then the most recent store and the name for WebKit, and the earliest
// creation for the others. Equal times fall back to the name.
func TestLessOrders(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	deep := Key{Name: "z", Path: "/app", Created: at(9), Stored: at(9)}
	// a was created first and stored again last; b and c came in one later
	// response, c's line first.
	a := Key{Name: "a", Path: "/", Created: at(1), Stored: at(5)}
	b := Key{Name: "b", Path: "/", Created: at(3), Stored: at(2)}
	c := Key{Name: "c", Path: "/", Created: at(2), Stored: at(2)}
	for _, tc := range []struct {
		o    Order
		want []Key
	}{
		{RFC6265, []Key{deep, a, c, b}},
		{Chromium, []Key{deep, a, c, b}},
		{WebKit, []Key{deep, a, b, c}},
	} {
		for i := range tc.want {
			for k := i + 1; k < len(tc.want); k++ {
				if !tc.o.Less(tc.want[i], tc.want[k]) {
					t.Errorf("order %d: %s should go before %s", tc.o, tc.want[i].Name, tc.want[k].Name)
				}
			}
		}
	}
	x := Key{Name: "x", Path: "/", Created: t0, Stored: t0}
	y := Key{Name: "y", Path: "/", Created: t0, Stored: t0}
	for _, o := range []Order{RFC6265, Chromium, WebKit} {
		if !o.Less(x, y) {
			t.Errorf("order %d: equal times should fall back to the name", o)
		}
	}
}

// TestKeepsCreation pins the replacement rule: Chromium keeps the creation
// time of a cookie set again only when its value is unchanged, every other
// order always.
func TestKeepsCreation(t *testing.T) {
	for _, tc := range []struct {
		o              Order
		same, newValue bool
	}{
		{RFC6265, true, true},
		{Chromium, true, false},
		{WebKit, true, true},
	} {
		if got := tc.o.KeepsCreation("1", "1"); got != tc.same {
			t.Errorf("order %d, same value: KeepsCreation = %v, want %v", tc.o, got, tc.same)
		}
		if got := tc.o.KeepsCreation("1", "2"); got != tc.newValue {
			t.Errorf("order %d, new value: KeepsCreation = %v, want %v", tc.o, got, tc.newValue)
		}
	}
}

// TestClockNeverRepeats checks that a jar's clock hands out strictly later
// times however its source behaves: frozen, as Go's Windows clock is between
// two timer interrupts, and stepping backwards. Each time is wall clock only.
func TestClockNeverRepeats(t *testing.T) {
	t0 := time.Now()
	sources := map[string]func(i int) time.Time{
		"frozen":    func(int) time.Time { return t0 },
		"backwards": func(i int) time.Time { return t0.Add(-time.Duration(i) * time.Millisecond) },
		"forwards":  func(i int) time.Time { return t0.Add(time.Duration(i) * time.Millisecond) },
	}
	for name, source := range sources {
		var c Clock
		i := 0
		c.Now = func() time.Time { i++; return source(i) }
		var last time.Time
		for n := 0; n < 10000; n++ {
			got := c.Next()
			if n > 0 && !got.After(last) {
				t.Fatalf("%s: stamp %d, %v, is not after %v", name, n, got, last)
			}
			if got != got.Round(0) {
				t.Fatalf("%s: stamp %d carries a monotonic reading", name, n)
			}
			last = got
		}
	}

	// A time later than the last one handed out comes back as it is.
	var c Clock
	first := c.NotBefore(t0)
	if !first.Equal(t0) {
		t.Fatalf("NotBefore(t0) = %v on a new clock, want t0", first)
	}
	later := t0.Add(time.Second)
	if got := c.NotBefore(later); !got.Equal(later) {
		t.Fatalf("NotBefore(later) = %v, want %v", got, later)
	}
	if got := c.NotBefore(t0); !got.Equal(later.Add(time.Nanosecond)) {
		t.Fatalf("NotBefore(t0) after later = %v, want a nanosecond after later", got)
	}
}

// TestClockSaw checks that a time loaded from a file moves the clock: the
// next store is later than it, even with the time source frozen, as Go's
// Windows clock is between two timer interrupts. A time up to a second ahead
// of the time source is followed, and one further ahead is left out. The
// source reads a day far from the system clock, so the bound must come from
// it.
func TestClockSaw(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := Clock{Now: func() time.Time { return t0 }}
	if got := c.Next(); !got.Equal(t0) {
		t.Fatalf("Next() = %v, want t0", got)
	}
	for _, tc := range []struct {
		name      string
		saw, want time.Time
	}{
		{"earlier", t0.Add(-time.Hour), t0.Add(time.Nanosecond)},
		{"same tick", t0.Add(5 * time.Nanosecond), t0.Add(6 * time.Nanosecond)},
		{"a second ahead", t0.Add(time.Second), t0.Add(time.Second + time.Nanosecond)},
		{"further ahead", t0.Add(time.Hour), t0.Add(time.Second + 2*time.Nanosecond)},
	} {
		c.Saw(tc.saw)
		if got := c.Next(); !got.Equal(tc.want) {
			t.Errorf("%s: Next() after Saw(t0 + %v) = t0 + %v, want t0 + %v", tc.name, tc.saw.Sub(t0), got.Sub(t0), tc.want.Sub(t0))
		}
	}

	// On the system clock too: an hour ahead is left out.
	var sys Clock
	sys.Saw(time.Now().Add(time.Hour))
	if got := sys.Next(); got.After(time.Now().Add(time.Second)) {
		t.Errorf("Next() = %v after Saw an hour ahead, want the system clock", got)
	}
}
