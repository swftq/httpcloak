package cflayout

import (
	"slices"
	"strings"
	"testing"
)

// The values are __CFStrHashCharacters from CFString.c run in 64-bit
// arithmetic, recomputed by two independent ports of the C. The home buckets
// are the ones Layout's doc comment walks through.
func TestHashIsCoreFoundations(t *testing.T) {
	for _, c := range []struct {
		name string
		hash uint64
	}{
		{"accept", 8835883671787510},
		{"content-type", 791355398047733494},
		{"sec-fetch-site", 16336341627164194402},
		{"content-length", 8768439688492333496},
		{"x-requested-with", 10539125435008055664},
		{"", 0},
	} {
		if got := Hash(c.name); got != c.hash {
			t.Errorf("Hash(%q) = %d, want %d", c.name, got, c.hash)
		}
	}

	for _, c := range []struct {
		name         string
		size, bucket uint64
	}{
		{"accept", 3, 1}, {"sec-fetch-mode", 3, 0}, {"sec-fetch-dest", 3, 1},
		{"sec-fetch-mode", 7, 6}, {"accept", 7, 2}, {"sec-fetch-dest", 7, 0},
		{"sec-fetch-site", 7, 4}, {"user-agent", 7, 0},
		{"accept", 13, 0}, {"origin", 13, 0}, {"pragma", 13, 0}, {"sec-fetch-site", 13, 0},
	} {
		if got := Hash(c.name) % c.size; got != c.bucket {
			t.Errorf("%q: home bucket %d of %d, want %d", c.name, got, c.size, c.bucket)
		}
	}

	// Over 96 characters only the first, middle and last 32 count. No
	// captured header name is that long, so this pins the rule as CFString.c
	// states it, from an independent port of the C, and nothing more.
	long := ("x-" + strings.Repeat("abcdefghijklmnopqrstuvwxyz0123456789-", 3))[:100]
	if got, want := Hash(long), uint64(15981120555877563595); got != want {
		t.Errorf("Hash of a 100-character name = %d, want %d", got, want)
	}
	// For 100 characters the runs are [0,32), [34,66) and [68,100), so the
	// characters at 32, 33, 66 and 67 do not count and the ones inside do.
	for i, counts := range map[int]bool{31: true, 32: false, 33: false, 34: true, 65: true, 66: false, 67: false, 68: true} {
		other := []byte(long)
		other[i] = '!'
		if changed := Hash(string(other)) != Hash(long); changed != counts {
			t.Errorf("changing character %d of 100: hash changed %v, want %v", i, changed, counts)
		}
	}
}

// The table grows from 3 to 7, 13 and 23 buckets when the 4th, 7th and 12th
// key arrive, re-adding the keys in bucket order, and the captured orders come
// out of it.
func TestLayoutGrowsLikeCFBasicHash(t *testing.T) {
	var tb table
	for k := 1; k <= 20; k++ {
		tb.add(strings.Repeat("k", k))
		want := 41
		switch {
		case k <= 3:
			want = 3
		case k <= 6:
			want = 7
		case k <= 11:
			want = 13
		case k <= 19:
			want = 23
		}
		if len(tb.buckets) != want {
			t.Fatalf("after %d keys the table has %d buckets, want %d", k, len(tb.buckets), want)
		}
	}

	for _, c := range []struct {
		name      string
		insertion []string
		want      []string
	}{
		{
			// A fetch() POST with cache: 'no-store', 11 names in 13 buckets:
			// 372 requests on macOS 26.3 over HTTP/1.1, TLS and HTTP/2
			// (run-20261031-234946 h1.log:15, h2first.log:129). Re-adding in
			// the order the keys first came, or sizing the table once for 11,
			// gives another order; only re-adding in bucket order gives this
			// one.
			"fetch POST",
			[]string{"referer", "pragma", "accept", "content-type", "origin", "sec-fetch-mode",
				"sec-fetch-dest", "sec-fetch-site", "cache-control", "user-agent", "content-length"},
			[]string{"accept", "content-type", "origin", "pragma", "sec-fetch-site", "content-length",
				"sec-fetch-mode", "user-agent", "referer", "sec-fetch-dest", "cache-control"},
		},
		{
			// The WebSocket handshake Safari re-sent after a 302, the only
			// captured block of 12 names, so the only one in 23 buckets
			// (run-20261031-234946 h1.log:5295). Its own order is one
			// insertion order that gives it.
			"redirected handshake",
			[]string{"pragma", "accept", "sec-fetch-site", "sec-websocket-version", "priority",
				"accept-language", "sec-websocket-extensions", "sec-fetch-mode", "cache-control",
				"origin", "user-agent", "sec-fetch-dest"},
			[]string{"pragma", "accept", "sec-fetch-site", "sec-websocket-version", "priority",
				"accept-language", "sec-websocket-extensions", "sec-fetch-mode", "cache-control",
				"origin", "user-agent", "sec-fetch-dest"},
		},
		{
			"navigation",
			[]string{"accept", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-site", "user-agent"},
			[]string{"sec-fetch-dest", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode"},
		},
		{
			"a key given twice keeps its first bucket",
			[]string{"accept", "sec-fetch-mode", "accept", "sec-fetch-dest", "sec-fetch-site", "user-agent"},
			[]string{"sec-fetch-dest", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode"},
		},
		{"empty", nil, []string{}},
	} {
		if got := Layout(c.insertion); !slices.Equal(got, c.want) {
			t.Errorf("%s:\n got %v\nwant %v", c.name, got, c.want)
		}
	}

	// More keys than the largest table holds come back as given.
	many := make([]string, 1066)
	for i := range many {
		many[i] = "x-" + strings.Repeat("a", i%7) + string(rune('a'+i%26)) + strings.Repeat("b", i/26)
	}
	if got := Layout(many); !slices.Equal(got, many) {
		t.Error("1066 keys did not come back in the order given")
	}
}
