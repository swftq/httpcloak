// Package cflayout models the iteration order of a CoreFoundation dictionary
// keyed by strings: CFString's hash and CFBasicHash's linear-probing table,
// from Apple's open-source CoreFoundation (github.com/apple-oss-distributions/CF).
//
// Safari 26 sends the headers a request carries itself in that order, which is
// why its header order depends on the set of names rather than on the kind of
// request; see fingerprint.Preset.CFNetworkHeaderOrder.
package cflayout

// hashEverythingLimit is CFString.c's HashEverythingLimit: a longer string is
// hashed only in its first, middle and last 32 characters.
const hashEverythingLimit = 96

// Hash is CFString's hash of s, __CFStrHashCharacters in CFString.c, in the
// 64-bit CFHashCode of every current Apple platform. Each byte of s stands for
// one UniChar, which is exact for the ASCII header names it is used on.
//
// The result starts at the length. Each full group of four characters c0..c3
// multiplies it by 67503105 and adds c0*16974593 + c1*66049 + c2*257 + c3, and
// each remaining character multiplies it by 257 and adds c. A string over 96
// characters is hashed in groups of four over its first 32 characters, the 32
// around its middle and its last 32 only. The sum is finally multiplied by
// 2^(length & 31) + 1, written as r + r<<(length&31).
func Hash(s string) uint64 {
	n := len(s)
	r := uint64(n)
	four := func(i int) {
		r = r*67503105 + uint64(s[i])*16974593 + uint64(s[i+1])*66049 + uint64(s[i+2])*257 + uint64(s[i+3])
	}
	if n <= hashEverythingLimit {
		i := 0
		for ; i+4 <= n; i += 4 {
			four(i)
		}
		for ; i < n; i++ {
			r = r*257 + uint64(s[i])
		}
	} else {
		for _, start := range [...]int{0, n>>1 - 16, n - 32} {
			for i := start; i < start+32; i += 4 {
				four(i)
			}
		}
	}
	return r + r<<(uint(n)&31)
}

// tableSizes and tableCapacities are CFBasicHash.c's __CFBasicHashTableSizes
// and __CFBasicHashTableCapacities from the first table up: a table of
// tableSizes[i] buckets holds at most tableCapacities[i] keys.
var (
	tableSizes      = [...]int{3, 7, 13, 23, 41, 71, 127, 191, 251, 383, 631, 1087, 1723}
	tableCapacities = [...]int{3, 6, 11, 19, 32, 52, 85, 118, 155, 237, 390, 672, 1065}
)

// Layout returns keys in the order a CFMutableDictionary created empty
// iterates them after they were added in the order given. A key given twice
// keeps the bucket it got first.
//
// The dictionary hashes linearly (__CFDictionaryCreateGeneric passes
// kCFBasicHashLinearHashing). A key goes to bucket Hash(key) % size, or to the
// next free bucket after it, wrapping around (CFBasicHashFindBucket.m). Before
// the k-th key is added, a table that holds fewer than k grows to the smallest
// size that holds k, and __CFBasicHashRehash re-adds the keys it had in bucket
// order, 0 to size-1, not in the order they first came. Iterating walks the
// buckets in index order.
//
// A navigation shows all of it. Added in the order the WebKit 26 presets use,
// accept (home bucket 1 of 3), sec-fetch-mode (0) and sec-fetch-dest (1,
// taken, so 2) fill the first table. sec-fetch-site makes it grow to 7,
// where sec-fetch-mode (home 6), accept (2) and sec-fetch-dest (0) are
// re-added in that bucket order, and sec-fetch-site goes to 4. user-agent's
// home, 0, is taken, so it goes to 1. That is sec-fetch-dest, user-agent,
// accept, sec-fetch-site, sec-fetch-mode, the order Safari 26 sends.
// Collisions are common at these sizes: in 13 buckets accept, origin, pragma
// and sec-fetch-site all have home 0, so their order there depends on the
// order they arrived in.
//
// The sizes stop at 1723 buckets. A list of more than 1065 keys, which no
// request carries, is returned in the order given.
func Layout(keys []string) []string {
	unique := make([]string, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if !seen[k] {
			seen[k] = true
			unique = append(unique, k)
		}
	}
	if len(unique) > tableCapacities[len(tableCapacities)-1] {
		return unique
	}
	var t table
	for _, k := range unique {
		t.add(k)
	}
	return t.keys()
}

// table is a CFBasicHash reduced to what decides the order: which key sits in
// which bucket.
type table struct {
	buckets []string
	used    []bool
	count   int
}

// add puts a key the table does not hold yet into it, growing it first when
// it is full.
func (t *table) add(key string) {
	if t.count+1 > t.capacity() {
		t.grow(t.count + 1)
	}
	t.put(key)
	t.count++
}

// capacity is how many keys the current table holds.
func (t *table) capacity() int {
	for i, size := range tableSizes {
		if size == len(t.buckets) {
			return tableCapacities[i]
		}
	}
	return 0 // no buckets yet: a dictionary created empty has none
}

// grow moves the keys to the smallest table that holds need of them, re-adding
// them in bucket order.
func (t *table) grow(need int) {
	size := tableSizes[len(tableSizes)-1]
	for i, c := range tableCapacities {
		if c >= need {
			size = tableSizes[i]
			break
		}
	}
	old := t.keys()
	t.buckets = make([]string, size)
	t.used = make([]bool, size)
	for _, k := range old {
		t.put(k)
	}
}

// put stores key in its home bucket or the first free one after it.
func (t *table) put(key string) {
	i := int(Hash(key) % uint64(len(t.buckets)))
	for t.used[i] {
		i++
		if i == len(t.buckets) {
			i = 0
		}
	}
	t.buckets[i] = key
	t.used[i] = true
}

// keys returns the keys in bucket order, which is iteration order.
func (t *table) keys() []string {
	out := make([]string, 0, t.count)
	for i, k := range t.buckets {
		if t.used[i] {
			out = append(out, k)
		}
	}
	return out
}
