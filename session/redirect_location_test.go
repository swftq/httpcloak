package session

import "testing"

// resolveURL resolves a redirect's Location and a page's src or href. The
// cases are the ones captured from Chrome 156 and Firefox 159 on 2026-10-28,
// as a 302's Location and as the URL of an img, a script and a stylesheet. The
// two browsers sent the same request-target for each, every way it was given.
func TestResolveURL(t *testing.T) {
	const base = "https://a.test/r/x/dir/sub/page?orig=1"
	cases := []struct {
		name, ref, want string
	}{
		{"root-relative keeps its query", "/app/page.html?q=1", "https://a.test/app/page.html?q=1"},
		{"path-relative", "next?x=1", "https://a.test/r/x/dir/sub/next?x=1"},
		{"dot-dot", "../up?x=2", "https://a.test/r/x/dir/up?x=2"},
		{"dot", "./same?x=3", "https://a.test/r/x/dir/sub/same?x=3"},
		{"dot segments inside", "../../a/./b/../c?x=4", "https://a.test/r/x/a/c?x=4"},
		{"dot-dot above the root", "../../../../../../top?x=5", "https://a.test/top?x=5"},
		{"lone dot", ".", "https://a.test/r/x/dir/sub/"},
		{"lone dot-dot", "..", "https://a.test/r/x/dir/"},
		{"query only replaces the query", "?page=2", "https://a.test/r/x/dir/sub/page?page=2"},
		{"protocol-relative takes the scheme", "//b.test/pr?x=6", "https://b.test/pr?x=6"},
		{"fragment kept on the URL", "/frag?x=7#sec", "https://a.test/frag?x=7#sec"},
		{"empty query kept", "/eq?", "https://a.test/eq?"},
		{"semicolon in the path", "/semi;p=1?x=23", "https://a.test/semi;p=1?x=23"},

		// An absolute reference is resolved too. It used to be returned as
		// given, dot segments and all.
		{"absolute loses its dot segments", "https://a.test/a/b/../abs?x=8", "https://a.test/a/abs?x=8"},
		{"absolute on another scheme", "http://b.test/./x/../y?x=1", "http://b.test/y?x=1"},
		{"upper-case scheme", "HTTPS://a.test/upper?x=22", "https://a.test/upper?x=22"},

		// %XX escapes in the path stay as written. %3F is a path character,
		// not a query separator: it used to be split into a query.
		{"%3F stays in the path", "/enc%3Fq=1", "https://a.test/enc%3Fq=1"},
		{"%3F before a real query", "/enc%3Fq=1?x=2", "https://a.test/enc%3Fq=1?x=2"},
		{"unreserved escapes kept", "/%41%62c?x=19", "https://a.test/%41%62c?x=19"},
		{"lower-case escapes kept", "/lc%c3%a9?x=24", "https://a.test/lc%c3%a9?x=24"},
		{"non-ASCII path", "/caf\u00e9?x=14", "https://a.test/caf%C3%A9?x=14"},
		{"space in the path", "/a b?x=25", "https://a.test/a%20b?x=25"},

		// The query is encoded with the URL standard's special-query set,
		// whatever form the reference took. %XX escapes are left alone, even
		// invalid ones, and so are the characters the set leaves out.
		{"non-ASCII query", "/na?q=caf\u00e9", "https://a.test/na?q=caf%C3%A9"},
		{"space in the query", "/sp?q=a b", "https://a.test/sp?q=a%20b"},
		{"apostrophe in the query", "/ap?q='x'", "https://a.test/ap?q=%27x%27"},
		{"quotes and angle brackets", `/dq?q="x"<>`, "https://a.test/dq?q=%22x%22%3C%3E"},
		{"combined", `/enc?q=a b&n=café&s='x'&d="y"<>`, "https://a.test/enc?q=a%20b&n=caf%C3%A9&s=%27x%27&d=%22y%22%3C%3E"},
		{"absolute query", "https://a.test/absq?q=a b&n=café", "https://a.test/absq?q=a%20b&n=caf%C3%A9"},
		{"protocol-relative query", "//b.test/protoq?q=a b", "https://b.test/protoq?q=a%20b"},
		{"query-only query", "?q=a b'", "https://a.test/r/x/dir/sub/page?q=a%20b%27"},
		{"escapes left alone", "/keep?q=a%20b&r=%zz&p=+&e=%C3%A9&l=%c3%a9", "https://a.test/keep?q=a%20b&r=%zz&p=+&e=%C3%A9&l=%c3%a9"},
		{"characters outside the set", "/qc?a={}|^`&b=\\&c=[]&d=/?:@!$&e=;,", "https://a.test/qc?a={}|^`&b=\\&c=[]&d=/?:@!$&e=;,"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveURL(base, c.ref)
			if err != nil {
				t.Fatalf("resolveURL(%q): %v", c.ref, err)
			}
			if got != c.want {
				t.Errorf("resolveURL(%q) = %q, want %q", c.ref, got, c.want)
			}
		})
	}

	// An invalid %-escape in the path does not parse. Both browsers failed
	// the fetch, and loaded no img, script or stylesheet, without a request.
	for _, ref := range []string{"/bad%zz?x=17", "https://a.test/bad%zz?x=17"} {
		if got, err := resolveURL(base, ref); err == nil {
			t.Errorf("resolveURL(%q) = %q, want an error", ref, got)
		}
	}
}

// The C0 controls and DEL never reach encodeSpecialQuery through net/url,
// which rejects them, but they are in the set.
func TestEncodeSpecialQuery(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"a=1&b=2", "a=1&b=2"},
		{"a=\x00\x1f\x7f", "a=%00%1F%7F"},
		{"a=#", "a=%23"},
		{"\xe9", "%E9"},
	}
	for _, c := range cases {
		if got := encodeSpecialQuery(c.in); got != c.want {
			t.Errorf("encodeSpecialQuery(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
