---
title: Per-Request Cookies
sidebar_position: 4
---

# Per-Request Cookies

A per-request `Cookie` header attaches cookies to a single call without touching the session jar. The header you set goes onto the wire byte-for-byte; httpcloak doesn't reorder, normalise, or rewrite the string. The pattern fits one-off testing, replaying a captured cookie value from somewhere outside the lib, or driving cookies by hand when the jar is off.

## Setting it on a request

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
req := &httpcloak.Request{
	Method: "GET",
	URL:    "https://httpbin.org/cookies",
	Headers: map[string][]string{
		"Cookie": {"session=abc; lang=en"},
	},
}
r, _ := s.Do(ctx, req)
defer r.Close()
```

</TabItem>
<TabItem value="python" label="Python">

```python
# Option A: explicit Cookie header
r = s.get(
    "https://httpbin.org/cookies",
    headers={"Cookie": "session=abc; lang=en"},
)

# Option B: cookies kwarg (joined into a single Cookie header for you)
r = s.get(
    "https://httpbin.org/cookies",
    cookies={"session": "abc", "lang": "en"},
)
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```js
// Option A: explicit Cookie header
let r = await s.get("https://httpbin.org/cookies", {
  headers: { Cookie: "session=abc; lang=en" },
});

// Option B: cookies option
r = await s.get("https://httpbin.org/cookies", {
  cookies: { session: "abc", lang: "en" },
});
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
// Option A: explicit Cookie header
var headers = new Dictionary<string, string> {
    { "Cookie", "session=abc; lang=en" }
};
var r = s.Get("https://httpbin.org/cookies", headers: headers);

// Option B: cookies parameter
var cookies = new Dictionary<string, string> {
    { "session", "abc" },
    { "lang", "en" }
};
var r2 = s.Get("https://httpbin.org/cookies", cookies: cookies);
```

</TabItem>
</Tabs>

## How this interacts with the jar

When the jar is on, the lib **merges** the per-request `Cookie` header with whatever the jar would have sent on its own. The caller-supplied header comes first, jar contents follow, joined with `; `.

The merge is usually what you want. To send only the per-request cookie and bypass the jar entirely, two clean options exist:

1. Disable the jar with [`WithoutCookieJar()`](./disabling-cookie-jar) for the whole session.
2. Call `ClearCookies()` on the session right before the request, then attach the header.

Setting `Cookie: ""` doesn't suppress the merge. The lib treats an empty value as "no per-request cookie" rather than "send nothing", so the jar still injects.

## Cookie order matters for fingerprinting

The order of cookies in the `Cookie` header is part of the client fingerprint, and browsers differ on it. Chrome and Firefox put longer paths first, then sort by creation time, per RFC 6265; Safari sends the most recently stored cookie first. httpcloak preserves whatever string you hand it byte-for-byte without re-sorting.

When hand-rolling cookies for a browser-shaped request, sort them yourself before attaching the header. Don't rely on `dict` iteration order in scripts, don't shuffle the order between requests on the same flow, and check that your sort matches the order the jar would have produced. Anti-bot vendors watch for cookie order drift between requests, and a mismatch on a long flow flags faster than most people expect.

When the jar is on, this is a non-issue. The jar sorts the way the preset's browser does (see [Cookie Jar](./cookie-jar)) and the order stays consistent across the session. Manual ordering only comes up when the `Cookie` header is being driven by hand.

## When per-request beats the jar

A few situations where a per-request header is the cleaner option:

- **One-off auth.** A single API call needs a special token cookie that shouldn't stick around for follow-ups.
- **Replaying a captured session.** A `Cookie` string from a browser export pastes straight in.
- **Cross-host scenarios.** The same cookie needs to ride out to two different hosts that the jar's domain rules wouldn't cover on their own.

Outside of those, let the jar do the work.
