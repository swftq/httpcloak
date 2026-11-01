---
title: Cookie Jar
sidebar_position: 2
---

# Cookie Jar

Every `Session` carries an in-memory cookie jar that stores `Set-Cookie` values from responses and attaches the matching ones to the next request, the same way a browser tab does. The jar is on by default and there's nothing to wire up; constructing the session is enough.

## What gets stored

When a response comes back with `Set-Cookie` headers, httpcloak parses each one and saves the full attribute set:

- `name` and `value`
- `domain` (with the host-only flag tracked separately)
- `path`
- `expires` and `max-age`
- `secure`
- `httpOnly`
- `sameSite`

The jar also records when it first stored each cookie and when it last stored it. When it builds a `Cookie` header, it lists the cookies in the order the preset's browser does. Longer paths go first on every preset, and after that:

- **Chrome, Firefox and the other presets** send the earliest created cookie first, which is RFC 6265's order, and the cookies one response set in `Set-Cookie` order. A cookie set again while it is still live keeps its place, as RFC 6265 asks and Firefox 159 does. On the Chrome presets it keeps its place only when its value is unchanged: with a new value it goes behind the cookies stored before it, as Chrome 156 does.
- **Safari and Chrome on iOS**, which runs on WebKit, send the most recently stored cookie first, and the cookies one response set in name order, as Safari 26.3 does. A cookie set again moves to the front. Every cookie in that capture had `Path=/`, so for these presets the longer-paths-first rule is RFC 6265's and was not captured.

The order follows the browser engine of the preset's User-Agent, so a custom preset gets the order of the browser it presents. Each store gets a time later than the jar's last one, so the order doesn't depend on how fine the system clock is, and it stays the same from one request to the next. The lower-level `client.Client` orders its own jar the same way, and switches the order with `SetPreset`.

Loading a saved session with `LoadSession` moves the jar's clock past the times it loads, so a cookie stored right after the load is newer than every loaded one, even within one tick of the system clock. The clock moves at most a second past the system clock for this: a loaded time further ahead, from a file written on a machine whose clock ran ahead, leaves the clock where it is, and its cookie counts as newer than the cookies stored until the system clock reaches that time.

## When the jar sends what

On the next request, the jar walks its stored cookies and picks the ones that match:

- the request **host** (host-only cookies need an exact match, domain cookies match the domain and any subdomain)
- the request **path** (cookie path must be a prefix of the request path with a `/` boundary)
- the request **scheme** (secure cookies only ride HTTPS)
- the **expiry** (anything past its expiry gets skipped)

The matches get joined into a single `Cookie:` header and attached to the outgoing request.

See [Domain and Path Matching](./domain-and-path-matching) for the full set of rules and the edge cases that catch most callers out.

## Lifecycle

Cookies live in memory for as long as the `Session` lives. Closing the session drops the jar with it.

To persist cookies across processes, use `Save()` and `LoadSession()`. The pair serialize the jar (along with TLS resumption tickets and a handful of other state) to a file that can be reloaded later. See [Session save & restore](/connection-lifecycle/session-save-restore) for the full flow.

## Quick example

The example below sets a cookie via `httpbin.org/cookies/set`, then reads `httpbin.org/cookies` on the same session to confirm the jar replayed it on the second request.

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
package main

import (
	"context"
	"fmt"
	"io"

	"github.com/sardanioss/httpcloak"
)

func main() {
	s := httpcloak.NewSession("chrome-152")
	defer s.Close()

	ctx := context.Background()

	r1, _ := s.Get(ctx, "https://httpbin.org/cookies/set?demo=hello")
	r1.Close()

	r2, _ := s.Get(ctx, "https://httpbin.org/cookies")
	body, _ := io.ReadAll(r2.Body)
	r2.Close()
	fmt.Println(string(body))
	// {"cookies": {"demo": "hello"}}
}
```

</TabItem>
<TabItem value="python" label="Python">

```python
import httpcloak

with httpcloak.Session(preset="chrome-152") as s:
    s.get("https://httpbin.org/cookies/set?demo=hello")
    r = s.get("https://httpbin.org/cookies")
    print(r.json())
    # {'cookies': {'demo': 'hello'}}
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```js
const httpcloak = require("httpcloak");

const s = new httpcloak.Session({ preset: "chrome-152" });
try {
  await s.get("https://httpbin.org/cookies/set?demo=hello");
  const r = await s.get("https://httpbin.org/cookies");
  console.log(r.json());
  // { cookies: { demo: 'hello' } }
} finally {
  s.close();
}
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-152");

s.Get("https://httpbin.org/cookies/set?demo=hello");
var r = s.Get("https://httpbin.org/cookies");
Console.WriteLine(r.Text);
// {"cookies": {"demo": "hello"}}
```

</TabItem>
</Tabs>

## Inspecting the jar

The session exposes the jar's contents through five methods:

- `GetCookies()` returns the full list of `CookieInfo` records with domain, path, expiry, and flags. The same shape across Go, Python, Node, and .NET (`List[Cookie]` / `Cookie[]` / `List<Cookie>`).
- `GetCookiesDetailed()` is an alias of `GetCookies` kept for migration symmetry. v1.6.5 finished the deprecation cycle that started in v1.6.1; the older flat name-to-value dict is gone, so both names return the same Cookie-object list.
- `SetCookie(...)` adds or updates a cookie programmatically. Each call is a store of its own, so on the Safari and iOS presets the cookie set last goes first. Seed several cookies oldest first, or restore a saved jar with `LoadSession`.
- `DeleteCookie(name, domain)` removes one (pass an empty domain to wipe matches across every domain).
- `ClearCookies()` empties the jar.

These are useful for tests, debugging, and seeding the jar before the first request goes out.

:::info DoStream parity (since 1.6.6)
`DoStream()` cookie-jar updates landed in 1.6.6 (commit `e3acf96`). On 1.6.6 or newer, `Do` and `DoStream` feed the same jar identically; the gap only affected the lower-level `client.Client.DoStream` on older builds, since session-level streams already had parity. See [Streaming Responses](../requests-and-responses/streaming-responses) for the manual workaround on pre-1.6.6 builds.
:::

## What the jar does NOT do

- It doesn't enforce `__Host-` and `__Secure-` cookie name prefixes with the strict RFC checks. The underlying flags (`Secure`, host-only) are still respected, but the prefix rules themselves aren't enforced separately.
- It stores `SameSite` but doesn't act on it. There's no cross-site request tracking inside httpcloak, so cookies always go out on requests you initiate.
- It doesn't garbage-collect expired cookies on every read. They get filtered out at send time, but they keep occupying space in the jar until that filter runs. The internal `*CookieJar` has a `ClearExpired()` method, but the public `Session` surface does not currently re-export it. For a forced clean snapshot, the workaround is `ClearCookies()` plus a re-fetch of the host's authentication cookie.

## When you don't want the jar

To drive cookies yourself, switch the jar off with `WithoutCookieJar()`. See [Disabling the Cookie Jar](./disabling-cookie-jar).
