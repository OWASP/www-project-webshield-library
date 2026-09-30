# A10 — Server-Side Request Forgery (SSRF)

`SSRFGuard` validates outbound URLs and redirect chains against a protocol allowlist and private-IP ranges; `SafeFetcher` wraps `fetch` and re-validates every redirect hop instead of letting the runtime auto-follow them unchecked.

::: warning Node-only
This module imports `node:dns/promises` to resolve hostnames for DNS-rebinding protection. Bundling it directly into a browser build requires polyfilling Node built-ins — see the [FAQ](/faq#can-i-use-owl-in-a-browser-bundle).
:::

## Core API (`@owasp-webshield/core`)

```js
import { SSRFGuard, SafeFetcher } from "@owasp-webshield/core";

const guard = new SSRFGuard({ allowProtocols: ["https:"], maxRedirectHops: 2 });
guard.validateUrl("https://api.example.com/users");
guard.validateRedirectChain(["https://a.example.com", "https://b.example.com"]);

const safeFetcher = new SafeFetcher({
  guard,
  fetchImpl: fetch
});

await safeFetcher.fetch("https://api.example.com/users", { method: "GET" });
```

- `SafeFetcher` follows redirects manually and re-validates every hop, including IPv4-mapped/expanded IPv6 loopback and `0.0.0.0` literals.
- Hostnames are resolved and every returned address is validated via `assertResolvedSafe()` (configurable through the `resolveHost` option), which blocks hostnames whose DNS records point at private addresses. See [CHANGELOG](/changelog) for the 1.0.3 fix.
- `assertResolvedSafe()` alone cannot fully close DNS rebinding: `fetch` resolves the host again when it connects, and a malicious DNS server can answer that second lookup with a private address. In Node, pass a `dispatcher` whose connect-time `lookup` is `guard.createSafeLookup()`, so the socket connects only to an address that was validated:

```js
import { Agent } from "undici";

const pinned = new SafeFetcher({
  guard,
  dispatcher: new Agent({ connect: { lookup: guard.createSafeLookup() } })
});
```

- Give the pinned `Agent` to outbound calls to untrusted URLs only, and never share it with unpinned code. A keep-alive connection is reused without another lookup, so pinning holds only if every socket in the pool was opened through `createSafeLookup()`.
- On a redirect, `SafeFetcher` strips `Authorization`, `Proxy-Authorization`, `Cookie` and `X-CSRF-Token` when the origin changes, and turns a 303 (or a 301/302 after POST) into a bodiless GET, as native `fetch` does.

## React Adapter (`@owasp-webshield/react`)

```jsx
import React from "react";
import { useSafeFetcher } from "@owasp-webshield/react";

export function RemoteConfigLoader() {
  const safeFetcher = useSafeFetcher({ allowProtocols: ["https:"] }, fetch);

  async function loadConfig() {
    const response = await safeFetcher.fetch("https://config.example.com/runtime.json");
    console.log(response.ok);
  }

  return <button onClick={loadConfig}>Load config</button>;
}
```
