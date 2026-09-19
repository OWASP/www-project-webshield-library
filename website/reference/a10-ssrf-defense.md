# A10 — Server-Side Request Forgery (SSRF)

`SSRFGuard` validates outbound URLs and redirect chains against a protocol allowlist and private-IP ranges; `SafeFetcher` wraps `fetch` and re-validates every redirect hop instead of letting the runtime auto-follow them unchecked.

::: warning Node-only
This module imports `node:dns/promises` to resolve hostnames for DNS-rebinding protection. Bundling it directly into a browser build requires polyfilling Node built-ins — see the [FAQ](/faq#can-i-use-owl-in-a-browser-bundle).
:::

## Core API (`@owasp-core/owl`)

```js
import { SSRFGuard, SafeFetcher } from "@owasp-core/owl";

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
- Hostnames are resolved and every returned address is validated via `assertResolvedSafe()` (configurable through the `resolveHost` option), closing DNS-rebinding gaps. See [CHANGELOG](/changelog) for the 1.0.3 fix.

## React Adapter (`@owasp-core/owl-react`)

```jsx
import React from "react";
import { useSafeFetcher } from "@owasp-core/owl-react";

export function RemoteConfigLoader() {
  const safeFetcher = useSafeFetcher({ allowProtocols: ["https:"] }, fetch);

  async function loadConfig() {
    const response = await safeFetcher.fetch("https://config.example.com/runtime.json");
    console.log(response.ok);
  }

  return <button onClick={loadConfig}>Load config</button>;
}
```
