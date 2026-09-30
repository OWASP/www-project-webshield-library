# A08 — Software & Data Integrity Failures

`CSRFTokenManager` issues and validates anti-CSRF tokens; `HTTPClient` wraps `fetch` with CSRF attachment, an async `tokenProvider`, interceptors, and origin-aware credential handling.

## Core API (`@owasp-webshield/core`)

```js
import { CSRFTokenManager, DATA_INTEGRITY_TYPES, HTTPClient, SSRFGuard } from "@owasp-webshield/core";

const csrf = new CSRFTokenManager();
csrf.rotateToken();
csrf.attach({});
csrf.validate(csrf.getToken());

const client = new HTTPClient({
  baseUrl: "https://api.example.com",
  csrfManager: csrf,
  tokenProvider: async () => "access-token",
  outboundRequestPolicy: new SSRFGuard()
});

client.addRequestInterceptor(async (config) => ({
  ...config,
  headers: { ...config.headers, "X-Request-Id": "req-1" }
}));

const response = await client.request("/profile", { method: "GET" });
console.log(response.ok, response.data, DATA_INTEGRITY_TYPES);
```

- `HTTPClient` accepts a `tokenProvider` function that may return a string, `null`, or a promise for either value. The client always awaits it before sending the request.
- `Authorization` / `X-CSRF-Token` headers are only attached to requests whose target matches `baseUrl`'s origin, or an origin explicitly listed in `allowedOrigins` — otherwise a `CREDENTIAL_LEAK_BLOCKED` `SecurityError` is thrown. This closes a cross-origin credential leak; see [CHANGELOG](/changelog) for the 1.0.3 fix.
- Passing an `outboundRequestPolicy` (typically a [`SSRFGuard`](/reference/a10-ssrf-defense)) composes transport hardening with SSRF defense in one client: the target is DNS-validated, redirects are followed manually with every hop re-validated, and `Authorization`/`X-CSRF-Token`/`Cookie` are stripped when a redirect leaves the original origin. In browsers the target of a manual redirect is hidden (an `opaqueredirect` response), so it can't be validated and the request fails with `SSRF_BLOCKED`. Request the final URL directly.
- Credentialed requests (with `Authorization` or `X-CSRF-Token`) follow redirects manually even without a policy, and strip those headers when a redirect leaves the current origin; `fetch` itself would forward `X-CSRF-Token`. In browsers the redirect target is hidden, so a redirected credentialed request fails with `CREDENTIAL_LEAK_BLOCKED` unless you pass `redirect: "follow"` explicitly.
- Under Node, a policy with DNS validation resolves every hostname before the request, so hostnames that don't resolve (for example fake domains in tests) fail with `SSRF_BLOCKED: Host could not be resolved`. Pass `new SSRFGuard({ resolveHost })` in tests.

## React Adapter (`@owasp-webshield/react`)

```jsx
import React from "react";
import { useSecureHttpClient, withSecurityHeaders } from "@owasp-webshield/react";

export function ProfileLoader({ tokenManager }) {
  const client = useSecureHttpClient({
    baseUrl: "https://api.example.com",
    tokenProvider: async () => tokenManager.getAccessToken()
  });

  async function loadProfile() {
    const response = await client.request(
      "/profile",
      withSecurityHeaders({
        method: "GET",
        headers: { "X-Feature": "profile-view" }
      })
    );

    console.log(response.data);
  }

  return <button onClick={loadProfile}>Load profile</button>;
}
```

- `useSecureHttpClient()` creates one `CSRFTokenManager` per hook instance and rotates a token during initialization.
- `withSecurityHeaders()` applies request-side defaults (`credentials: "same-origin"`, `referrerPolicy: "strict-origin-when-cross-origin"`) and preserves caller-supplied options and headers. Response headers such as `X-Frame-Options` must be set by your server.
