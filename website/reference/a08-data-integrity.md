# A08 — Software & Data Integrity Failures

`CSRFTokenManager` issues and validates anti-CSRF tokens; `HTTPClient` wraps `fetch` with CSRF attachment, an async `tokenProvider`, interceptors, and origin-aware credential handling.

## Core API (`@owasp-core/owl`)

```js
import { CSRFTokenManager, DATA_INTEGRITY_TYPES, HTTPClient, SSRFGuard } from "@owasp-core/owl";

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
- `Authorization` / `X-CSRF-Token` headers are only attached to requests whose target matches `baseUrl`'s origin, or an origin explicitly listed in `allowedOrigins` — otherwise a `CREDENTIAL_LEAK_BLOCKED` `SecurityError` is thrown. This closes a cross-origin credential leak; see [CHANGELOG](/changelog) for the 2.0.0 fix.
- Passing an `outboundRequestPolicy` (typically a [`SSRFGuard`](/reference/a10-ssrf-defense)) composes transport hardening with SSRF defense in one client.

## React Adapter (`@owasp-core/owl-react`)

```jsx
import React from "react";
import { useSecureHttpClient, withSecurityHeaders } from "@owasp-core/owl-react";

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
- `withSecurityHeaders()` adds OWL defaults and preserves caller-supplied headers.
