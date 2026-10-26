# @owasp-webshield/node

Framework-neutral server layer for [OWL (OWASP Webshield Library)](https://owasp.org/www-project-webshield-library/). It provides per-request authentication, access control, CSRF, validation, security headers, SSRF checks, error mapping and security logging as plain functions over [`@owasp-webshield/core`](https://www.npmjs.com/package/@owasp-webshield/core).

Using Express? Install [`@owasp-webshield/express`](https://www.npmjs.com/package/@owasp-webshield/express) instead. It wraps these functions as middleware.

## Installation

```bash
npm install @owasp-webshield/core @owasp-webshield/node
```

An ES module with TypeScript declarations. It needs Node.js 20.19+ or 22.12+, which can also load it from CommonJS with `require()`.

## Usage

Every function takes a Node `IncomingMessage` (plain `node:http`, Express, Connect) or a Fetch API `Request`, and throws a `SecurityError` on failure. `toErrorResponse()` turns any error into a safe response.

```js
import http from "node:http";
import { assertPermission, authenticate, securityHeaders, toErrorResponse, verifyCsrf } from "@owasp-webshield/node";

const headers = securityHeaders();

http.createServer(async (req, res) => {
  try {
    const session = await authenticate(req, { verifyToken: (token) => sessionStore.lookup(token) });
    await verifyCsrf(req, { getExpectedToken: () => sessionStore.csrfTokenFor(session.userId) });
    assertPermission({ session, action: "read", resource: "reports" }, owl);
    res.writeHead(200, { ...headers, "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  } catch (error) {
    const { status, headers: errorHeaders, body } = toErrorResponse(error);
    res.writeHead(status, { ...headers, ...errorHeaders, "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  }
}).listen(3000);
```

The core `AuthManager`/`TokenManager`/`CSRFTokenManager` each hold a single session, which suits a browser tab. These functions hold no state: `verifyToken` and `getExpectedToken` look the session up per request, so concurrent users never share one.

## Exports

| Category | Exports |
|---|---|
| A01 Access Control | `checkPermission`, `assertPermission`, `toPermissionChecker` |
| A03 Injection Defense | `assertValidInput`, `sanitizeFields` |
| A05 Security Misconfiguration | `securityHeaders`, `DEFAULT_SECURITY_HEADERS`, `assertHardened` |
| A07 Auth Session | `authenticate`, `extractBearerToken` |
| A08 Data Integrity | `verifyCsrf`, `issueCsrfToken`, `generateCsrfToken`, `isSafeMethod`, `DEFAULT_CSRF_COOKIE`, `DEFAULT_CSRF_HEADER` |
| A09 Logging Monitoring | `logRequestError`, `requestLogContext` |
| A10 SSRF Defense | `assertSafeOutboundUrl` |
| Errors | `toErrorResponse`, `statusForSecurityError` |
| HTTP helpers | `getHeader`, `getMethod`, `getPath`, `getCookieValues`, `serializeCookie` |

A02 (crypto), A04 (design guard) and A06 (dependency scanning) have no per-request step. Use them from `@owasp-webshield/core` directly.

## Documentation

- [Node & Express integration guide](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/node-api-integration.md)
- [Runnable example (owl-enabled-node-secrets-app)](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/owl-enabled-node-secrets-app)

## License

Apache-2.0. See the [main repository](https://github.com/OWASP/www-project-webshield-library) for the full license text and contribution guidelines.
