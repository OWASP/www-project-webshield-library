# Node & Express Setup

UI gates are a convenience: the server has to enforce every rule. Two packages do that:

| Package | Use it for |
|---|---|
| `@owasp-webshield/express` | Express 4.18+ and 5 middleware. Start here for an Express app. |
| `@owasp-webshield/node` | The framework-neutral functions the middleware is built on, for plain `node:http` or another framework. |

```bash
npm install @owasp-webshield/core @owasp-webshield/express
```

Both are ES modules with TypeScript declarations. They need Node.js 20.19+ or 22.12+, which can also load them from CommonJS with `require()`.

## Sessions are per request

The core `AuthManager`, `TokenManager` and `CSRFTokenManager` each hold one session, which suits a browser tab but not a server. The server packages keep no session state: you supply `verifyToken(token)` (verify a JWT or look the token up in your session store) and, for CSRF, `getExpectedToken(req)`. They run on every request, so concurrent users never share a session.

## Express

```js
import express from "express";
import { createOwlClient, SecurityLogger } from "@owasp-webshield/core";
import {
  assertHardened,
  csrfProtection,
  errorHandler,
  requireAuth,
  requirePermission,
  securityHeaders,
  validate
} from "@owasp-webshield/express";

const logger = new SecurityLogger();
// Refuses to start with debug on, a wildcard CORS origin, insecure cookies, ...
assertHardened({ debug: process.env.NODE_ENV !== "production" }, { logger });

const owl = createOwlClient({ roles: { editor: { permissions: ["write:reports"] } } });

const app = express();
app.use(securityHeaders());          // first, so error responses get the headers too
app.use(express.json({ limit: "100kb" }));
app.use(requireAuth({ verifyToken: (token) => sessions.lookup(token) })); // -> req.owl.session
app.use(csrfProtection());           // POST/PUT/PATCH/DELETE need X-CSRF-Token

app.post("/reports",
  requirePermission("write", "reports", owl),
  validate({ title: { required: true, type: "string", maxLength: 120 } }, { allowUnknownFields: false }),
  (req, res) => res.status(201).json(req.body)
);

app.use(errorHandler({ logger }));   // last: 400/401/403 JSON, 5xx never leak messages
```

| Middleware | Category | On failure |
|---|---|---|
| `securityHeaders()` | A05 | — (CSP, HSTS, `nosniff`, frame and referrer policies) |
| `requireAuth({ verifyToken })` | A07 | 401 with `WWW-Authenticate: Bearer` |
| `requirePermission(action, resource, checker)` | A01 | 403, or 401 without a session |
| `csrfProtection()`, `issueCsrfToken(res)` | A08 | 403 |
| `validate(schema)`, `sanitizeBody(fields)` | A03 | 400 with per-field errors |
| `guardOutboundUrl(getUrl)` | A10 | 403 for private, loopback or metadata targets |
| `errorHandler({ logger })` | A09 | JSON error responses, logged and redacted |
| `assertHardened(config)` | A05 | throws at startup |

The CSRF defaults (`XSRF-TOKEN` cookie, `X-CSRF-Token` header) match the React and Vue adapters' `useSecureHttpClient()`, so they work together without configuration. In TypeScript, the declarations add `req.owl` (`session`, `outboundUrl`) to Express's `Request` type.

## Plain Node or another framework

`@owasp-webshield/node` exposes the same checks as functions that take a Node `IncomingMessage` or a Fetch `Request` and throw a `SecurityError`, which `toErrorResponse()` turns into a safe response:

```js
import http from "node:http";
import { assertPermission, authenticate, securityHeaders, toErrorResponse, verifyCsrf } from "@owasp-webshield/node";

const headers = securityHeaders();

http.createServer(async (req, res) => {
  try {
    const session = await authenticate(req, { verifyToken: (token) => sessions.lookup(token) });
    await verifyCsrf(req, { getExpectedToken: () => sessions.csrfTokenFor(session.userId) });
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

## Runnable examples

- [OWL Enabled Vue + Express Incident Desk](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/owl-enabled-vue-express-incident-desk): the Express middleware in a complete app, with sign-in lockout, rate limits, server-side sessions and per-incident ACL locks.
- [OWL Enabled Node Secrets App](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/owl-enabled-node-secrets-app): a plain `node:http` API on `@owasp-webshield/node`.

The complete guide is in the repository: [Node & Express integration](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/node-api-integration.md).
