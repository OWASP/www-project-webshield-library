# Node API Integration (Express and plain Node)

## Goal

Apply OWL controls at the HTTP boundary of a Node API: authentication, access
control, CSRF, input validation, security headers, outbound-URL checks, error
responses and security logging.

## Packages

| Package | Use it for |
|---|---|
| `@owasp-webshield/express` | Express 4 and 5 middleware. Start here for an Express app. |
| `@owasp-webshield/node` | The framework-neutral functions the Express middleware is built on. Use it with plain `node:http` or another framework. |
| `@owasp-webshield/core` | The managers both packages wrap (`createOwlClient`, `SecurityLogger`, `SSRFGuard`, ...). |

> **Available from 2.0.0.** Both server packages are first published in OWL 2.0.0, released
> alongside core and React 2.0.0. Install matching versions of all OWL packages.

```bash
npm install @owasp-webshield/core @owasp-webshield/express
```

## How this differs from the browser managers

`AuthManager`, `TokenManager` and `CSRFTokenManager` each hold **one** session, which is
right for a browser tab and wrong for a server handling many users at once. The server
packages keep no session state of their own:

- `requireAuth({ verifyToken })` calls your `verifyToken(token, req)` on every request.
  That's where you verify a JWT or look the token up in your session store; return the
  user's `{ userId, roles }`, or `null`.
- `csrfProtection({ getExpectedToken })` reads the expected CSRF token from your
  server-side session. Without it, it uses the double-submit cookie set by
  `issueCsrfToken(res)`.

The session for the current request is available on `req.owl.session`.

## Express

```js
import express from "express";
import { createOwlClient, SecurityLogger, SSRFGuard } from "@owasp-webshield/core";
import {
  assertHardened,
  csrfProtection,
  errorHandler,
  guardOutboundUrl,
  issueCsrfToken,
  requireAuth,
  requirePermission,
  sanitizeBody,
  securityHeaders,
  validate
} from "@owasp-webshield/express";
import { sessions } from "./session-store.js"; // your own store or JWT verifier

// A05: refuse to start with an unsafe configuration. Pass the values the app
// really uses, not secure defaults.
const logger = new SecurityLogger();
assertHardened(
  {
    debug: process.env.NODE_ENV !== "production",
    cors: { origin: process.env.CORS_ORIGIN || "self" },
    cookies: { secure: true, httpOnly: true, sameSite: "Strict" }
  },
  { logger }
);

// A01: roles and per-resource ACL rules.
const owl = createOwlClient({
  roles: {
    viewer: { permissions: ["read:reports"] },
    editor: { permissions: ["write:reports"], inherits: ["viewer"] }
  }
});

const app = express();
app.disable("x-powered-by");
app.use(securityHeaders());              // A05: first, so error responses get the headers too
app.use(express.json({ limit: "100kb" }));

app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: issueCsrfToken(res) }); // A08: double-submit cookie
});

const api = express.Router();
api.use(requireAuth({ verifyToken: (token) => sessions.lookup(token) })); // A07
api.use(csrfProtection());               // A08: POST/PUT/PATCH/DELETE need X-CSRF-Token

api.get("/reports/:id",
  requirePermission("read", (req) => `report:${req.params.id}`, owl),
  (req, res) => res.json({ id: req.params.id, viewer: req.owl.session.userId })
);

api.post("/reports",
  requirePermission("write", "reports", owl),
  validate(
    { title: { required: true, type: "string", maxLength: 120 }, body: { type: "string" } },
    { allowUnknownFields: false }        // A03/A08: rejects mass assignment such as {"role": "admin"}
  ),
  sanitizeBody(["body"]),               // A03: rich text is sanitized before it is stored
  (req, res) => res.status(201).json(req.body)
);

api.post("/webhooks",
  requirePermission("write", "reports", owl),
  guardOutboundUrl((req) => req.body.url, { guard: new SSRFGuard() }), // A10
  (req, res) => res.status(201).json({ target: req.owl.outboundUrl.href })
);

app.use("/api", api);
app.use(errorHandler({ logger }));      // A09: last; maps errors to 400/401/403/500 and logs them
app.listen(3000);
```

### Middleware reference

| Middleware | Category | On failure |
|---|---|---|
| `securityHeaders(overrides?)` | A05 | n/a. Sets CSP, HSTS, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, COOP/CORP and `Permissions-Policy`, and removes `X-Powered-By`. An override of `false` drops a header. The default CSP suits a JSON API; pass your own for HTML. |
| `requireAuth({ verifyToken, getToken? })` | A07 | 401 `AUTH_REQUIRED`, with `WWW-Authenticate: Bearer` |
| `requirePermission(action, resource, checker)` | A01 | 403 `ACCESS_DENIED`, or 401 with no session. `resource` can be a function of `req`. `checker` is a `PermissionChecker` or the `createOwlClient()` result. |
| `csrfProtection({ getExpectedToken?, cookieName?, headerName? })` | A08 | 403 `CSRF_INVALID` |
| `issueCsrfToken(res, options?)` | A08 | n/a. Sets the `XSRF-TOKEN` cookie and returns the token. |
| `validate(schema, { source?, allowUnknownFields?, validator? })` | A03 | 400 `INVALID_INPUT`, with an `errors` array (field, rule, message; never the submitted value) |
| `sanitizeBody(fields, { sanitizer? })` | A03 | n/a |
| `guardOutboundUrl(getUrl, { guard? })` | A10 | 403 `SSRF_BLOCKED`, or 400 for a value that isn't a URL |
| `errorHandler({ logger?, exposeMessages? })` | A09 | Sends JSON error responses. 5xx responses never include the error message. |
| `assertHardened(config, { failOn?, logger? })` | A05 | Throws `MISCONFIGURATION` at startup |

Each middleware forwards its errors to `next(err)`, including from async checks, so they
reach `errorHandler()` on Express 4, which doesn't catch rejected promises itself.

### Working with the browser side

`@owasp-webshield/react`'s `useSecureHttpClient()` and core's
`CSRFTokenManager.fromCookie()` read the `XSRF-TOKEN` cookie and send `X-CSRF-Token`,
which are this package's defaults, so the two work together without configuration.

The double-submit cookie stops cross-site requests. It does not stop a sibling subdomain
you don't control from setting the cookie itself. `csrfProtection()` rejects a request
that carries the cookie twice, but where possible either keep the token in the server-side
session (`getExpectedToken`), or use a `__Host-` cookie name, which the browser won't let a
subdomain set:

```js
const cookieName = "__Host-XSRF-TOKEN";
app.get("/csrf-token", (req, res) => res.json({ csrfToken: issueCsrfToken(res, { cookieName }) }));
api.use(csrfProtection({ cookieName }));
// Browser: CSRFTokenManager.fromCookie("__Host-XSRF-TOKEN"), or useSecureHttpClient({ csrfCookieName: "__Host-XSRF-TOKEN" })
```

### Making the outbound request

`guardOutboundUrl()` checks the URL before the route runs. The DNS answer can change
between that check and the request, and the target can redirect, so make the request
itself with `SafeFetcher`. In Node, give it a dispatcher that re-checks the address at
connect time:

```js
import { Agent } from "undici";
import { SafeFetcher, SSRFGuard } from "@owasp-webshield/core";

const guard = new SSRFGuard();
const fetcher = new SafeFetcher({ guard, dispatcher: new Agent({ connect: { lookup: guard.createSafeLookup() } }) });
await fetcher.fetch(req.owl.outboundUrl.href, { method: "POST", body: JSON.stringify(event) });
```

## Plain Node (or another framework)

`@owasp-webshield/node` exposes the same checks as plain functions. They take a Node
`IncomingMessage` or a Fetch API `Request`, and throw `SecurityError`, which
`toErrorResponse()` turns into a response.

```js
import http from "node:http";
import {
  assertPermission,
  authenticate,
  logRequestError,
  securityHeaders,
  toErrorResponse,
  verifyCsrf
} from "@owasp-webshield/node";

const headers = securityHeaders();

http.createServer(async (req, res) => {
  try {
    const session = await authenticate(req, { verifyToken: (token) => sessions.lookup(token) });
    await verifyCsrf(req, { getExpectedToken: () => sessions.csrfTokenFor(session.userId) });
    assertPermission({ session, action: "read", resource: "reports" }, owl);
    res.writeHead(200, { ...headers, "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  } catch (error) {
    logRequestError(logger, error, req);
    const { status, headers: errorHeaders, body } = toErrorResponse(error);
    res.writeHead(status, { ...headers, ...errorHeaders, "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  }
}).listen(3000);
```

[OWL Enabled Node Secrets App](../examples/owl-enabled-node-secrets-app/README.md) is a
runnable server built this way. For the Express middleware in a complete app (sign-in with
lockout, server-side sessions, CSRF via the `XSRF-TOKEN` cookie, per-incident ACL locks, an
SSRF-guarded webhook), see
[OWL Enabled Vue + Express Incident Desk](../examples/owl-enabled-vue-express-incident-desk/README.md).

| Function | Category |
|---|---|
| `authenticate(req, { verifyToken, getToken? })`, `extractBearerToken(req)` | A07 |
| `checkPermission(...)`, `assertPermission(...)`, `toPermissionChecker(source)` | A01 |
| `verifyCsrf(req, options)`, `issueCsrfToken(options)`, `generateCsrfToken()`, `isSafeMethod(req)` | A08 |
| `assertValidInput(input, schema, options)`, `sanitizeFields(input, fields, options)` | A03 |
| `securityHeaders(overrides)`, `DEFAULT_SECURITY_HEADERS`, `assertHardened(config, options)` | A05 |
| `assertSafeOutboundUrl(url, { guard })` | A10 |
| `toErrorResponse(error, options)`, `statusForSecurityError(code)` | Errors |
| `logRequestError(logger, error, req)`, `requestLogContext(req)` | A09 |
| `serializeCookie(name, value, options)`, `getCookieValues(req, name)`, `getHeader(req, name)` | HTTP helpers |

## Security checklist

- Run `assertHardened()` before `listen()`, with the configuration the app really uses.
- Register `securityHeaders()` first and `errorHandler()` last.
- Authenticate per request against your own session store or token verifier, never against
  a value held in a module-level variable.
- Put `requirePermission()` on every route, scoped to the specific resource where it matters.
- Validate every body with `allowUnknownFields: false` when the body is passed to a model or
  database call as a whole.
- Sanitize user-generated rich text before it is stored or rendered.
- Check user-supplied URLs with `guardOutboundUrl()`, then request them through `SafeFetcher`.
