# @owasp-webshield/express

Express adapter for [OWL (OWASP Webshield Library)](https://owasp.org/www-project-webshield-library/). It provides middleware for authentication, access control, CSRF, input validation, security headers, SSRF checks and security error handling, built on [`@owasp-webshield/core`](https://www.npmjs.com/package/@owasp-webshield/core) and [`@owasp-webshield/node`](https://www.npmjs.com/package/@owasp-webshield/node). It works with Express 4.18+ and 5.

## Installation

```bash
npm install @owasp-webshield/core @owasp-webshield/express
```

## Quick start

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
assertHardened({ debug: process.env.NODE_ENV !== "production" }, { logger }); // throws on unsafe config

const owl = createOwlClient({ roles: { editor: { permissions: ["write:reports"] } } });

const app = express();
app.use(securityHeaders());
app.use(express.json());
app.use(requireAuth({ verifyToken: (token) => sessionStore.lookup(token) })); // -> req.owl.session
app.use(csrfProtection());

app.post("/reports",
  requirePermission("write", "reports", owl),
  validate({ title: { required: true, type: "string", maxLength: 120 } }, { allowUnknownFields: false }),
  (req, res) => res.status(201).json(req.body)
);

app.use(errorHandler({ logger }));
```

`verifyToken` is called on every request, so sessions are never shared between users. Return the user's `{ userId, roles }`, or `null` for an unknown or expired token.

## Middleware

| Category | Export |
|---|---|
| A01 Access Control | `requirePermission(action, resource, checker)` |
| A03 Injection Defense | `validate(schema, options)`, `sanitizeBody(fields, options)` |
| A05 Security Misconfiguration | `securityHeaders(overrides)`, `assertHardened(config, options)` |
| A07 Auth Session | `requireAuth({ verifyToken })` |
| A08 Data Integrity | `csrfProtection(options)`, `issueCsrfToken(res, options)` |
| A09 Logging Monitoring | `errorHandler({ logger })` |
| A10 SSRF Defense | `guardOutboundUrl(getUrl, { guard })` |

Security failures become JSON responses (`400`/`401`/`403`, with the `SecurityErrorCode` in `error`). A `500` never includes the error's message.

## Documentation

- [Node & Express integration guide](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/node-api-integration.md)
- [API reference](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/api-reference.md)

## License

Apache-2.0. See the [main repository](https://github.com/OWASP/www-project-webshield-library) for the full license text and contribution guidelines.
