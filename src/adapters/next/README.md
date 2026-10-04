# @owasp-webshield/next

Next.js adapter for [OWL (OWASP Webshield Library)](https://owasp.org/www-project-webshield-library/). It guards App Router route handlers (authentication, access control, CSRF, input validation, SSRF checks, security headers and safe error responses), checks CSRF in middleware, sets security headers from `next.config.js`, reads the session in Server Components and Server Actions, and makes the React adapter usable from them. It is built on [`@owasp-webshield/node`](https://www.npmjs.com/package/@owasp-webshield/node) and [`@owasp-webshield/react`](https://www.npmjs.com/package/@owasp-webshield/react), and supports Next.js 14 and later (tested with 16).

## Why it exists

`@owasp-webshield/react` and `@owasp-webshield/node` alone leave gaps in an App Router app, each easy to miss in review:

- The React adapter can't be imported into Server Components (no `"use client"`).
- Every route handler has to repeat the same steps: authenticate, check CSRF and the permission, validate, map errors, add headers. A route that skips one has a hole.
- A plain `try`/`catch` turns `redirect()` and `notFound()` into 500s.
- Route handlers don't limit request bodies.
- `params` is a Promise since Next.js 15, so `params.id` in a permission check is `undefined`.
- OWL's JSON API CSP breaks pages, and `next.config.js` headers replace route-handler headers.
- `NextResponse` drops a `Set-Cookie` header appended before `cookies.set()`.
- Server Components and Server Actions have no request to authenticate.

This package closes each of these. The [Next.js integration guide](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/nextjs-integration.md#why-a-dedicated-nextjs-adapter) lists them with what the adapter does about each.

## Installation

```bash
npm install @owasp-webshield/core @owasp-webshield/next
```

An ES module with TypeScript declarations. It needs Node.js 20.19+ or 22.12+.

| Import | Use it in |
|---|---|
| `@owasp-webshield/next` | Route handlers, `middleware.js` / `proxy.js`, `next.config.js`. Uses only the Fetch API. |
| `@owasp-webshield/next/server` | Server Components and Server Actions (reads `next/headers`). |
| `@owasp-webshield/next/client` | Client components. The React adapter's components and hooks, marked `"use client"`. |

## Route handlers

```js
// app/api/reports/[id]/route.js
import { withOwl } from "@owasp-webshield/next";
import { owl, verifyToken } from "@/lib/owl";

export const GET = withOwl(
  async (request, context, { session, params }) => Response.json(await reports.get(params.id, session.userId)),
  {
    auth: { verifyToken },
    permission: { action: "read", resource: ({ params }) => `report:${params.id}`, checker: owl }
  }
);

export const PATCH = withOwl(
  async (request, context, { body }) => Response.json(await reports.update(body)),
  {
    auth: { verifyToken },
    csrf: true,
    permission: { action: "write", resource: "reports", checker: owl },
    body: { schema: { title: { required: true, type: "string", maxLength: 120 } }, allowUnknownFields: false, sanitize: ["title"] }
  }
);
```

The checks run in this order, and the first failure becomes a JSON response (`400`/`401`/`403`, with the `SecurityErrorCode` in `error`):

| Option | Category | Does |
|---|---|---|
| `auth: { verifyToken, getToken }` | A07 | Authenticates the request; the session goes to the handler. `getToken: cookieToken("session")` reads a cookie instead of the `Authorization` header. |
| `csrf: true` or `{ getExpectedToken, cookieName, headerName }` | A08 | Rejects POST/PUT/PATCH/DELETE without a valid `X-CSRF-Token`. |
| `permission: { action, resource, checker }` | A01 | Requires the permission for a role of the session, with ACL deny-overrides. `resource` can be a function of the checked state. |
| `query: { schema, allowUnknownFields }` | A03 | Validates the search params. |
| `body: { schema, allowUnknownFields, sanitize, limit }` | A03 | Parses the JSON body (100 KB limit by default; 413 over it, 415 for another content type), validates and sanitizes it. |
| `outboundUrl: { getUrl, guard }` | A10 | Checks a caller-supplied URL, e.g. `getUrl: ({ body }) => body.webhookUrl`. |
| `securityHeaders` | A05 | Header overrides, or `false`. |
| `logger`, `exposeMessages` | A09 | Logs every failure through a `SecurityLogger`; `exposeMessages: false` sends only the error code. |

The handler gets `(request, context, owl)`, where `owl` holds `params` (already awaited), `session`, `query`, `body` and `outboundUrl`. Errors it throws are mapped the same way, and a `500` never includes the error's message. `redirect()`, `notFound()` and Next.js's other control-flow errors pass through unchanged.

## Middleware

```js
// middleware.js (proxy.js in Next.js 16)
import { NextResponse } from "next/server";
import { guardCsrf } from "@owasp-webshield/next";

export async function middleware(request) {
  return (await guardCsrf(request)) ?? NextResponse.next();
}

export const config = { matcher: ["/api/:path*"] };
```

Keep the matcher on API routes. Server Actions POST to page URLs without the CSRF header, and Next.js checks their `Origin` itself. Do authentication and permission checks in the route handler or page, not only in middleware. `ensureCsrfCookie(request, response)` issues the CSRF cookie on a page response if the browser doesn't have one yet; `issueCsrfToken(response)` always issues a new one.

## Security headers for pages

```js
// next.config.mjs
import { securityHeadersConfig } from "@owasp-webshield/next";

export default {
  poweredByHeader: false,
  async headers() {
    return securityHeadersConfig({}, { source: "/((?!api/).*)" });
  }
};
```

Headers from `next.config.js` replace the ones a route handler sets. The `source` above leaves API routes to `withOwl`, which sends the strict JSON API policy. The default CSP is the one the Next.js security guide gives for apps without nonces. It allows inline scripts, which Next.js needs for its bootstrap code, and `'unsafe-eval'` in development only. For a nonce-based policy, pass your own `"Content-Security-Policy"`.

## Server Components and Server Actions

```js
// lib/auth.js
import { cookieToken } from "@owasp-webshield/next";
import { createServerAuth } from "@owasp-webshield/next/server";

export const { getSession, requireSession, requirePermission } = createServerAuth({
  verifyToken: (token) => sessionStore.lookup(token),
  getToken: cookieToken("session"),
  checker: owl
});
```

```js
// app/dashboard/page.js
const session = await getSession(); // null when signed out
if (!session) redirect("/login");

// app/reports/actions.js
"use server";
export async function deleteReport(id) {
  await requirePermission("delete", `report:${id}`); // throws AUTH_REQUIRED / ACCESS_DENIED
  // ...
}
```

Server Actions are reachable by direct POST requests, so check the session and permission inside each one. Validate their input with `assertValidInput()`, which `@owasp-webshield/next` re-exports.

## Client components

```js
// app/layout.js (a Server Component)
import { OwlProvider } from "@owasp-webshield/next/client";
```

`@owasp-webshield/next/client` re-exports every component and hook of `@owasp-webshield/react` from a `"use client"` module. The `A01AccessControl`…`A10SSRFDefense` namespaces aren't included, because Next.js doesn't allow `export *` in a client module. Import those from `@owasp-webshield/react` inside your own client components.

## Runtimes

The route-handler, middleware and header helpers use only the Fetch API. CSRF tokens use Web Crypto, so `guardCsrf` also runs on the Edge runtime. The SSRF DNS check (`outboundUrl`) needs Node.js, which is the default runtime for route handlers. The Pages Router (`pages/api`) passes Node's `req`/`res`; use [`@owasp-webshield/node`](https://www.npmjs.com/package/@owasp-webshield/node) there.

## Documentation

- [Next.js integration guide](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/nextjs-integration.md)
- [React adapter usage](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/react-adapter-usage.md)
- [API reference](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/api-reference.md)
- [Runnable example (owl-enabled-nextjs-expense-portal)](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/owl-enabled-nextjs-expense-portal)

## License

Apache-2.0. See the [main repository](https://github.com/OWASP/www-project-webshield-library) for the full license text and contribution guidelines.
