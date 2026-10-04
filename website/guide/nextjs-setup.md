# Next.js Setup

`@owasp-webshield/next` brings OWL to the Next.js App Router (Next.js 14 and later):

| Import | Use it in |
|---|---|
| `@owasp-webshield/next` | Route handlers (`withOwl`), middleware (`guardCsrf`, `ensureCsrfCookie`) and `next.config.js` (`securityHeadersConfig`) |
| `@owasp-webshield/next/server` | Server Components and Server Actions (`createServerAuth`) |
| `@owasp-webshield/next/client` | Client components: the [React adapter](./react-setup) as a `"use client"` module |

```bash
npm install @owasp-webshield/core @owasp-webshield/next
```

## Why a separate adapter

The React and Node packages alone leave gaps in an App Router app:

- The React adapter can't be imported into Server Components (no `"use client"`).
- Every route handler has to repeat the same checks, error mapping and headers.
- A plain `try`/`catch` turns `redirect()` into a 500.
- Route handlers have no body limit.
- `params` is a Promise, so `params.id` is `undefined` in a permission check.
- OWL's JSON API CSP breaks pages, and `next.config.js` headers replace route-handler headers.
- `NextResponse` drops a cookie header appended before `cookies.set()`.
- Server Actions have no request object, yet are public endpoints.

This package closes each of these. The [integration guide](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/nextjs-integration.md#why-a-dedicated-nextjs-adapter) has the full list.

## Route handlers

```js
// app/api/reports/[id]/route.js
import { withOwl } from "@owasp-webshield/next";

export const PATCH = withOwl(
  async (request, context, { params, body }) => Response.json(await reports.update(params.id, body)),
  {
    auth: { verifyToken: (token) => sessionStore.lookup(token) },
    csrf: true,
    permission: { action: "write", resource: ({ params }) => `report:${params.id}`, checker: owl },
    body: { schema: { title: { required: true, type: "string", maxLength: 120 } }, allowUnknownFields: false }
  }
);
```

The checks run in the order `auth`, `csrf`, `permission`, `query`, `body`, `outboundUrl`. The first failure becomes a JSON response (`400`/`401`/`403`/`413`/`415`), and a `500` never includes the error's message. `redirect()` and `notFound()` pass through. Every response gets the security headers it doesn't set itself.

## Middleware and CSRF

```js
// middleware.js (proxy.js in Next.js 16)
import { NextResponse } from "next/server";
import { ensureCsrfCookie, guardCsrf } from "@owasp-webshield/next";

export async function middleware(request) {
  if (request.nextUrl.pathname.startsWith("/api/")) return (await guardCsrf(request)) ?? NextResponse.next();
  const response = NextResponse.next();
  ensureCsrfCookie(request, response); // XSRF-TOKEN, read by useSecureHttpClient()
  return response;
}
```

Run `guardCsrf` only on API routes. Server Actions don't send the CSRF header; Next.js checks their `Origin` itself.

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

The default CSP is the one the Next.js security guide gives for apps without nonces. Headers from `next.config.js` replace the ones route handlers set, so the `source` leaves `/api/` to `withOwl`.

## Server Components and Server Actions

```js
// lib/auth.js
import { cookieToken } from "@owasp-webshield/next";
import { createServerAuth } from "@owasp-webshield/next/server";

export const { getSession, requirePermission } = createServerAuth({
  verifyToken: (token) => sessionStore.lookup(token),
  getToken: cookieToken("session"),
  checker: owl
});
```

`await getSession()` returns the session or `null` in a page. `await requirePermission("delete", "report:7")` throws `AUTH_REQUIRED` or `ACCESS_DENIED` in a Server Action. Check inside every action, because each one is a public POST endpoint.

[OWL Enabled Next.js Expense Portal](https://github.com/OWASP/www-project-webshield-library/tree/main/examples/owl-enabled-nextjs-expense-portal) is a runnable app built this way, with HTTP tests for every control.

The complete guide is in the repository: [Next.js integration](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/nextjs-integration.md).
