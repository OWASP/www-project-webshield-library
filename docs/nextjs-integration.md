# Next.js Integration (App Router)

## Goal

Apply OWL controls across a Next.js App Router app: route handlers, middleware, pages, Server
Actions and client components, using one session model and one CSRF scheme throughout.

## Why a dedicated Next.js adapter

Before 2.0.0, a Next.js app could already use OWL in two ways: the React adapter for its
components, and `@owasp-webshield/node` for its server code, since those functions accept a
Fetch `Request`. Building the [example app](../examples/owl-enabled-nextjs-expense-portal/README.md)
that way, and testing it against a real Next.js 16 server, showed where that stops working. Each
problem below is either a security hole or a broken page, and each one is easy to miss in review.

| Problem without the adapter | Effect | What the adapter does |
|---|---|---|
| The React adapter has no `"use client"` directive | Importing `OwlProvider`, `AuthGate` or a hook into an App Router layout or page fails to build | `@owasp-webshield/next/client` re-exports every component and hook from a `"use client"` module. It uses named exports, because Next.js rejects `export *` in a client module |
| Route handlers get a Fetch `Request` and return a `Response`; Express-style middleware doesn't apply | Each route repeats the same glue: authenticate, check CSRF and the permission, validate, `try`/`catch`, map `SecurityError` to a status code, add headers, log. A route that leaves one step out has a hole | `withOwl(handler, options)` runs every check in a fixed order and turns any failure into a safe JSON response, logged through `SecurityLogger`. A 500 never includes the error's message |
| Next.js implements `redirect()`, `notFound()` and its dynamic-rendering bailouts by throwing errors | A plain `try`/`catch` around the handler turns a redirect into a 500 | `withOwl` passes these errors through, using the same checks as Next.js's `unstable_rethrow()` |
| Route handlers don't limit or check the request body; `request.json()` reads whatever arrives | Memory exhaustion from large uploads; form posts parsed as JSON | `body` reads the stream with a byte limit (100 KB by default, 413 when exceeded), requires a JSON content type (415 otherwise), validates against a schema, rejects unknown fields (mass assignment) and can sanitize fields |
| `params` became a Promise in Next.js 15 | `params.id` is `undefined` on the Promise (Next.js 16 passes a plain one), so a permission check like `` `report:${params.id}` `` silently checks `report:undefined` | `withOwl` awaits `params` before any check runs and passes the result to the permission's resource function and to the handler |
| OWL's default headers are made for a JSON API (`default-src 'none'`) | Used on pages, the CSP blocks Next.js's own inline bootstrap scripts, and the page doesn't load | `securityHeadersConfig()` gives `next.config.js` a page CSP (the one the Next.js security guide recommends without nonces, with `'unsafe-eval'` in development only), while `withOwl` keeps the strict policy on API routes |
| Headers from `next.config.js` **replace** headers with the same name set by a route handler (verified on Next.js 16) | A site-wide header rule quietly overrides the API's stricter CSP and any header a route sets itself | The documented `source: "/((?!api/).*)"` leaves API routes to `withOwl` (see [section 4](#4-security-headers-for-pages)) |
| `NextResponse` keeps its own cookie list and rewrites `Set-Cookie` from it on every `cookies.set()` | A CSRF cookie appended as a header is silently dropped once the route sets any other cookie (verified on Next.js 16) | `issueCsrfToken()` and `ensureCsrfCookie()` go through `response.cookies` when it exists, with the same secure defaults as `serializeCookie()` |
| Server Components and Server Actions have no request object | No natural place to call `authenticate(req)`; apps end up trusting what the page already rendered | `createServerAuth()` in `@owasp-webshield/next/server` reads the current request through `headers()`, with `getSession()`, `requireSession()` and `requirePermission()` |
| Server Actions are public POST endpoints | Checking the session only in the page that shows the form leaves the action open to direct calls | The guide and example check the session and permission inside each action. The example's tests replay one user's action form as another user to prove it |
| Browsers authenticate page loads and actions with cookies, not bearer tokens | `authenticate()` reads only `Authorization: Bearer` by default | `cookieToken(name)` reads the session from a cookie, and treats a cookie sent twice (cookie tossing) as no session |
| CSRF in middleware has to work on the Edge runtime and must not break Server Actions | Server Actions send no CSRF header, and a global check rejects them | `guardCsrf()` uses only the Fetch API and Web Crypto (verified in Edge middleware), and is meant for `/api` routes. Next.js protects Server Actions itself by checking `Origin` |

The adapter doesn't import Next.js in its main entry, so route handlers and middleware stay
testable with plain `Request` objects. It adds no security logic of its own: every check is
`@owasp-webshield/node` or core underneath, so a Next.js route enforces the same rules as an
Express route.

### Found while building the example app

These are app-level issues rather than adapter features. They're handled in the example and
documented there:

- **Client IP for rate limiting:** Next.js only sets `X-Forwarded-For` when the request doesn't
  already have one, so a client talking to `next start` directly can choose its "IP". Per-IP
  limits are only trustworthy behind a proxy that appends the real address. The example takes
  the entry added by a configurable number of trusted proxies, and its per-account lockout
  doesn't depend on the IP.
- **Startup hardening check:** if `assertHardened()` throws inside `instrumentation.js`, Next.js
  stays up and answers every request with a 500. The example exits the process instead, so a
  deploy fails visibly. Put Node-only code in a separate file imported under
  `NEXT_RUNTIME === "nodejs"`, or the Edge build warns.
- **`__Host-` cookies** have to be cleared with the attributes they were set with.
  `cookies().delete()` sends no `Secure` attribute, and browsers ignore any `__Host-` cookie
  without it, so the old cookie stays. The example sets it to an empty value with `maxAge: 0`
  instead.

## Packages

| Import | Use it in |
|---|---|
| `@owasp-webshield/next` | Route handlers (`withOwl`), `middleware.js` / `proxy.js` (`guardCsrf`, `ensureCsrfCookie`) and `next.config.js` (`securityHeadersConfig`). Fetch API only; it doesn't import Next.js. |
| `@owasp-webshield/next/server` | Server Components and Server Actions: `createServerAuth()` reads the current request through `headers()` from `next/headers`. |
| `@owasp-webshield/next/client` | Client components: the React adapter (`OwlProvider`, `AuthGate`, `PermissionGate`, `SanitizedText`, the hooks) from a `"use client"` module. |
| `@owasp-webshield/core` | The managers the adapter wraps (`createOwlClient`, `SecurityLogger`, `SSRFGuard`, ...). |

> **Available from 2.0.0.** `@owasp-webshield/next` is first published in OWL 2.0.0. Install
> matching versions of all OWL packages. Next.js 14 and later are supported; the adapter is tested
> against Next.js 16.

```bash
npm install @owasp-webshield/core @owasp-webshield/next
```

## 1. Shared configuration

Define the policy and the session lookup once, and import them everywhere else.

```js
// lib/owl.js
import { createOwlClient, SecurityLogger } from "@owasp-webshield/core";
import { cookieToken } from "@owasp-webshield/next";
import { createServerAuth } from "@owasp-webshield/next/server";

export const owl = createOwlClient({
  roles: {
    viewer: { permissions: ["read:reports"] },
    editor: { permissions: ["read:reports", "write:reports"] }
  },
  acl: [{ resource: "report:archived", action: "write", effect: "deny" }]
});

export const logger = new SecurityLogger();

// Called on every request: look the token up in your session store (or verify a JWT)
// and return { userId, roles }, or null.
export const auth = {
  verifyToken: (token) => sessionStore.lookup(token),
  getToken: cookieToken("session")
};

export const { getSession, requireSession, requirePermission } = createServerAuth({ ...auth, checker: owl });
```

`cookieToken("session")` reads the token from the `session` cookie, which is how a browser
authenticates page loads and Server Actions. Drop `getToken` to use `Authorization: Bearer`
instead, for example for an API used by other services. A cookie that arrives twice (cookie
tossing from a sibling subdomain) counts as no token.

Set the session cookie yourself at sign-in, with `serializeCookie()` from
`@owasp-webshield/node` or `response.cookies.set()`: `HttpOnly`, `Secure`, `SameSite=Lax` or
`Strict`, and ideally a `__Host-` name.

## 2. Route handlers

```js
// app/api/reports/[id]/route.js
import { withOwl } from "@owasp-webshield/next";
import { auth, logger, owl } from "@/lib/owl";

export const GET = withOwl(
  async (request, context, { session, params }) => Response.json(await reports.get(params.id)),
  {
    auth,
    permission: { action: "read", resource: ({ params }) => `report:${params.id}`, checker: owl },
    logger
  }
);

export const PATCH = withOwl(
  async (request, context, { params, body }) => Response.json(await reports.update(params.id, body)),
  {
    auth,
    csrf: true,
    permission: { action: "write", resource: ({ params }) => `report:${params.id}`, checker: owl },
    body: {
      schema: { title: { required: true, type: "string", maxLength: 120 }, summary: { type: "string", maxLength: 2000 } },
      allowUnknownFields: false,
      sanitize: ["summary"]
    },
    logger
  }
);
```

`withOwl(handler, options)` runs its checks in a fixed order: `auth`, `csrf`, `permission`,
`query`, `body`, `outboundUrl`. The first failure becomes a JSON error response:

| Failure | Status | Body |
|---|---|---|
| No or unknown token | 401 (`WWW-Authenticate: Bearer`) | `{ "error": "AUTH_REQUIRED", "message": ... }` |
| CSRF token missing or wrong | 403 | `{ "error": "CSRF_INVALID", ... }` |
| No role grants the permission, or an ACL deny | 403 | `{ "error": "ACCESS_DENIED", ... }` |
| Invalid query or body, unknown field | 400 | `{ "error": "INVALID_INPUT", "errors": [{ field, code, message }] }` |
| Malformed JSON / not JSON / over `limit` | 400 / 415 / 413 | `{ "error": "bad_request", "message": ... }` |
| Outbound URL to a private address | 403 | `{ "error": "SSRF_BLOCKED", ... }` |
| Anything else | 500 | `{ "error": "internal_error" }`, never the error's message |

The handler receives `(request, context, owl)`. `owl.params` is already awaited (it is a Promise
since Next.js 15), and `owl.session`, `owl.query`, `owl.body` and `owl.outboundUrl` hold what the
checks produced. Errors the handler throws, including a `SecurityError` from your own checks, are
mapped the same way. `redirect()`, `notFound()` and Next.js's other control-flow errors pass
through untouched. Pass `logger` to log every failure as a `security.<code>` event, without the
query string.

`withOwl` adds `DEFAULT_SECURITY_HEADERS` to every response, including error responses. These
headers, including a `default-src 'none'` CSP, are made for a JSON API. Headers the handler sets
itself take precedence. `securityHeaders: { ... }` overrides individual headers and `false` turns
them off.

### Outbound requests (SSRF)

```js
export const POST = withOwl(
  async (request, context, { outboundUrl }) => Response.json(await testWebhook(outboundUrl)),
  {
    auth,
    csrf: true,
    body: { schema: { webhookUrl: { required: true, type: "string", maxLength: 2048 } } },
    outboundUrl: { getUrl: ({ body }) => body.webhookUrl }
  }
);
```

The check resolves the host and rejects private, loopback and metadata addresses. Make the
request itself with `SafeFetcher` so that redirects and DNS rebinding are checked too. The DNS
lookup needs the Node.js runtime, the default for route handlers. Don't set
`export const runtime = "edge"` on such a route.

## 3. CSRF

OWL uses the double-submit cookie pattern by default. The server sets an `XSRF-TOKEN` cookie, and
the browser sends its value back in the `X-CSRF-Token` header. `useSecureHttpClient()` from the
React adapter does the browser side automatically.

Issue the cookie before the first state-changing request, either from a route:

```js
// app/api/csrf/route.js
import { NextResponse } from "next/server";
import { issueCsrfToken } from "@owasp-webshield/next";

export function GET() {
  const response = NextResponse.json({ ok: true });
  issueCsrfToken(response);
  return response;
}
```

or from middleware on page loads, with `ensureCsrfCookie(request, response)`. That function
reuses the browser's cookie and only issues one when there is none. `issueCsrfToken()` sets the
cookie through `NextResponse.cookies` when it can, so cookies you set afterwards don't overwrite
it.

Check it per route with `withOwl({ csrf: true })`, or for every API route at once in middleware:

```js
// middleware.js (proxy.js in Next.js 16)
import { NextResponse } from "next/server";
import { ensureCsrfCookie, guardCsrf } from "@owasp-webshield/next";

export async function middleware(request) {
  if (request.nextUrl.pathname.startsWith("/api/")) {
    return (await guardCsrf(request)) ?? NextResponse.next();
  }
  const response = NextResponse.next();
  ensureCsrfCookie(request, response);
  return response;
}

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
```

Run `guardCsrf` only on API routes. Server Actions are POST requests to page URLs and don't send
the CSRF header; Next.js protects them by comparing `Origin` with the host. If you prefer the
synchronizer-token pattern, keep the token in your server-side session and pass
`csrf: { getExpectedToken: (request) => ... }`.

Middleware is a good first gate, but not the only one. Repeat authentication and permission
checks in the route handler, Server Component or Server Action that touches the data.

## 4. Security headers for pages

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

`securityHeadersConfig(overrides, { source, dev })` returns the `headers()` entries with a CSP
that a Next.js page can run under:

```text
default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
img-src 'self' blob: data:; font-src 'self'; object-src 'none'; base-uri 'self';
form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests
```

This is the policy the Next.js security guide gives for apps that don't use nonces. Next.js
inlines its bootstrap scripts, so `script-src` needs `'unsafe-inline'`. `'unsafe-eval'` is added
only when `dev` is true, which defaults to `NODE_ENV === "development"`. For a stricter,
nonce-based CSP, generate the nonce in middleware and pass your own policy in `overrides`. Add the
origins your pages load from (analytics, image CDNs, `connect-src` for APIs).

Headers from `next.config.js` **replace** headers with the same name that a route handler sets.
The `source` above excludes `/api/`, so API routes keep `withOwl`'s JSON API policy. Change it if
your route handlers live elsewhere.

## 5. Server Components and Server Actions

```js
// app/reports/page.js
import { redirect } from "next/navigation";
import { getSession } from "@/lib/owl";

export default async function ReportsPage() {
  const session = await getSession(); // null when signed out or the token is unknown
  if (!session) redirect("/login");
  return <ReportList userId={session.userId} />;
}
```

```js
// app/reports/actions.js
"use server";
import { assertValidInput } from "@owasp-webshield/next";
import { requirePermission } from "@/lib/owl";

export async function renameReport(id, formData) {
  await requirePermission("write", `report:${id}`); // throws AUTH_REQUIRED or ACCESS_DENIED
  const input = assertValidInput(Object.fromEntries(formData), { title: { required: true, type: "string", maxLength: 120 } }, { allowUnknownFields: false });
  await reports.rename(id, input.title);
}
```

A Server Action is a public POST endpoint: anyone can call it with any arguments, whether or
not the page that renders it is protected. Check the session, the permission and the input inside
every action. `getSession()` returns `null` only for a missing or rejected token. An error from
your session store still throws, so an outage isn't treated as "signed out".

`verifyToken` runs on every call. If a page calls `getSession()` from several components, wrap
your lookup in React's `cache()` so that it runs once per request.

## 6. Client components

```js
// app/providers.js
"use client";
import { OwlProvider } from "@owasp-webshield/next/client";
import { createOwlClient } from "@owasp-webshield/core";

const owl = createOwlClient({ roles: { viewer: { permissions: ["read:reports"] } } });

export function Providers({ children }) {
  return <OwlProvider client={owl}>{children}</OwlProvider>;
}
```

```js
// app/layout.js
import { Providers } from "./providers";

export default function RootLayout({ children }) {
  return <html lang="en"><body><Providers>{children}</Providers></body></html>;
}
```

Server Components can import `AuthGate`, `PermissionGate` and `SanitizedText` from
`@owasp-webshield/next/client` and render them directly. See
[react-adapter-usage.md](./react-adapter-usage.md) for the hooks. The `A01AccessControl` …
`A10SSRFDefense` namespace exports aren't in the client entry, because Next.js rejects `export *`
in a `"use client"` module. Import them from `@owasp-webshield/react` in your own client
components.

Client-side gates only improve the UI. The server checks from sections 2 and 5 are what
protect the data.

## 7. Startup check

```js
// instrumentation.js
import { assertHardened } from "@owasp-webshield/next";

export function register() {
  assertHardened({ debug: process.env.NODE_ENV !== "production" }); // pass your real cors/cookie settings too
}
```

`assertHardened()` throws on a high-severity misconfiguration, such as a debug flag or a wildcard
CORS origin in production, so the server fails at startup instead of running with it.

## Runnable example

[OWL Enabled Next.js Expense Portal](../examples/owl-enabled-nextjs-expense-portal/README.md)
uses everything on this page in one app (route handlers, the proxy, Server Actions, Server
Components and client components), with HTTP tests for each control.

## Pages Router and runtimes

- **Pages Router** (`pages/api/*`): the handler gets Node's `req`/`res`, which `withOwl` doesn't
  wrap. Call the functions from `@owasp-webshield/node` (`authenticate`, `verifyCsrf`,
  `assertPermission`, `assertValidInput`, `toErrorResponse`). They accept Node's
  `IncomingMessage`.
- **Edge runtime:** `guardCsrf`, `ensureCsrfCookie`, `issueCsrfToken` and the header helpers
  use only the Fetch API and Web Crypto, and work in Edge middleware. `outboundUrl` and
  `CryptoManager` need Node.js.
