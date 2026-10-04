# OWL Enabled Vue + Express Incident Desk

A small team incident tracker, built as a reference for OWL across the whole stack: a
Vue 3 front end on [`@owasp-webshield/vue`](../../src/adapters/vue/README.md) and an
Express 5 API on [`@owasp-webshield/express`](../../src/adapters/express/README.md). Every
OWASP Top 10 category (A01–A10) does real work, and the security-relevant behavior is
covered by tests.

Reporters file incidents, responders work them and keep encrypted private notes, and
admins can lock an incident, read the audit log and run the security checks.

## Run locally

From this folder:

```bash
npm install
npm run dev      # API on :8788 + Vite on http://localhost:5173 (proxies /api to the API)
npm test         # API tests (Node's built-in test runner)

npm run build    # production build of the Vue app into dist/
npm start        # Express serves the API and dist/ on http://localhost:8080
```

Demo accounts (also listed on the sign-in page):

| User | Password | Role |
|---|---|---|
| `alice` | `owl-demo-reporter` | reporter: read and report incidents |
| `riley` | `owl-demo-responder` | responder: also move incidents through their lifecycle and keep private notes |
| `ada` | `owl-demo-admin` | admin: also lock and delete incidents, audit log, security report, webhook test |

> ⚠️ **Demo only.** The accounts and passwords are hard-coded in `server/users.js` so this
> README can list them, and all data is in memory. Load users from your own store and keep
> secrets out of source code.

## What each category does here

| Category | Front end (Vue) | API (Express) |
|---|---|---|
| A01 Broken Access Control | `PermissionGate`/`usePermission` hide what a role can't do; `installOwlRouterGuard` guards routes and leaves a page when the session ends | `requirePermission()` on every route, using the same roles (`shared/policy.js`). An admin **lock** is a per-incident ACL deny that overrides every role's RBAC grant, admins included |
| A02 Cryptographic Failures | | Private notes are encrypted at rest with AES-256-GCM (`CryptoManager`); passwords are PBKDF2 hashes |
| A03 Injection | Descriptions render through `v-safe-html:moderate`, never `v-html`; text is interpolated, so it's always escaped | `validate()` with `allowUnknownFields: false` on every body (stops mass assignment such as `reporterId`); `sanitizeBody()` stores descriptions as sanitized HTML |
| A04 Insecure Design | Only valid next statuses are offered | `ThreatModelGuard`: the incident lifecycle (closed is final) and an abuse rule capping open incidents per reporter; per-IP rate limits (`express-rate-limit`) on every request; `DesignChecklist` on the admin page |
| A05 Security Misconfiguration | | `assertHardened()` refuses to start with debug on or a wildcard CORS origin; `securityHeaders()` sends a strict CSP, HSTS, `nosniff` and `X-Frame-Options`; 32 KB body limit |
| A06 Vulnerable Components | Admin page: "Run scan" | `DependencyRiskScanner` over a real `npm audit` of this app; high or critical findings fail the policy |
| A07 Identification & Authentication | Token kept in memory only (a reload signs you out; nothing in `localStorage`); the UI follows session expiry | PBKDF2 password check with one generic error for unknown users and wrong passwords, a lockout after 5 failures per account, a limit of 10 failed sign-ins per IP per minute, and random server-side session tokens that expire (`requireAuth({ verifyToken })`) |
| A08 Software & Data Integrity | `useSecureHttpClient` sends the `XSRF-TOKEN` cookie as `X-CSRF-Token` and won't attach credentials to another origin | `csrfProtection({ getExpectedToken })`: each session's own token (synchronizer pattern), delivered in the `XSRF-TOKEN` cookie at sign-in |
| A09 Logging & Monitoring | Admin page shows the audit log | `SecurityLogger` records sign-ins, changes and every denied request; note text is logged under a redacted key and shows as `[REDACTED]` |
| A10 SSRF | | Admin "webhook test": `guardOutboundUrl()` refuses private, loopback, link-local (cloud metadata) and non-HTTP targets; `SafeFetcher` with a pinned-DNS `undici` dispatcher re-checks every redirect |

Hiding a button in the UI is a convenience; the API enforces every rule on its own. The
tests call the API directly to prove it, for example a reporter changing a status gets 403.

## Try the security controls

- **Rich text:** report an incident with `<img src=x onerror=alert(1)>` or
  `<a href="javascript:alert(1)">x</a>` in the description. The preview and the saved
  incident keep the formatting and drop the script.
- **Access control:** sign in as `alice` and open `/admin`: you land on "Not allowed".
- **Lock:** as `ada`, lock an incident. `riley` can still read it but can't change its
  status or add notes, and neither can `ada` until it's unlocked.
- **Audit log:** add a private note as `riley`, then open the audit log as `ada`: the
  event is there, the note text is `[REDACTED]`.
- **SSRF:** in the admin webhook test, try `http://169.254.169.254/latest/meta-data` or
  `http://127.0.0.1:22/`: both are refused with `SSRF_BLOCKED`.
- **Session expiry:** run the API with `SESSION_TTL_MS=30000 npm run dev`, sign in and
  wait: the page moves to the sign-in screen when the session ends.

## Layout

```text
shared/policy.js      roles, lifecycle and validation schemas, used by both sides
server/app.js         Express app: OWL middleware and routes
server/users.js       password hashing, generic errors, lockout
server/sessions.js    server-side session store
server/incidents.js   incident store: lifecycle, abuse rule, encrypted notes
src/                  Vue app: plugin setup (owl.js), API client (api.js), router, views
test/api.test.js      API tests for every category
```

## Notes

- **Production checklist:** keep sessions and incidents in a database or Redis, load the
  notes key from a KMS or secret store (it's random per process here), and serve over
  HTTPS. Consider a `__Host-` CSRF cookie name (pass it to both `issueCsrfToken` and
  `useSecureHttpClient({ csrfCookieName })`).
- **Rate limits:** every request is limited to 300 per minute per IP, and failed sign-ins to
  10 per minute per IP (successful ones don't count). Over the limit, the API answers 429
  and logs `security.rate_limited`. The counters are in memory; with several instances, use
  a shared store (`express-rate-limit` supports Redis), and behind a reverse proxy set
  `app.set("trust proxy", ...)` so limits apply to the real client address.
- **Lockout trade-off:** the per-account lockout slows guessing against one account, but
  anyone who knows a username can lock it for a minute. The per-IP sign-in limit stops one
  client from spraying many accounts.
- **CPU cost:** PBKDF2 at 600,000 iterations runs synchronously, so each sign-in blocks the
  event loop briefly; the sign-in rate limit bounds how often one client can trigger it.
- **CSRF and bearer tokens:** a bearer token in memory isn't sent automatically by the
  browser, so CSRF protection here is defense in depth. It's essential when sessions are
  carried in cookies.
- **Bundler warning:** `vite build` warns that `node:dns/promises` was externalized. Core only
  imports it under Node, for SSRF DNS checks, so the warning is harmless.
