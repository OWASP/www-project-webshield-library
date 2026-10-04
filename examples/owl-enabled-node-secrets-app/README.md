# OWL Enabled Node Secrets App

A small team credential vault — built directly on `@owasp-webshield/core`, no framework —
showing every OWASP Top 10 category (A01–A10) doing real work. This example replaces
`core-node-demo`.

Unlike the browser-based `owl-enabled-react-todo-app` example, this one runs in real
Node, so it can use **`CryptoManager`** (real AES-256-GCM encryption at rest), which
needs Node's native `crypto` module and is a throwing stub in browser bundles. It also
runs a **real `npm audit`**, not a fixture. Its HTTP API (`npm run serve`) is built on
[`@owasp-webshield/node`](../../src/adapters/node/README.md) with a server-side session
per login.

## Run locally

From this folder:

```bash
npm install
npm start          # scripted CLI walkthrough — every category, one run, no server
npm run serve       # a small REST API on :8787 — see "Try the API" below
npm test            # HTTP-level tests for the API (Node's built-in test runner)
```

## What `npm start` demonstrates

| Category | Where |
|---|---|
| A01 Broken Access Control | `RBACManager` + `ACLManager` + `PermissionChecker` — RBAC denies a `viewer` reveal outright; a per-secret ACL freeze denies reveal even for `admin` (deny-override, scoped to one secret instead of a whole resource type) |
| A02 Crypto Failures | `CryptoManager` (AES-256-GCM) encrypts every secret at rest with a vault master key; `SecretPolicy` flags weak stored values and overdue rotations |
| A03 Injection | `InputValidator.validateSchema` + `InputSanitizer` on secret name/description |
| A04 Insecure Design | A lifecycle guard (active → rotating → active, active → revoked) plus abuse-case checks on metadata length, self-audited against a `DesignChecklist` |
| A05 Security Misconfiguration | `SecurityConfigManager` + `HardeningReporter`, run once at boot |
| A06 Vulnerable Components | `DependencyRiskScanner` backed by a **real** `NpmAuditProvider` (shells out to `npm audit --json` against the repo root) |
| A07 Auth & Session | `AuthManager` + `TokenManager` |
| A08 Data Integrity | `CSRFTokenManager` + `HTTPClient`; the API issues a CSRF token per session (synchronizer-token pattern) |
| A09 Logging & Monitoring | `SecurityLogger` — a reveal is logged with the plaintext under the key `secretValue`, which auto-redacts to `[REDACTED]` because it matches the default redact-key list; `EventEmitter` builds the full audit trail printed at the end |
| A10 SSRF | `SafeFetcher`/`SSRFGuard` guards the "notify on reveal" webhook call; a literal cloud-metadata IP (`169.254.169.254`) is blocked |

## Try the API (`npm run serve`)

> ⚠️ **Demo only — do not copy the login route.** `POST /login` issues a session for
> whichever role the request body names, with no credentials, so anyone who can reach the
> server can become `admin`. A real service must authenticate the user (password, SSO,
> passkey, ...) and take roles from its own user store, never from the request.
>
> For the same reason the server only accepts connections from this machine (`127.0.0.1`).
> `HOST=0.0.0.0 npm run serve` exposes it to your network; don't, on a network you don't control.

Every `/login` creates its own server-side session (a random bearer token and CSRF
token, valid for 30 minutes), so several users can be signed in at once with different
roles. Every mutating request needs both the bearer token from `/login` and that
session's CSRF token in `X-CSRF-Token`; omitting either, or using another session's
CSRF token, is rejected. `POST /logout` ends the session.

```bash
# Log in — returns { accessToken, csrfToken }
curl -s -X POST localhost:8787/login -H 'Content-Type: application/json' -d '{"role":"contributor"}'

TOKEN=<accessToken from above>
CSRF=<csrfToken from above>

# Rejected — no CSRF header (403 CSRF_INVALID)
curl -s -X POST localhost:8787/secrets \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"STRIPE_KEY","value":"sk_live_...","description":"Stripe secret key"}'

# Accepted
curl -s -X POST localhost:8787/secrets \
  -H "Authorization: Bearer $TOKEN" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"name":"STRIPE_KEY","value":"sk_live_...","description":"Stripe secret key"}'

# Rejected — a role in the body can't override the session's role (403 ACCESS_DENIED)
curl -s -X POST localhost:8787/secrets   -H "Authorization: Bearer $TOKEN" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json'   -d '{"role":"admin","name":"ESCALATED","value":"x9Qz7Lw2Rt8Yp4f"}'

# Log in as admin in a second session (the contributor's session stays valid), reveal it
curl -s -X POST localhost:8787/login -H 'Content-Type: application/json' -d '{"role":"admin"}'
ADMIN_TOKEN=<accessToken from above>
ADMIN_CSRF=<csrfToken from above>
curl -s -X POST localhost:8787/secrets/STRIPE_KEY/reveal -H "Authorization: Bearer $ADMIN_TOKEN" -H "X-CSRF-Token: $ADMIN_CSRF"

# Freeze it (per-secret ACL deny) — reveal now fails even for admin
curl -s -X POST localhost:8787/secrets/STRIPE_KEY/freeze \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "X-CSRF-Token: $ADMIN_CSRF" -H 'Content-Type: application/json' -d '{"frozen":true}'
```

Other routes: `GET /secrets`, `POST /secrets/:name/rotate` (`{"newValue": "..."}`), `DELETE /secrets/:name`, `POST /logout`. Secret names in the path are URL-decoded (`/secrets/DB%20PASS/reveal`). Request bodies over 64 KB are rejected with 413.

## Notes

- `server.js` handles the HTTP boundary with [`@owasp-webshield/node`](../../src/adapters/node/README.md): `authenticate()` looks the bearer token up in the server's session store, `verifyCsrf()` checks the `X-CSRF-Token` header against that session's token, `securityHeaders()` on every response, `toErrorResponse()` to map `SecurityError`s to 400/401/403 (500s never expose their message), `logRequestError()` into the audit trail, and `assertHardened()` at boot. An Express app would use the same checks as middleware from `@owasp-webshield/express`; see [Node & Express integration](../../docs/node-api-integration.md).
- The RBAC/ACL roles and the token/session managers are built with `createOwlClient()` (one config object) instead of constructing `RBACManager`/`ACLManager`/`TokenManager`/`AuthManager` separately — see `vault.js`. `EventEmitter`/`SecurityLogger` are still constructed directly since this vault wires the logger's sink into its own audit-trail event channel, which is more specific than `createOwlClient`'s config covers.
- Vault state (secrets, roles, audit log) is in-memory only — restarting either entry point resets everything.
- `SSRFGuard.assertResolvedSafe()` does a real DNS lookup for non-literal hostnames in Node (unlike the browser build, which skips DNS entirely). The demo's outbound webhook target, `hooks.example.com`, doesn't have a real DNS record, so `vault.js` injects a fixed `resolveHost` returning a deterministic, non-private address for it — keeping the whole example runnable offline instead of depending on real network access.
- `npm audit --json` is run against the repo root (`../..`), since this example's own `package.json` has no dependencies to meaningfully audit. Point `NpmAuditProvider`'s `cwd` option at any project with a `package-lock.json` to scan it instead.
