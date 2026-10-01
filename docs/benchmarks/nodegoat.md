# OWL vs OWASP NodeGoat — Traceability Matrix

This matrix traces every weakness that [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) documents to the OWL API that addresses it, or records that OWL has no control for it yet.

| | |
|---|---|
| **Target** | OWASP NodeGoat, commit [`c5cb68a`](https://github.com/OWASP/NodeGoat/commit/c5cb68a7084e4ae7dcc60e6a98768720a81841e8) |
| **OWL version** | `@owasp-webshield/core` 1.0.0 (`src/core`, branch `bug/ssrf_protection`) |
| **Method** | Static review: NodeGoat source read against OWL source. **Not yet runtime-verified.** |
| **Last reviewed** | 2026-09-30 |
| **Companion** | [OWL vs Juice Shop](./juice-shop.md), which extends this roadmap with R10–R16 |

## Summary

| Status | Count | Meaning |
|---|---|---|
| ✅ **Covered** | 10 | An OWL API implements the control. The app only has to call it. |
| 🟡 **Partial** | 5 | OWL provides a building block or detection. The app (or another library) supplies the rest. |
| ❌ **Gap** | 5 | OWL has no API for this today. |
| ⚪ **Out of scope** | 2 | Deployment or app-logic concern that a library can't reasonably own. |
| | **22** | NodeGoat weaknesses reviewed |

> **Headline (static):** OWL has a direct control for 10 of 22 NodeGoat weaknesses and a partial control for 5 more.

Two caveats apply to every row:

- **No Express adapter.** OWL ships framework-agnostic primitives. Every "Covered" row still needs a few lines of glue (middleware, error-to-403 mapping) in NodeGoat. An Express adapter would reduce this to one line per control (see [R1](#roadmap)).
- **Runtime prerequisite.** NodeGoat targets Node 12, and OWL requires Node ≥ 20 (`globalThis.crypto`, native `fetch`). Whether NodeGoat's pinned dependencies run on Node 20 has not been checked yet.

## Matrix

OWASP IDs are this project's categorization, based on each list's category descriptions. The CWE is the closest weakness. NodeGoat locations are relative to the NodeGoat repository root.

| # | NodeGoat weakness | NodeGoat location | Top 10 2021 / 2025 | CWE | OWL control | Status |
|---|---|---|---|---|---|---|
| 1 | Server-side JS injection (`eval` of form input) | `app/routes/contributions.js` → `handleContributionsUpdate` | A03 / A05 | CWE-95 | `InputValidator.validateSchema` (numeric `pattern`) | ✅ Covered |
| 2 | NoSQL injection (`$where` built from `threshold`) | `app/data/allocations-dao.js` → `getByUserIdAndThreshold` | A03 / A05 | CWE-943 | `InputValidator.validateSchema` | ✅ Covered |
| 3 | Log injection / log forging | `app/routes/session.js` → `handleLoginRequest` | A09 / A09 | CWE-117 | `SecurityLogger` (JSON sink) | ✅ Covered |
| 4 | Stored XSS in memos (Markdown output, autoescape off) | `app/views/memos.html`, `server.js` swig config | A03 / A05 | CWE-79 | `InputSanitizer("moderate").sanitizeHTML` | ✅ Covered |
| 5 | XSS in profile fields (HTML-attribute and `href` contexts) | `app/routes/profile.js`, `app/views/profile.html` | A03 / A05 | CWE-79 | `InputSanitizer("strict")`, `InputValidator.validateUrl` | 🟡 Partial |
| 6 | Session ID not regenerated on login (fixation) | `app/routes/session.js` → `handleLoginRequest` | A07 / A07 | CWE-384 | — | ❌ Gap |
| 7 | Session cookie lacks `HttpOnly` / `Secure` / `SameSite` | `server.js` → `session({...})` | A05 / A02 | CWE-1004, CWE-614 | `SecurityConfigManager`, `HardeningReporter` | 🟡 Partial |
| 8 | Missing security headers, `X-Powered-By` exposed | `server.js` (helmet commented out) | A05 / A02 | CWE-693, CWE-1021 | — | ❌ Gap |
| 9 | Passwords stored and compared in plaintext | `app/data/user-dao.js` → `addUser`, `validateLogin` | A02 / A04 | CWE-256 | `PBKDF2Adapter`, `generateSalt` | 🟡 Partial |
| 10 | Weak password policy (`/^.{1,20}$/`) | `app/routes/session.js` → `validateSignup` | A07 / A07 | CWE-521 | `SecretPolicy.isEntropySufficient` | ✅ Covered |
| 11 | User enumeration (different errors for bad user vs bad password) | `app/routes/session.js` → `handleLoginRequest` | A07 / A07 | CWE-204 | — | ⚪ Out of scope |
| 12 | No brute-force protection (lockout / rate limit) | `app/routes/session.js` → `handleLoginRequest` | A07 / A07 | CWE-307 | — | ❌ Gap |
| 13 | Insecure direct object reference (`/allocations/:userId`) | `app/routes/allocations.js` → `displayAllocations` | A01 / A01 | CWE-639 | `PermissionChecker` / `ACLManager` | 🟡 Partial |
| 14 | Missing function-level access control (`/benefits`) | `app/routes/index.js` (`isAdmin` not applied) | A01 / A01 | CWE-285 | `RBACManager` | ✅ Covered |
| 15 | SSN / DOB stored in plaintext | `app/data/profile-dao.js` → `updateUser` | A02 / A04 | CWE-312 | `CryptoManager.encrypt` / `decrypt` | ✅ Covered |
| 16 | Cleartext HTTP transport | `server.js` (`http.createServer`) | A02 / A04 | CWE-319 | — | ⚪ Out of scope |
| 17 | CSRF on state-changing forms (`csurf` disabled) | `server.js`, `POST /profile`, `/contributions`, `/benefits`, `/memos` | A01 / A01 | CWE-352 | `CSRFTokenManager` | ✅ Covered |
| 18 | Vulnerable / unmaintained components | `package.json` (`marked@0.3.5`, `bcrypt-nodejs`, `swig`, …) | A06 / A03 | CWE-1104 | `ComponentPolicy`, `DependencyRiskScanner` | 🟡 Partial |
| 19 | Open redirect (`/learn?url=`) | `app/routes/index.js` → `/learn` | A01 / A01 | CWE-601 | — | ❌ Gap |
| 20 | SSRF (user-controlled `url` fetched server-side) | `app/routes/research.js` → `displayResearch` | A10 / A01 | CWE-918 | `SafeFetcher` + `SSRFGuard` | ✅ Covered |
| 21 | ReDoS in bank-routing validation | `app/routes/profile.js` → `handleProfileUpdate` | — (not in Top 10) | CWE-1333 | — | ❌ Gap |
| 22 | Type confusion / HTTP parameter pollution (arrays where strings are expected) | `app/routes/profile.js` (noted in code comment) | A03 / A05 | CWE-1287 | `InputValidator.validateSchema` (`type: "string"`) | ✅ Covered |

## How OWL addresses each covered row

These are integration notes for whoever wires OWL into a NodeGoat fork. They describe the OWL call and the caveats that matter, not full patches.

**#1, #2 — Injection via unvalidated numbers.** Validate the raw form value with `validateSchema({ preTax: { required: true, type: "string", pattern: /^\d{1,2}$/ } })` before it reaches `eval` or the `$where` string. Form fields arrive as strings, so `type: "number"` would reject every request; the check has to be a `pattern`. This neutralizes the sinks but leaves them in place. Removing `eval` and `$where` is still the real fix, and that is application code.

**#3 — Log injection.** Replace `console.log("...: ", userName)` with `logger.warn("login_unknown_user", { userName })`. The default sink `JSON.stringify`s each entry, so CR/LF in user input becomes `\r\n` inside a JSON string and can't start a new log line. A custom `sink` that writes raw strings would lose this. `SecurityLogger` does not neutralize control characters itself.

**#4 — Memo XSS.** Wrap the Markdown output as `sanitizer.sanitizeHTML(marked(memo))` with the `"moderate"` profile. OWL's tokenizer drops `<script>`/`<svg>` content and `on*` attributes, and removes `javascript:` URLs even when they are hidden with entities or control characters. This also covers the known sanitize-bypass classes in `marked@0.3.5` (row 18), without upgrading `marked`.

**#10 — Password policy.** Call `SecretPolicy.isEntropySufficient(password, minimumBits)` in `validateSignup`. The 60-bit default suits machine secrets. For human passwords, choose and document a threshold, and test it against NodeGoat's seed passwords. OWL has no breached-password (k-anonymity) check.

**#14 — Function-level access.** Define roles with `rbac.defineRole("admin", ["read:benefits", "update:benefits"])` and `defineRole("user", [])`. Map `user.isAdmin` to a role in middleware and call `rbac.can(role, "update", "benefits")`. This is exactly what `RBACManager` is for; the only glue is the role lookup and returning 403.

**#15 — Sensitive data at rest.** Call `cryptoManager.encrypt(ssn, key)` and store the `{ ciphertext, iv, tag, alg }` object; call `decrypt` on read. AES-256-GCM authenticates the stored value, which NodeGoat's commented-out AES-CBC fix doesn't. Derive or load the key **once at startup**: `deriveKey` runs 600,000 PBKDF2 iterations synchronously, so calling it per request would block the event loop.

**#17 — CSRF.** Build a manager per request backed by the server session: `new CSRFTokenManager({ storage: { get: () => req.session.csrf, set: (v) => { req.session.csrf = v; } } })`. Call `rotateToken()` when rendering (NodeGoat's templates already emit `<input name="_csrf" value="{{csrftoken}}">`) and `validate(req.body._csrf)` on POST. `validate` throws `SecurityError(CSRF_INVALID)`, which the error handler must map to 403. The class is documented browser-first; this server-side synchronizer-token use works, but it isn't documented yet.

**#20 — SSRF.** Replace `needle.get(url)` with `new SafeFetcher({ guard, dispatcher })`, using an undici `Agent` whose `connect.lookup` is `guard.createSafeLookup()`. This blocks private, loopback, link-local (cloud metadata) and reserved targets on every redirect hop, including IPv4-mapped, NAT64 and 6to4 IPv6 forms, and closes the DNS-rebinding race. See the limitation noted under [E1](#roadmap).

**#22 — Type confusion.** `validateSchema` with `type: "string"` rejects arrays and objects that `body-parser` produces from repeated or bracketed parameters, so later `.trim()`-style calls can't crash the handler.

## What is left: partial rows and gaps

| # | What OWL provides | What's missing |
|---|---|---|
| 5 | `InputSanitizer` encodes `& < >` in text; `validateUrl` checks for http(s). | **No context-aware output encoding.** `encodeText` doesn't encode `"` or `'`, so sanitized input placed in `value="{{...}}"` can still break out of the attribute. There's no URL-context encoder for the `href` either. The root fix in NodeGoat is turning swig `autoescape` back on, which is not OWL. |
| 6 | `AuthManager` holds a client-side session. | No server-session helper to regenerate the session ID on login or privilege change. |
| 7 | `SecurityConfigManager` holds secure cookie defaults (`httpOnly`, `secure`, `sameSite: "Strict"`), and `HardeningReporter` flags insecure cookie config. | OWL audits configuration but doesn't apply it. The app has to copy `config.cookies` into `express-session`. `HardeningReporter` doesn't inspect a real `express-session` config or check the cookie name. |
| 8 | — | No response-header middleware or header audit (CSP, `X-Frame-Options`/`frame-ancestors`, `nosniff`, HSTS, removing `X-Powered-By`). |
| 9 | `PBKDF2Adapter` (600k iterations, SHA-256) and `generateSalt`. | No `hashPassword` / `verifyPassword` API. Each app has to invent a storage format (salt, iterations, digest) and remember to use `crypto.timingSafeEqual`; OWL's constant-time compare is private to `CSRFTokenManager`. |
| 12 | `ThreatModelGuard.evaluateAbuseCase` can express a rule. | No attempt counter, lockout or rate limiter, and no pluggable store for one. |
| 13 | `PermissionChecker` answers role/resource questions. | **No object-ownership primitive.** The decisive check, `params.userId === session.userId`, is app code. OWL's policy model has no subject/owner attributes (ABAC). |
| 18 | `ComponentPolicy` (allowlist, denylist, `minVersions`) and `DependencyRiskScanner` (pluggable provider, severity gate). | Detection only; remediation (upgrading) is on the app. No built-in provider, so users must adapt `npm audit --json` themselves. |
| 19 | `InputValidator.validateUrl` accepts any http(s) URL. `redirect.js` is internal and handles fetch redirects, not user redirects. | No safe-redirect helper (same-origin or allowlisted hosts; rejects `//host` and backslash tricks). |
| 21 | `validateSchema` supports `maxLength` and `pattern`. | **Bug-level finding:** `validateSchema` still runs `pattern` after `maxLength` has already failed. So moving a backtracking regex into an OWL schema with a length cap does **not** protect it (`src/core/a03-injection-defense/InputValidator.js`). OWL also has no regex-safety check. |

Out of scope: **#11** (choosing identical login error messages is app logic) and **#16** (TLS termination is a deployment concern). OWL's docs could still cover both in guidance.

## Roadmap

Candidate follow-up issues, in rough order of value per effort:

| ID | Proposal | Closes | Size |
|---|---|---|---|
| R1 | **`@owasp-webshield/express` adapter:** middleware for CSRF (synchronizer token over `req.session`), RBAC guards, schema validation, `SecurityError` → HTTP status mapping, security headers, and session regeneration. | 6, 8; simplifies 1–3, 14, 17, 22 | L |
| R2 | `InputValidator`: skip `pattern` when a length rule fails, and document length-before-pattern. | 21 (partly) | S |
| R3 | Context-aware encoders: `encodeForHTMLAttribute`, `encodeForURLComponent`, `encodeForJS`. | 5 | M |
| R4 | `PasswordHasher.hash()` / `verify()` with a self-describing format and constant-time compare. | 9 | S |
| R5 | Safe-redirect helper (`isSafeRedirect(url, { allowOrigins })`). | 19 | S |
| R6 | Attempt limiter with a pluggable store (memory/Redis), for lockout and rate limiting. | 12 | M |
| R7 | Ownership/ABAC check in A01 (e.g., `PermissionChecker.check({ ..., owner, subject })`). | 13 | M |
| R8 | `SecurityConfigManager.toCookieOptions()` plus `HardeningReporter` accepting a real `express-session` config. | 7 | S |
| R9 | Built-in `npm audit` provider for `DependencyRiskScanner`. | 18 | S |
| E1 | `SSRFGuard` `allowHosts` option. Today any public host is reachable; OWASP's SSRF guidance prefers a destination allowlist when targets are known, as they are in NodeGoat's research page. | strengthens 20 | S |

Delivering R1–R5 would move the static count from **10 covered / 5 partial / 5 gaps** to roughly **16 covered / 3 partial / 1 gap**.

## Next step: runtime verification

This review is static. It shows which OWL API applies, not that the wiring works end to end. To upgrade the matrix to measured results:

1. Fork NodeGoat, run it on Node 20, and wire in the ✅ rows as described above.
2. Confirm each row with NodeGoat's own tutorial steps (`/tutorial` in the running app) against the original and the OWL-wired build.
3. Record results in this file, and change **Method** at the top to "Runtime-verified" with the date.
