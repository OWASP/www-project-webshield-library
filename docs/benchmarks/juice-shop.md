# OWL vs OWASP Juice Shop — Traceability Matrix

This matrix traces all 116 [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) challenges to the weakness behind each one. It then records the OWL API that addresses that weakness, or notes that OWL has no control for it yet.

| | |
|---|---|
| **Target** | OWASP Juice Shop v20.2.0, commit [`1618a61`](https://github.com/juice-shop/juice-shop/commit/1618a611b173b4bf114028e6e02549950606e29d) |
| **OWL version** | `@owasp-webshield/core` 1.0.0 (`src/core`, branch `bug/ssrf_protection`) |
| **Method** | Static review: Juice Shop source (routes, models, `lib/insecurity.ts`, Angular components) read against OWL source. **Not yet runtime-verified.** |
| **Last reviewed** | 2026-09-30 |
| **Companion** | [OWL vs NodeGoat](./nodegoat.md), which defines roadmap items R1–R9 and E1 referenced below |

## Summary

Juice Shop is a CTF as well as a vulnerable app. Many of its challenges are OSINT puzzles, leaked-secret hunts, easter eggs or Web3 exercises, and no application library could address those. They are counted separately so they don't dilute or inflate the result.

| Status | Challenges | Weakness classes | Meaning |
|---|---|---|---|
| ✅ **Covered** | 23 | 10 | An OWL API implements the control. The app only has to call it. |
| 🟡 **Partial** | 17 | 6 | OWL provides a building block or detection. The app (or another library) supplies the rest. |
| ❌ **Gap** | 30 | 11 | OWL has no API for this today. |
| ⚪ **Out of scope** | 46 | 8 | Not a code-level weakness a library can own: OSINT, leaked secrets, deployment hygiene, app-specific logic, LLM, Web3. |
| | **116** | **35** | |

> **Headline (static):** 70 of Juice Shop's 116 challenges exercise a weakness a security library could address. OWL has a direct control for 23 of them and a partial control for 17 more.

The single largest gap is **SQL injection (8 challenges)**, and OWL's `a03-injection-defense` module has no answer for it today (see [J01](#j01)).

Juice Shop requires Node 22–26, so unlike NodeGoat it has no runtime conflict with OWL (Node ≥ 20). As with NodeGoat, every "Covered" row still needs hand-written Express glue until an adapter exists ([R1](./nodegoat.md#roadmap)).

## Matrix by weakness class

OWASP IDs are this project's categorization, based on each list's category descriptions. The CWE is the closest weakness. Locations are relative to the Juice Shop repository root. The full per-challenge list is in the [appendix](#appendix-all-116-challenges).

| ID | Weakness class | # | Juice Shop location | Top 10 2021 / 2025 | CWE | OWL control | Status |
|---|---|---|---|---|---|---|---|
| <a id="j01"></a>J01 | SQL injection | 8 | `routes/login.ts`, `routes/search.ts` (string-built `sequelize.query`) | A03 / A05 | CWE-89 | — | ❌ Gap |
| <a id="j02"></a>J02 | NoSQL injection (`$where`, operator objects) | 3 | `routes/showProductReviews.ts`, `routes/trackOrder.ts`, `routes/updateProductReviews.ts` | A03 / A05 | CWE-943 | `InputValidator.validateSchema` | ✅ Covered |
| <a id="j03"></a>J03 | Server-side code injection (`eval` of username) | 1 | `routes/userProfile.ts` | A03 / A05 | CWE-95 | `InputValidator.validateSchema` | ✅ Covered |
| <a id="j04"></a>J04 | Evaluation of structured input (B2B orders) | 2 | `routes/b2bOrder.ts` | A03 / A05 | CWE-95 | `InputValidator` (flat rules only) | 🟡 Partial |
| <a id="j05"></a>J05 | Unsafe XML / YAML parsing | 3 | `routes/fileUpload.ts` → `handleXmlUpload`, `handleYamlUpload` | A05 / A02 | CWE-611, CWE-776 | — | ❌ Gap |
| <a id="j06"></a>J06 | Stored XSS (server-side sanitization) | 4 | `models/feedback.ts`, `models/user.ts`, `models/product.ts`, `routes/saveLoginIp.ts` | A03 / A05 | CWE-79 | `InputSanitizer`, `InputValidator.validateEmail` | ✅ Covered |
| <a id="j07"></a>J07 | DOM XSS (Angular `bypassSecurityTrustHtml`) | 3 | `frontend/.../search-result.component.ts`, `track-result.component.ts` | A03 / A05 | CWE-79 | `InputSanitizer` (browser build) | ✅ Covered |
| <a id="j08"></a>J08 | XSS via CSP header injection | 1 | `routes/userProfile.ts` (CSP built from `profileImage`) | A03 / A05 | CWE-79, CWE-113 | `InputSanitizer` | 🟡 Partial |
| <a id="j09"></a>J09 | Path traversal and file-access bypass (zip slip, NUL byte) | 6 | `routes/fileUpload.ts` → `extractZipBuffer`, `routes/fileServer.ts` | A01 / A01 | CWE-22, CWE-158 | — | ❌ Gap |
| <a id="j10"></a>J10 | Mass assignment / unfiltered request objects | 2 | user registration via `finale-rest` (`role` in body), `routes/dataErasure.ts` (`...req.body` into `res.render`) | A08 / A08 | CWE-915 | — | ❌ Gap |
| <a id="j11"></a>J11 | Object-level authorization (ownership) | 5 | `routes/basket.ts`, `routes/basketItems.ts`, `routes/updateProductReviews.ts`, `routes/dataExport.ts`, `/api/Feedbacks` | A01 / A01 | CWE-639 | `PermissionChecker` / `ACLManager` | 🟡 Partial |
| <a id="j12"></a>J12 | Function-level authorization | 4 | `finale-rest` endpoints in `server.ts` (`/api/Products`, `/api/Feedbacks`), `routes/chat.ts` | A01 / A01 | CWE-285 | `RBACManager` | ✅ Covered |
| <a id="j13"></a>J13 | CSRF | 1 | `routes/updateUserProfile.ts` (cookie-authenticated POST) | A01 / A01 | CWE-352 | `CSRFTokenManager` | ✅ Covered |
| <a id="j14"></a>J14 | SSRF | 1 | `routes/profileImageUrlUpload.ts` (`fetch(url)`) | A10 / A01 | CWE-918 | `SafeFetcher` + `SSRFGuard` | ✅ Covered |
| <a id="j15"></a>J15 | Open redirect (substring allowlist match) | 1 | `lib/insecurity.ts` → `isRedirectAllowed` | A01 / A01 | CWE-601 | — | ❌ Gap |
| <a id="j16"></a>J16 | JWT signature verification (`none`, key confusion) | 2 | `lib/insecurity.ts` (`express-jwt`, `jws.verify`) | A02 / A04 | CWE-347 | — | ❌ Gap |
| <a id="j17"></a>J17 | Weak password hashing (unsalted MD5) | 1 | `lib/insecurity.ts` → `hash` | A02 / A04 | CWE-916 | `PBKDF2Adapter` | 🟡 Partial |
| <a id="j18"></a>J18 | Excessive data exposure in API responses (password hash, JSONP) | 2 | `routes/currentUser.ts`, user API responses | A01 / A01 | CWE-213 | — | ❌ Gap |
| <a id="j19"></a>J19 | Password and registration policy | 3 | `models/user.ts`, `/api/Users` | A07 / A07 | CWE-521, CWE-20 | `SecretPolicy`, `InputValidator` | ✅ Covered |
| <a id="j20"></a>J20 | Knowledge-based account recovery (security questions) | 7 | `routes/resetPassword.ts`, `data/static/securityQuestions.yml` | A04 / A06 | CWE-640 | — | ⚪ Out of scope |
| <a id="j21"></a>J21 | Anti-automation and rate limiting | 2 | `routes/captcha.ts`, `server.ts` (`rateLimit` behind `trust proxy`) | A07 / A07 | CWE-307, CWE-804 | — | ❌ Gap |
| <a id="j22"></a>J22 | Race condition (repeated likes) | 1 | `routes/likeProductReviews.ts` | A04 / A06 | CWE-362 | — | ⚪ Out of scope |
| <a id="j23"></a>J23 | Secrets stored in plaintext (TOTP seeds) | 1 | `models/user.ts` → `totpSecret`, `routes/2fa.ts` | A02 / A04 | CWE-312 | `CryptoManager` | ✅ Covered |
| <a id="j24"></a>J24 | Forgeable tokens (coupons, continue codes) | 2 | `lib/insecurity.ts` → `generateCoupon` (z85), `routes/restoreProgress.ts` (hashids) | A02 / A04 | CWE-345 | `CryptoManager` (AES-GCM) | ✅ Covered |
| <a id="j25"></a>J25 | Server-side business-rule validation | 3 | feedback rating, `routes/basketItems.ts` quantity, registration repeat password | A04 / A06 | CWE-20, CWE-1284 | `InputValidator` (pattern only) | 🟡 Partial |
| <a id="j26"></a>J26 | File upload validation (size, type) | 2 | `routes/fileUpload.ts` → `checkUploadSize`, `checkFileType` | A04 / A06 | CWE-434 | — | ❌ Gap |
| <a id="j27"></a>J27 | Error handling and stack-trace disclosure | 1 | `server.ts` (`errorhandler()`) | A05 / A10 | CWE-209 | `SecurityError` (typed only) | ❌ Gap |
| <a id="j28"></a>J28 | Unrestricted external image URLs | 1 | `routes/profileImageUrlUpload.ts`, `routes/redirect.ts` | A05 / A02 | CWE-20 | — | ❌ Gap |
| <a id="j29"></a>J29 | Vulnerable or malicious npm dependencies | 5 | `package.json`, `frontend/package.json` | A06 / A03 | CWE-1104, CWE-506 | `ComponentPolicy`, `DependencyRiskScanner` | 🟡 Partial |
| <a id="j30"></a>J30 | Vulnerable infrastructure image | 1 | `Dockerfile` | A06 / A03 | CWE-1104 | — | ⚪ Out of scope |
| <a id="j31"></a>J31 | Exposed files, endpoints and hidden routes | 11 | `server.ts` (`serve-index` on `/ftp`, `/support/logs`, …; `/metrics`), Angular routes | A05 / A02 | CWE-548, CWE-200 | — | ⚪ Out of scope |
| <a id="j32"></a>J32 | Leaked secrets and credentials | 8 | frontend bundle, IaC files, external pastes | A07 / A07 | CWE-798 | — | ⚪ Out of scope |
| <a id="j33"></a>J33 | Client-side trust and app-specific logic | 6 | `routes/deluxe.ts`, coupon clock, `routes/changePassword.ts`, OAuth password derivation | A04 / A06 | CWE-602, CWE-620 | — | ⚪ Out of scope |
| <a id="j34"></a>J34 | LLM prompt injection | 3 | `routes/chat.ts` | — (OWASP LLM01) | CWE-1427 | — | ⚪ Out of scope |
| <a id="j35"></a>J35 | CTF meta, puzzles, stale content and Web3 | 9 | various | — | — | — | ⚪ Out of scope |

## How OWL addresses each covered class

Juice Shop's own fixes (its "coding challenges") usually replace the vulnerable line. The OWL controls below are the ones an app would call instead of, or in addition to, that fix.

**J02 — NoSQL injection.** Validate `req.params.id` with a numeric `pattern` before it reaches the `$where` string, and the order ID with its own format pattern. For the review update, `validateSchema({ id: { type: "string" } })` rejects operator objects such as `{ "$ne": … }` (verified). Juice Shop's `{ multi: true }` flag is still app code.

**J03 — Code injection through the username.** A `pattern` allowlist on username at update time stops `#{…}` from ever being stored. Removing the `eval` in `routes/userProfile.ts` is the real fix and is application code.

**J06 — Stored XSS.** Replace `sanitizeSecure` / `sanitizeLegacy` (which depend on an old `sanitize-html`) with `new InputSanitizer("moderate").sanitizeHTML()` in the model hooks and in `saveLoginIp`. OWL's tokenizer removes `<iframe>`, `<script>` and `<svg>` with their content, and removes `javascript:` URLs even when they are hidden with entities. The challenge's own reference string sanitizes to an empty string (verified). For the email field, `validateEmail` rejects markup because it contains whitespace. For the product-description path (`restfulXssChallenge`), J12 must also stop non-admins from editing products.

**J07 — DOM XSS.** Pass the value through the browser build's `InputSanitizer` before `bypassSecurityTrustHtml`. Simply not bypassing Angular's built-in sanitizer is equally valid; OWL helps where the app really does need to render user HTML.

**J12 — Function-level authorization.** Juice Shop exposes `finale-rest` CRUD endpoints for products and feedback to any logged-in user. An `RBACManager` guard (`can(role, "update", "products")`, `can(role, "delete", "feedbacks")`) in front of those routes, with roles taken from the verified JWT, closes the admin-only operations and the chatbot debug path.

**J13 — CSRF.** Use the same server-side synchronizer-token pattern as NodeGoat ([#17](./nodegoat.md#how-owl-addresses-each-covered-row)) on `POST /profile`. That route is authenticated by the `token` cookie, so an origin/referer check alone isn't enough.

**J14 — SSRF.** Replace `fetch(url)` in `profileImageUrlUpload` with `SafeFetcher` plus a `createSafeLookup()` dispatcher. Loopback and private targets fail with `SSRF_BLOCKED` (verified for `localhost`).

**J19 — Password and registration policy.** `SecretPolicy.isEntropySufficient` rejects dictionary words plus sequences (`admin123`-style). It also rejects padded passwords with few distinct characters, which its entropy estimator scores explicitly. `validateSchema` with `required` on email and password rejects empty registrations sent directly to the API. Seeded accounts with weak passwords still need a reset; policy only applies to new passwords.

**J23 — TOTP seeds.** Store `totpSecret` as `CryptoManager.encrypt()` output with a key held outside the database. A database read (for example via J01) then yields ciphertext only. Load the key once at startup ([NodeGoat #15](./nodegoat.md#how-owl-addresses-each-covered-row) explains why).

**J24 — Forgeable tokens.** Coupons are z85-*encoded* and continue codes use hashids with a salt that is in the source, so neither carries integrity. Issuing them as `CryptoManager.encrypt()` payloads (AES-256-GCM) makes any tampering fail at `decrypt()`. OWL has no HMAC/signing API, so AEAD is the only integrity primitive available; tokens are longer as a result.

## What is left: partial classes and gaps

| ID | What OWL provides | What's missing |
|---|---|---|
| J01 | `InputValidator.validateEmail`. | **No parameterized-query support.** Email validation isn't an injection defense: `validateEmail` accepts an address followed by a quote and SQL comment (verified). Free-text search can't be allowlisted at all. The fix is bound parameters (`replacements` in Sequelize). OWL could offer a tagged-template `sql` helper or lint-style detection, but has neither. |
| J04 | Flat string rules (`type`, `pattern`, length). | No nested or array schema, so a structured B2B payload can't be described. The root fix is `JSON.parse` instead of evaluation, which is app code. |
| J05 | — | No safe-parser guidance or presets (XML without external entities or DTDs, YAML with safe schema and size limits). |
| J08 | `InputSanitizer` removes the `<script>` from the username. | No header-safe value check or CSP builder. `validateUrl` accepts a URL containing `;` and spaces (verified), so it can't stop a directive being injected into the CSP. |
| J09 | — | No safe path resolution helper (confine to a base directory, reject NUL bytes, validate archive entry paths). |
| J10 | `validateSchema` checks the keys it is given. | **Unknown keys pass silently** (verified: `{ role: "admin" }` validates against a schema without `role`). A `strict` / `stripUnknown` option would close both challenges. |
| J11 | `PermissionChecker` for role/resource checks. | No object-ownership primitive (same as [NodeGoat #13](./nodegoat.md#what-is-left-partial-rows-and-gaps)). |
| J15 | — | Juice Shop has an allowlist, but checks it with `includes()`. OWL has no safe-redirect helper that compares parsed origins exactly ([R5](./nodegoat.md#roadmap)). |
| J16 | `TokenManager` stores tokens client-side. | No server-side JWT verification with pinned algorithms and keys. `none` and RS/HS key confusion are exactly what such a helper prevents. |
| J17 | `PBKDF2Adapter`. | No `hashPassword` / `verifyPassword` API ([R4](./nodegoat.md#roadmap)). |
| J18 | `SecurityLogger.redact()` already knows which keys are sensitive, but only for logs. | No response-field allowlist or redaction helper for API output, and no JSONP check. |
| J21 | — | No attempt limiter ([R6](./nodegoat.md#roadmap)). The Juice Shop rate limit is bypassable because it trusts client-supplied forwarding headers; a limiter needs a documented, trusted client-key function. There is also no CAPTCHA/challenge binding. |
| J25 | `pattern` can express `^[1-5]$` because it tests `String(value)` (verified). | No numeric `min` / `max` and no cross-field rule (`equals: "password"`). The pattern workaround isn't obvious to users. |
| J26 | — | No upload validation (size limit, extension allowlist, magic-byte sniffing). |
| J27 | `SecurityError` gives typed error codes. | No error-response middleware that hides internals and maps codes to HTTP status ([R1](./nodegoat.md#roadmap)). |
| J28 | `SSRFGuard` covers server-side fetches only. | No host allowlist ([E1](./nodegoat.md#roadmap)) and nothing for URLs rendered client-side. |
| J29 | `ComponentPolicy` denylist and `minVersions`, `DependencyRiskScanner` gate. | Detection only, and only for packages someone has listed. No built-in advisory or typosquat data source ([R9](./nodegoat.md#roadmap)). |

### Why the out-of-scope classes are out of scope

- **J20 Knowledge-based recovery:** the flaw is the design choice of security questions. The fix is removing them, not a library call.
- **J22 Race condition:** needs atomic database updates or unique constraints in the data layer.
- **J30 Infrastructure image:** container scanning, not an npm dependency.
- **J31 Exposed files and endpoints:** only the operator knows which paths are secret; this is deployment hygiene. A future `HardeningReporter` route audit could flag directory listings.
- **J32 Leaked secrets:** secret scanning and rotation belong in CI and ops.
- **J33 Client-side trust and app logic:** each fix is app-specific, such as re-authenticating before a password change or not trusting the client clock.
- **J34 LLM prompt injection:** belongs to the OWASP Top 10 for LLM Applications, not the web Top 10 OWL maps to. It's a candidate for a future OWL module, not a gap in the current ones.
- **J35 CTF meta, puzzles and Web3:** scoreboard, privacy-policy, steganography and smart-contract challenges have no application-code weakness.

## Roadmap

These build on the [NodeGoat roadmap](./nodegoat.md#roadmap) (R1–R9, E1). The existing items also close these Juice Shop classes: R1 → J27, R4 → J17, R5 → J15, R6 → J21, R7 → J11, R9 → J29, E1 → J28.

New items from this review:

| ID | Proposal | Closes | Challenges | Size |
|---|---|---|---|---|
| R10 | `validateSchema` options: `unknownKeys: "reject" \| "strip"`, numeric `min` / `max`, cross-field `equals`, nested `object` / `array` rules. | J10, J25, J04 (partly) | 7 | M |
| R11 | Tagged-template `sql` helper returning `{ text, values }` for Sequelize/pg bound parameters, plus docs on why validation is not an injection defense. | J01 | 8 | M |
| R12 | Safe path helper: `resolveWithin(baseDir, userPath)`, NUL-byte rejection, archive-entry validation. | J09 | 6 | S |
| R13 | Server-side JWT verification with pinned `algorithms` and key, and rejection of `none`. | J16 | 2 | M |
| R14 | Response filtering: `pickSafe(obj, allowlist)`, reusing `SecurityLogger`'s sensitive-key list. | J18 | 2 | S |
| R15 | Upload validator: size, extension allowlist, magic bytes. | J26 | 2 | S |
| R16 | Parser-hardening presets and guidance for XML/YAML, plus a CSP builder that rejects `;` and newlines in source values. | J05, J08 | 4 | M |

**R10–R13 alone would address 18 of the 30 gap challenges** (J01, J09, J10, J16).

## Next step: runtime verification

Juice Shop ships an end-to-end test suite that solves each challenge automatically. That makes runtime verification simpler than for NodeGoat:

1. Fork Juice Shop and wire in the ✅ classes as described above.
2. Run Juice Shop's own e2e suite against the fork. Challenges in a Covered class should now **fail to solve**. Any that still solve show where the static review was wrong.
3. Record results here and change **Method** at the top to "Runtime-verified" with the date.

## Appendix: all 116 challenges

Generated from Juice Shop's `data/static/challenges.yml` at the pinned commit. Every challenge appears exactly once. ★ = Juice Shop difficulty.

| Challenge | Juice Shop category | ★ | Class | Status |
|---|---|---|---|---|
| Login Admin | Injection | 2 | [J01](#j01) | ❌ Gap |
| Database Schema | Injection | 3 | [J01](#j01) | ❌ Gap |
| GDPR Data Erasure | Broken Authentication | 3 | [J01](#j01) | ❌ Gap |
| Login Bender | Injection | 3 | [J01](#j01) | ❌ Gap |
| Login Jim | Injection | 3 | [J01](#j01) | ❌ Gap |
| Christmas Special | Injection | 4 | [J01](#j01) | ❌ Gap |
| Ephemeral Accountant | Injection | 4 | [J01](#j01) | ❌ Gap |
| User Credentials | Injection | 4 | [J01](#j01) | ❌ Gap |
| NoSQL DoS | Injection | 4 | [J02](#j02) | ✅ Covered |
| NoSQL Manipulation | Injection | 4 | [J02](#j02) | ✅ Covered |
| NoSQL Exfiltration | Injection | 5 | [J02](#j02) | ✅ Covered |
| SSTi | Injection | 6 | [J03](#j03) | ✅ Covered |
| Blocked RCE DoS | Insecure Deserialization | 5 | [J04](#j04) | 🟡 Partial |
| Successful RCE DoS | Insecure Deserialization | 6 | [J04](#j04) | 🟡 Partial |
| XXE Data Access | XXE | 3 | [J05](#j05) | ❌ Gap |
| Memory Bomb | Insecure Deserialization | 5 | [J05](#j05) | ❌ Gap |
| XXE DoS | XXE | 5 | [J05](#j05) | ❌ Gap |
| API-only XSS | XSS | 3 | [J06](#j06) | ✅ Covered |
| Client-side XSS Protection | XSS | 3 | [J06](#j06) | ✅ Covered |
| HTTP-Header XSS | XSS | 4 | [J06](#j06) | ✅ Covered |
| Server-side XSS Protection | XSS | 4 | [J06](#j06) | ✅ Covered |
| Bonus Payload | XSS | 1 | [J07](#j07) | ✅ Covered |
| DOM XSS | XSS | 1 | [J07](#j07) | ✅ Covered |
| Reflected XSS | XSS | 2 | [J07](#j07) | ✅ Covered |
| CSP Bypass | XSS | 4 | [J08](#j08) | 🟡 Partial |
| Easter Egg | Broken Access Control | 4 | [J09](#j09) | ❌ Gap |
| Forgotten Developer Backup | Sensitive Data Exposure | 4 | [J09](#j09) | ❌ Gap |
| Forgotten Sales Backup | Sensitive Data Exposure | 4 | [J09](#j09) | ❌ Gap |
| Poison Null Byte | Improper Input Validation | 4 | [J09](#j09) | ❌ Gap |
| Arbitrary File Write | Vulnerable Components | 6 | [J09](#j09) | ❌ Gap |
| Video XSS | XSS | 6 | [J09](#j09) | ❌ Gap |
| Admin Registration | Improper Input Validation | 3 | [J10](#j10) | ❌ Gap |
| Local File Read | Vulnerable Components | 5 | [J10](#j10) | ❌ Gap |
| View Basket | Broken Access Control | 2 | [J11](#j11) | 🟡 Partial |
| Forged Feedback | Broken Access Control | 3 | [J11](#j11) | 🟡 Partial |
| Forged Review | Broken Access Control | 3 | [J11](#j11) | 🟡 Partial |
| Manipulate Basket | Broken Access Control | 3 | [J11](#j11) | 🟡 Partial |
| GDPR Data Theft | Sensitive Data Exposure | 4 | [J11](#j11) | 🟡 Partial |
| Admin Section | Broken Access Control | 2 | [J12](#j12) | ✅ Covered |
| AI Debugging | Broken Access Control | 2 | [J12](#j12) | ✅ Covered |
| Five-Star Feedback | Broken Access Control | 2 | [J12](#j12) | ✅ Covered |
| Product Tampering | Broken Access Control | 3 | [J12](#j12) | ✅ Covered |
| CSRF | Broken Access Control | 3 | [J13](#j13) | ✅ Covered |
| SSRF | Broken Access Control | 6 | [J14](#j14) | ✅ Covered |
| Allowlist Bypass | Unvalidated Redirects | 4 | [J15](#j15) | ❌ Gap |
| Unsigned JWT | Vulnerable Components | 5 | [J16](#j16) | ❌ Gap |
| Forged Signed JWT | Vulnerable Components | 6 | [J16](#j16) | ❌ Gap |
| Weird Crypto | Cryptographic Issues | 2 | [J17](#j17) | 🟡 Partial |
| Password Hash Leak | Sensitive Data Exposure | 2 | [J18](#j18) | ❌ Gap |
| Email Leak | Sensitive Data Exposure | 5 | [J18](#j18) | ❌ Gap |
| Empty User Registration | Improper Input Validation | 2 | [J19](#j19) | ✅ Covered |
| Password Strength | Broken Authentication | 2 | [J19](#j19) | ✅ Covered |
| Login Amy | Sensitive Data Exposure | 3 | [J19](#j19) | ✅ Covered |
| Meta Geo Stalking | Sensitive Data Exposure | 2 | [J20](#j20) | ⚪ Out of scope |
| Visual Geo Stalking | Sensitive Data Exposure | 2 | [J20](#j20) | ⚪ Out of scope |
| Bjoern's Favorite Pet | Broken Authentication | 3 | [J20](#j20) | ⚪ Out of scope |
| Reset Jim's Password | Broken Authentication | 3 | [J20](#j20) | ⚪ Out of scope |
| Reset Bender's Password | Broken Authentication | 4 | [J20](#j20) | ⚪ Out of scope |
| Reset Uvogin's Password | Sensitive Data Exposure | 4 | [J20](#j20) | ⚪ Out of scope |
| Reset Bjoern's Password | Broken Authentication | 5 | [J20](#j20) | ⚪ Out of scope |
| CAPTCHA Bypass | Broken Anti Automation | 3 | [J21](#j21) | ❌ Gap |
| Reset Morty's Password | Broken Anti Automation | 5 | [J21](#j21) | ❌ Gap |
| Multiple Likes | Broken Anti Automation | 6 | [J22](#j22) | ⚪ Out of scope |
| Two Factor Authentication | Broken Authentication | 5 | [J23](#j23) | ✅ Covered |
| Forged Coupon | Cryptographic Issues | 6 | [J24](#j24) | ✅ Covered |
| Imaginary Challenge | Cryptographic Issues | 6 | [J24](#j24) | ✅ Covered |
| Repetitive Registration | Improper Input Validation | 1 | [J25](#j25) | 🟡 Partial |
| Zero Stars | Improper Input Validation | 1 | [J25](#j25) | 🟡 Partial |
| Payback Time | Improper Input Validation | 3 | [J25](#j25) | 🟡 Partial |
| Upload Size | Improper Input Validation | 3 | [J26](#j26) | ❌ Gap |
| Upload Type | Improper Input Validation | 3 | [J26](#j26) | ❌ Gap |
| Error Handling | Security Misconfiguration | 1 | [J27](#j27) | ❌ Gap |
| Cross-Site Imaging | Security Misconfiguration | 5 | [J28](#j28) | ❌ Gap |
| Security Advisory | Miscellaneous | 3 | [J29](#j29) | 🟡 Partial |
| Legacy Typosquatting | Vulnerable Components | 4 | [J29](#j29) | 🟡 Partial |
| Vulnerable Library | Vulnerable Components | 4 | [J29](#j29) | 🟡 Partial |
| Frontend Typosquatting | Vulnerable Components | 5 | [J29](#j29) | 🟡 Partial |
| Supply Chain Attack | Vulnerable Components | 5 | [J29](#j29) | 🟡 Partial |
| Vulnerable Infrastructure | Vulnerable Components | 3 | [J30](#j30) | ⚪ Out of scope |
| Confidential Document | Sensitive Data Exposure | 1 | [J31](#j31) | ⚪ Out of scope |
| Exposed Metrics | Observability Failures | 1 | [J31](#j31) | ⚪ Out of scope |
| Score Board | Miscellaneous | 1 | [J31](#j31) | ⚪ Out of scope |
| Web3 Sandbox | Broken Access Control | 1 | [J31](#j31) | ⚪ Out of scope |
| Deprecated Interface | Security Misconfiguration | 2 | [J31](#j31) | ⚪ Out of scope |
| Misplaced IaC Files | Security Misconfiguration | 2 | [J31](#j31) | ⚪ Out of scope |
| Access Log | Observability Failures | 4 | [J31](#j31) | ⚪ Out of scope |
| Misplaced Signature File | Observability Failures | 4 | [J31](#j31) | ⚪ Out of scope |
| Blockchain Hype | Security through Obscurity | 5 | [J31](#j31) | ⚪ Out of scope |
| Extra Language | Broken Anti Automation | 5 | [J31](#j31) | ⚪ Out of scope |
| Retrieve Blueprint | Sensitive Data Exposure | 5 | [J31](#j31) | ⚪ Out of scope |
| Exposed Credentials | Sensitive Data Exposure | 2 | [J32](#j32) | ⚪ Out of scope |
| Login MC SafeSearch | Sensitive Data Exposure | 2 | [J32](#j32) | ⚪ Out of scope |
| NFT Takeover | Sensitive Data Exposure | 2 | [J32](#j32) | ⚪ Out of scope |
| Leaked Unsafe Product | Sensitive Data Exposure | 4 | [J32](#j32) | ⚪ Out of scope |
| Login Cloud Admin | Sensitive Data Exposure | 4 | [J32](#j32) | ⚪ Out of scope |
| Leaked Access Logs | Observability Failures | 5 | [J32](#j32) | ⚪ Out of scope |
| Leaked API Key | Sensitive Data Exposure | 5 | [J32](#j32) | ⚪ Out of scope |
| Login Support Team | Security Misconfiguration | 6 | [J32](#j32) | ⚪ Out of scope |
| Missing Encoding | Improper Input Validation | 1 | [J33](#j33) | ⚪ Out of scope |
| Deluxe Fraud | Improper Input Validation | 3 | [J33](#j33) | ⚪ Out of scope |
| Expired Coupon | Improper Input Validation | 4 | [J33](#j33) | ⚪ Out of scope |
| Login Bjoern | Broken Authentication | 4 | [J33](#j33) | ⚪ Out of scope |
| Change Bender's Password | Broken Authentication | 5 | [J33](#j33) | ⚪ Out of scope |
| Premium Paywall | Cryptographic Issues | 6 | [J33](#j33) | ⚪ Out of scope |
| Chatbot Prompt Injection | Injection | 2 | [J34](#j34) | ⚪ Out of scope |
| Greedy Chatbot Manipulation | Injection | 3 | [J34](#j34) | ⚪ Out of scope |
| System Prompt Extraction | Injection | 3 | [J34](#j34) | ⚪ Out of scope |
| Mass Dispel | Miscellaneous | 1 | [J35](#j35) | ⚪ Out of scope |
| Outdated Allowlist | Unvalidated Redirects | 1 | [J35](#j35) | ⚪ Out of scope |
| Privacy Policy | Miscellaneous | 1 | [J35](#j35) | ⚪ Out of scope |
| Security Policy | Miscellaneous | 2 | [J35](#j35) | ⚪ Out of scope |
| Mint the Honey Pot | Improper Input Validation | 3 | [J35](#j35) | ⚪ Out of scope |
| Privacy Policy Inspection | Security through Obscurity | 3 | [J35](#j35) | ⚪ Out of scope |
| Nested Easter Egg | Cryptographic Issues | 4 | [J35](#j35) | ⚪ Out of scope |
| Steganography | Security through Obscurity | 4 | [J35](#j35) | ⚪ Out of scope |
| Wallet Depletion | Miscellaneous | 6 | [J35](#j35) | ⚪ Out of scope |
