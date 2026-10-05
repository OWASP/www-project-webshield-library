# OWL Benchmark Traceability Matrix

This page consolidates the OWL benchmark reviews into one matrix, traced in three directions:

1. **OWASP Top 10 category → benchmark evidence:** does OWL's A01–A10 coverage claim hold up against real vulnerable apps?
2. **OWL API → benchmark findings:** which OWL APIs are exercised, and which never are?
3. **Gap → roadmap item:** which planned work closes which findings?

| Benchmark | Target | Unit counted | Detail |
|---|---|---|---|
| NodeGoat | OWASP NodeGoat `c5cb68a` | 22 documented weaknesses | [nodegoat.md](./nodegoat.md) (row IDs `#1`–`#22`) |
| Juice Shop | OWASP Juice Shop v20.2.0 `1618a61` | 116 challenges in 35 weakness classes | [juice-shop.md](./juice-shop.md) (class IDs `J01`–`J35`) |
| Runtime benchmark | Local replicas of both targets, baseline vs OWL | 16 attack scenarios | [runtime-verification.md](./runtime-verification.md) (IDs `JS-01`–`JS-06`, `NG-01`–`NG-10`) |
| Actual-app benchmark | OWASP Juice Shop v20.2.0 `1618a61` and OWASP NodeGoat `c5cb68a`, as shipped vs through OWL wiring preloads | the same 16 attack scenarios, 32 checks | [upstream-verification.md](./upstream-verification.md) (same IDs) |

**Method:** static review of OWL 1.0.0 `src/core`, not yet runtime-verified; last reviewed 2026-09-30. The two benchmarks count different units (weaknesses vs. challenges), so their numbers are shown side by side and never summed. Sixteen of those weaknesses are additionally **runtime-verified**, twice over: against local baseline replicas of the documented routes with the same route under OWL ([runtime-verification.md](./runtime-verification.md), run 2026-10-04, part of `npm test`), and against the actual pinned applications with the same scenarios in baseline and OWL modes ([upstream-verification.md](./upstream-verification.md), run 2026-10-04, `npm run benchmark:apps`). Both runs record 13 blocked and 3 gaps (SQL injection, IDOR, brute force).

**Legend:** ✅ Covered — an OWL API implements the control · 🟡 Partial — OWL provides part of it · ❌ Gap — no OWL API today · ⚪ Out of scope — not addressable by a library.

## Scoreboard

| | ✅ Covered | 🟡 Partial | ❌ Gap | ⚪ Out of scope | In scope |
|---|---|---|---|---|---|
| **NodeGoat** (weaknesses) | 10 | 5 | 5 | 2 | 20 |
| **Juice Shop** (challenges) | 23 | 17 | 30 | 46 | 70 |

## 1. OWASP Top 10 (2021) → benchmark evidence

OWL's modules are numbered by the 2021 list (`a01-access-control` … `a10-ssrf-defense`), so this matrix uses 2021 IDs. The benchmark pages also give the 2025 ID for every row.

Cells show **Covered / Partial / Gap** counts. For NodeGoat these are weaknesses; for Juice Shop they are challenges. Out-of-scope items are excluded.

| Category | OWL module | NodeGoat C / P / G | Juice Shop C / P / G | ✅ Covered by | 🟡 Partial | ❌ Gap | Verdict |
|---|---|---|---|---|---|---|---|
| A01 Broken Access Control | `a01-access-control`, `CSRFTokenManager` | 2 / 1 / 1 | 5 / 5 / 9 | #14, #17, J12, J13 | #13, J11 | #19, J09, J15, J18 | Roles and CSRF hold up. Ownership (IDOR), path traversal and redirects are unaddressed. |
| A02 Cryptographic Failures | `a02-crypto-integrity` | 1 / 1 / 0 | 3 / 1 / 2 | #15, J23, J24 | #9, J17 | J16 | Encryption at rest is strong. Password hashing lacks a hash/verify API, and there is no JWT verification. |
| A03 Injection | `a03-injection-defense` | 4 / 1 / 0 | 11 / 3 / 8 | #1, #2, #4, #22, J02, J03, J06, J07 | #5, J04, J08 | J01 | XSS and NoSQL are well covered. **SQL injection (8 challenges) has no answer.** |
| A04 Insecure Design | `a04-insecure-design-guard` | 0 / 0 / 0 | 0 / 3 / 2 | — | J25 | J26 | Neither benchmark exercises the A04 module itself. The partial comes from `InputValidator`. |
| A05 Security Misconfiguration | `a05-security-misconfiguration` | 0 / 1 / 1 | 0 / 0 / 5 | — | #7 | #8, J05, J27, J28 | **Weakest category.** OWL audits a config object but sets no headers, hardens no parsers and maps no errors. |
| A06 Vulnerable Components | `a06-vulnerable-components` | 0 / 1 / 0 | 0 / 5 / 0 | — | #18, J29 | — | Detection only. No built-in advisory data source. |
| A07 Identification & Authentication | `a07-auth-session`, `SecretPolicy` | 1 / 0 / 2 | 3 / 0 / 2 | #10, J19 | — | #6, #12, J21 | Password policy works. No server-side session regeneration or attempt limiting. |
| A08 Software & Data Integrity | `a08-data-integrity` | 0 / 0 / 0 | 0 / 0 / 2 | — | — | J10 | Mass assignment is unaddressed; `validateSchema` ignores unknown keys. |
| A09 Logging & Monitoring | `a09-logging-monitoring` | 1 / 0 / 0 | 0 / 0 / 0 | #3 | — | — | Covered, but only one benchmark row exercises it. |
| A10 SSRF | `a10-ssrf-defense` | 1 / 0 / 0 | 1 / 0 / 0 | #20, J14 | — | — | Covered in both benchmarks. |
| Not in Top 10 (ReDoS) | `a03-injection-defense` | 0 / 0 / 1 | — | — | — | #21 | `validateSchema` runs `pattern` even after `maxLength` fails. |

## 2. OWL API → benchmark findings

Every public OWL API, with each benchmark row that uses it. Rows marked *finding* are where the review found a defect or limitation in the API itself, not just a missing feature.

| Module | API | NodeGoat | Juice Shop | Exercised? |
|---|---|---|---|---|
| A01 | `RBACManager` | ✅ #14 | ✅ J12 (4) | Yes |
| A01 | `ACLManager`, `PermissionChecker` | 🟡 #13 | 🟡 J11 (5) | Yes, partial |
| A02 | `CryptoManager` | ✅ #15 | ✅ J23 (1), ✅ J24 (2) | Yes |
| A02 | `PBKDF2Adapter`, `generateSalt` | 🟡 #9 | 🟡 J17 (1) | Yes, partial |
| A02 | `Argon2Adapter` | — | — | **No** |
| A02 | `SecretPolicy` | ✅ #10 | ✅ J19 (3) | Yes |
| A03 | `InputValidator.validateSchema` | ✅ #1, #2, #22 · ❌ #21 *finding* | ✅ J02 (3), J03 (1), J19 · 🟡 J04 (2), J25 (3) · ❌ J10 (2) *finding* | Yes |
| A03 | `InputValidator.validateEmail`, `validateUrl` | 🟡 #5 | ✅ J06 · ❌ J01 (8) *finding* · 🟡 J08 (1) *finding* | Yes |
| A03 | `InputSanitizer` | ✅ #4 · 🟡 #5 *finding* | ✅ J06 (4), J07 (3) · 🟡 J08 (1) | Yes |
| A04 | `ThreatModelGuard`, `DesignChecklist` | — (considered for #12; insufficient) | — | **No** |
| A05 | `SecurityConfigManager`, `HardeningReporter` | 🟡 #7 | — | Yes, partial |
| A06 | `ComponentPolicy`, `DependencyRiskScanner` | 🟡 #18 | 🟡 J29 (5) | Yes, partial |
| A07 | `AuthManager`, `TokenManager` | — | — (J16 needs server-side verification, which these don't do) | **No** |
| A08 | `CSRFTokenManager` | ✅ #17 | ✅ J13 (1) | Yes |
| A08 | `HTTPClient` | — | — | **No** |
| A09 | `SecurityLogger` | ✅ #3 | — | Yes |
| A09 | `EventEmitter` | — | — | **No** |
| A10 | `SSRFGuard`, `SafeFetcher` | ✅ #20 | ✅ J14 (1) | Yes |
| — | `SecurityError` | Used for 403 mapping in covered rows | ❌ J27 (1) (no error middleware) | Yes |
| — | `createOwlClient` | — | — | **No** |

**Unexercised APIs:** `Argon2Adapter`, `ThreatModelGuard`, `DesignChecklist`, `AuthManager`, `TokenManager`, `HTTPClient`, `EventEmitter` and `createOwlClient`. Most of these are client-side or SPA APIs (token storage, authenticated fetch, the React provider wiring) or design-time aids, and both benchmarks were reviewed from the server side. Juice Shop's Angular frontend stores and sends a JWT, so reviewing that frontend against `TokenManager` and `HTTPClient` is the natural way to extend coverage.

**Findings in existing APIs** (defects, not missing features):

| API | Finding | Rows |
|---|---|---|
| `InputValidator.validateSchema` | Runs `pattern` after `maxLength` has already failed, so a length cap doesn't protect a backtracking regex. | #21 |
| `InputValidator.validateSchema` | Unknown keys pass silently, which enables mass assignment. | J10 |
| `InputSanitizer` | Doesn't encode `"` or `'`, so output isn't safe inside HTML attributes. | #5 |
| `InputValidator.validateEmail` | Accepts SQL metacharacters. Correct for an email check, but undocumented as not being an injection defense. | J01 |
| `InputValidator.validateUrl` | Accepts `;` and spaces, so the result isn't safe to place in a header (e.g. CSP). | J08 |

## 3. Gap → roadmap item

Each roadmap item, with the benchmark rows it would move from ❌/🟡 toward ✅. R1–R9 and E1 are defined in [nodegoat.md](./nodegoat.md#roadmap); R10–R16 are defined in [juice-shop.md](./juice-shop.md#roadmap).

| ID | Proposal | NodeGoat rows | Juice Shop classes | Juice Shop challenges | Size |
|---|---|---|---|---|---|
| R11 | Tagged-template `sql` helper for bound parameters | — | J01 | 8 | M |
| R12 | Safe path helper (`resolveWithin`, NUL bytes, archive entries) | — | J09 | 6 | S |
| R10 | `validateSchema`: unknown-key handling, `min`/`max`, `equals`, nested rules | — | J10, J25, J04 (partly) | 7 | M |
| R7 | Ownership / ABAC check | #13 | J11 | 5 | M |
| R9 | Built-in `npm audit` provider | #18 | J29 | 5 | S |
| R16 | XML/YAML parser presets and a CSP builder | — | J05, J08 | 4 | M |
| R1 | `@owasp-webshield/express` adapter (headers, sessions, error mapping, middleware) | #6, #8 | J27 | 1 | L |
| R6 | Attempt limiter with pluggable store | #12 | J21 | 2 | M |
| R13 | Server-side JWT verification with pinned algorithms | — | J16 | 2 | M |
| R14 | Response-field filtering | — | J18 | 2 | S |
| R15 | Upload validator (size, extension, magic bytes) | — | J26 | 2 | S |
| R4 | `PasswordHasher.hash()` / `verify()` | #9 | J17 | 1 | S |
| R5 | Safe-redirect helper | #19 | J15 | 1 | S |
| E1 | `SSRFGuard` `allowHosts` | #20 (strengthens) | J28 | 1 | S |
| R2 | Skip `pattern` when a length rule fails | #21 | — | — | S |
| R3 | Context-aware encoders (attribute, URL, JS) | #5 | — | — | M |
| R8 | `toCookieOptions()` and real-config audit | #7 | — | — | S |

Sorted by Juice Shop challenges closed. **R11, R12 and R10 together address 21 of the 47 Juice Shop challenges currently marked Gap or Partial.**

## Keeping this page current

- The per-benchmark pages are the source of truth. Update them first, then re-derive the counts here.
- When a roadmap item ships, move its rows to ✅ on the benchmark page, update the scoreboard, and cross the item off section 3.
- When a benchmark is runtime-verified, change **Method** at the top and on the benchmark page, and add a "verified on" date to the scoreboard.
