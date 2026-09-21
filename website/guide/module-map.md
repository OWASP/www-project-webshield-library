# Module Map by OWASP Number

Every OWL module maps directly to an OWASP Top 10 (2021) category, so the API you import matches the vocabulary your threat model already uses.

| # | OWASP Category | Core Module | Key Exports |
|---|---|---|---|
| A01 | Broken Access Control | `a01-access-control` | [`RBACManager`, `ACLManager`, `PermissionChecker`](/reference/a01-access-control) |
| A02 | Cryptographic Failures | `a02-crypto-integrity` | [`CryptoManager`, `PBKDF2Adapter`, `Argon2Adapter`, `SecretPolicy`](/reference/a02-crypto-integrity) |
| A03 | Injection | `a03-injection-defense` | [`InputSanitizer`, `InputValidator`](/reference/a03-injection-defense) |
| A04 | Insecure Design | `a04-insecure-design-guard` | [`ThreatModelGuard`, `DesignChecklist`](/reference/a04-insecure-design-guard) |
| A05 | Security Misconfiguration | `a05-security-misconfiguration` | [`SecurityConfigManager`, `HardeningReporter`](/reference/a05-security-misconfiguration) |
| A06 | Vulnerable & Outdated Components | `a06-vulnerable-components` | [`DependencyRiskScanner`, `ComponentPolicy`](/reference/a06-vulnerable-components) |
| A07 | Identification & Authentication Failures | `a07-auth-session` | [`AuthManager`, `TokenManager`](/reference/a07-auth-session) |
| A08 | Software & Data Integrity Failures | `a08-data-integrity` | [`CSRFTokenManager`, `HTTPClient`](/reference/a08-data-integrity) |
| A09 | Security Logging & Monitoring Failures | `a09-logging-monitoring` | [`SecurityLogger`, `EventEmitter`](/reference/a09-logging-monitoring) |
| A10 | Server-Side Request Forgery | `a10-ssrf-defense` | [`SSRFGuard`, `SafeFetcher`](/reference/a10-ssrf-defense) |

::: tip Composition across categories
`HTTPClient` (A08) natively accepts an `outboundRequestPolicy` from `SSRFGuard` (A10), composing transport hardening and SSRF defense in a single client. See the [A08 reference](/reference/a08-data-integrity) for the full example.
:::

::: tip Simplified setup for A01/A07/A09
`createOwlClient()` builds the A01 (`RBACManager`/`ACLManager`), A07 (`TokenManager`/`AuthManager`), and A09 (`EventEmitter`/`SecurityLogger`) managers from one config object, and React's `OwlProvider` composes their four providers into one component. See [React Adapter Setup](/guide/react-setup) or the [A07 reference](/reference/a07-auth-session).
:::

Every class and typed constant also has a matching React hook or provider in `@owasp-js/owl-react`, documented alongside the core API on each category's reference page.
