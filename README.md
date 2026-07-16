<p align="center">
  <img src="https://owasp.org/assets/images/logo.png" width="180" alt="OWASP Logo" />
</p>

<h1 align="center">OWASP Web Shield Library</h1>

<p align="center">
  <strong>OWL — Practical, reusable OWASP Top 10 security controls for modern JavaScript applications.</strong>
</p>

<p align="center">
  <a href="https://github.com/OWASP/www-project-webshield-library/blob/main/LICENSE.md"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License" /></a>
  <a href="https://owasp.org/projects/"><img src="https://img.shields.io/badge/owasp-lab%20project-blue" alt="OWASP Lab Project" /></a>
  <a href="https://github.com/OWASP/www-project-webshield-library/actions"><img src="https://img.shields.io/github/check-runs/OWASP/www-project-webshield-library/main?label=CI" alt="CI" /></a>
  <a href="https://github.com/OWASP/www-project-webshield-library/releases"><img src="https://img.shields.io/github/v/release/OWASP/www-project-webshield-library?sort=semver" alt="Release" /></a>
  <img src="https://img.shields.io/badge/node-%3E%3D20-brightgreen" alt="Node 20+" />
  <img src="https://img.shields.io/badge/coverage-A01--A10-success" alt="OWASP A01-A10" />
</p>

---

> **OWL** is a production-focused JavaScript security toolkit that maps security controls directly to OWASP Top 10 categories (A01–A10). It ships a framework-agnostic core package and a full React adapter — making security primitives as easy to use as any other NPM library.

## Contents

- [Why OWL](#why-owl)
- [Quick Start](#quick-start)
- [Module Map](#module-map-by-owasp-number)
- [Core Usage](#core-usage)
- [React Adapter](#react-adapter-usage)
- [Examples](#integration-examples)
- [Scripts](#scripts)
- [Project Docs](#project-docs)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## Why OWL

| Problem | OWL Solution |
|---|---|
| Security scattered across ad-hoc snippets | Category-aligned modules A01–A10 |
| No shared language between dev and security teams | OWASP-numbered APIs and typed errors |
| Inconsistent deny/allow logic | Deterministic deny-overrides policy engine |
| Risky outbound requests | SSRF guard wired directly into `HTTPClient` |
| Secrets leaking through logs | Redaction-first `SecurityLogger` |
| React apps with no auth or permission guard | `AuthGate`, `PermissionGate`, and provider hooks |

---

## Installation

```bash
npm install
```

## Quick Start

```js
import {
  TokenManager,
  AuthManager,
  RBACManager,
  ACLManager,
  PermissionChecker
} from "@owl/core";

const tokenManager = new TokenManager();
tokenManager.setTokens({ accessToken: "jwt", expiresAt: Date.now() + 3600000 });

const authManager = new AuthManager({ tokenManager });
authManager.setSession({ userId: "u1", roles: ["admin"] });

const rbac = new RBACManager();
rbac.defineRole("admin", ["read:invoice", "update:invoice"]);

const acl = new ACLManager();
acl.setPolicy("invoice", "delete", "deny");

const permissions = new PermissionChecker({ rbacManager: rbac, aclManager: acl });
console.log(permissions.check({ role: "admin", action: "read", resource: "invoice" }));
```

## Module Map by OWASP Number

| # | OWASP Category | Core Module | Key Exports |
|---|---|---|---|
| A01 | Broken Access Control | `a01-access-control` | `RBACManager`, `ACLManager`, `PermissionChecker` |
| A02 | Crypto Failures | `a02-crypto-integrity` | `CryptoManager`, `PBKDF2Adapter`, `Argon2Adapter`, `SecretPolicy` |
| A03 | Injection | `a03-injection-defense` | `InputSanitizer`, `InputValidator` |
| A04 | Insecure Design | `a04-insecure-design-guard` | `ThreatModelGuard`, `DesignChecklist` |
| A05 | Security Misconfiguration | `a05-security-misconfiguration` | `SecurityConfigManager`, `HardeningReporter` |
| A06 | Vulnerable Components | `a06-vulnerable-components` | `DependencyRiskScanner`, `ComponentPolicy` |
| A07 | Auth & Session Failures | `a07-auth-session` | `AuthManager`, `TokenManager` |
| A08 | Data Integrity Failures | `a08-data-integrity` | `CSRFTokenManager`, `HTTPClient` |
| A09 | Security Logging Failures | `a09-logging-monitoring` | `SecurityLogger`, `EventEmitter` |
| A10 | SSRF | `a10-ssrf-defense` | `SSRFGuard`, `SafeFetcher` |

> `HTTPClient` (A08) natively accepts an `outboundRequestPolicy` from `SSRFGuard` (A10), composing transport hardening and SSRF defense in one client.

## Core Usage

```js
import { InputSanitizer, InputValidator } from "@owl/core";

const sanitizer = new InputSanitizer("strict");
const clean = sanitizer.sanitizeHTML('<img src=x onerror=alert(1)>safe');

const validator = new InputValidator();
const result = validator.validateSchema(
  { email: "user@example.com" },
  { email: { required: true, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ } }
);
```

## React Adapter Usage

```js
import React from "react";
import {
  AuthProvider,
  ACLProvider,
  RBACProvider,
  AuthGate,
  PermissionGate
} from "@owl/react-adapter";

export function App({ authManager, aclManager, rbacManager }) {
  return (
    <AuthProvider authManager={authManager}>
      <ACLProvider aclManager={aclManager}>
        <RBACProvider rbacManager={rbacManager}>
          <AuthGate fallback={<div>Please sign in</div>}>
            <PermissionGate action="read" resource="reports" fallback={<div>Forbidden</div>}>
              <div>Secure Content</div>
            </PermissionGate>
          </AuthGate>
        </RBACProvider>
      </ACLProvider>
    </AuthProvider>
  );
}
```

## Integration Examples

| Example | Description |
|---|---|
| [Core JS usage](examples/core-js-usage.md) | Full composition guide for `@owl/core` |
| [React adapter usage](examples/react-adapter-usage.md) | Provider + hook composition for `@owl/react-adapter` |
| [Core Node demo ▶](examples/core-node-demo/README.md) | Runnable Node script — `node index.js` |
| [React adapter demo ▶](examples/react-adapter-demo/README.md) | Runnable Vite app — `npm run dev` |
| [OWL enabled app ▶](examples/owl-enabled-app/README.md) | Full multi-page reference app (A01–A10 demo pages) |
| [Node API integration](examples/node-api-integration.md) | Express-style middleware patterns |
| [Deployment recipes](examples/deployment-recipes.md) | Production and CI deployment patterns |
| [GitHub Actions gate](examples/github-actions-security-gate.md) | Security quality gate for CI/CD |

## Scripts

```bash
npm run build    # Build ESM and CJS outputs
npm run test     # Run Jest unit tests
npm run lint     # Run ESLint
npm run check    # lint + test (full quality gate)
```

## Project Docs

| Document | Purpose |
|---|---|
| [docs/api-reference.md](docs/api-reference.md) | Full API reference with copyable examples |
| [docs/release-process.md](docs/release-process.md) | Step-by-step release runbook |
| [docs/architecture.md](docs/architecture.md) | System architecture and module layout |
| [docs/framework.md](docs/framework.md) | Framework guide and adoption patterns |
| [docs/enhanced-documentation.md](docs/enhanced-documentation.md) | Enhanced capability overview |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common issues and fixes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy |
| [SUPPORT.md](SUPPORT.md) | Getting help |
| [GOVERNANCE.md](GOVERNANCE.md) | Project governance |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |

## Contributing

Pull requests, bug reports, and feedback are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started.

Before submitting a PR:

```bash
npm run check   # must pass
```

Tests must cover security-relevant success and failure paths.

## Security

Do **not** open public issues for security vulnerabilities. Follow the private reporting process in [SECURITY.md](SECURITY.md).

## License

Apache 2.0 — see [LICENSE.md](LICENSE.md).

---

<p align="center">
  <sub>OWASP Web Shield Library &mdash; <em>making security controls as natural as any other dependency.</em></sub>
</p>