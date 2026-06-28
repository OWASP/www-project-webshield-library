# OWL - OWASP Web Shield Library

OWL is a production-focused JavaScript security toolkit with OWASP-numbered modules and a React adapter.

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

- A01 Access Control: `src/core/a01-access-control`
- A02 Crypto & Integrity: `src/core/a02-crypto-integrity`
- A03 Injection Defense: `src/core/a03-injection-defense`
- A04 Insecure Design Guard: `src/core/a04-insecure-design-guard`
- A05 Security Misconfiguration: `src/core/a05-security-misconfiguration`
- A06 Vulnerable Components: `src/core/a06-vulnerable-components`
- A07 Auth & Session: `src/core/a07-auth-session`
- A08 Data Integrity & CSRF: `src/core/a08-data-integrity`
- A09 Logging & Monitoring: `src/core/a09-logging-monitoring`
- A10 SSRF Defense: `src/core/a10-ssrf-defense`

Cross-mapping note: `HTTPClient` in A08 can integrate A10 SSRF policies for outbound request enforcement.

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

- Examples index: `examples/README.md`
- React app integration: `examples/react-app-integration.md`
- Node API integration: `examples/node-api-integration.md`
- Deployment recipes: `examples/deployment-recipes.md`
- GitHub Actions security gate: `examples/github-actions-security-gate.md`

## Scripts

- `npm run build`: Build ESM and CJS outputs.
- `npm run test`: Run unit tests.
- `npm run lint`: Run ESLint checks.
- `npm run check`: Run quality checks.

## Project Docs

- Contributing: `CONTRIBUTING.md`
- Code of Conduct: `CODE_OF_CONDUCT.md`
- Security Policy: `SECURITY.md`
- Changelog: `CHANGELOG.md`
- Support: `SUPPORT.md`
- Governance: `docs/GOVERNANCE.md`
- Enhanced docs: `docs/enhanced-documentation.md`
- Architecture: `docs/architecture.md`
- Framework guide: `docs/framework.md`
- Troubleshooting: `docs/troubleshooting.md`

## Security Notes

- Default token handling is in-memory.
- ACL conflict strategy is deny-overrides.
- Security logs redact common sensitive fields.
- SSRF guard blocks loopback/private targets and protocol abuse.

## Roadmap Alignment

- Phase 1 Foundation: A01, A03, A07, A08, A09 complete with tests.
- Phase 2 Expansion: A02, A04, A05, A06, A10 plus React adapter implemented.
- Phase 3 Completion: integration snippets, docs, and extension guidance included.

## Extending with New OWASP Modules

1. Create `src/core/aXX-name/` with focused classes and `index.js` exports.
2. Add tests under `src/__tests__/core/` for positive/negative/edge behavior.
3. Export from `src/core/index.js` and document in this README module map.