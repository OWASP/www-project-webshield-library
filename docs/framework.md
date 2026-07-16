---
render_with_liquid: false
---

# OWASP Web Shield Library — Framework Guide

## What This Framework Enables

OWL helps teams integrate security controls as reusable framework components instead of scattered ad hoc checks.

It supports category-by-category adoption and aligns implementation to OWASP-style threat domains (A01-A10).

## How To Use The Framework

### 1. Bootstrap Core Security Managers

Create core managers once in a bootstrap layer and pass them to application services and adapters.

```js
import {
  TokenManager,
  AuthManager,
  RBACManager,
  ACLManager,
  PermissionChecker,
  CSRFTokenManager,
  HTTPClient,
  SSRFGuard
} from "@owl/core";

const tokenManager = new TokenManager();
const authManager = new AuthManager({ tokenManager });

const rbac = new RBACManager();
const acl = new ACLManager();
const permissionChecker = new PermissionChecker({ rbacManager: rbac, aclManager: acl });

const csrf = new CSRFTokenManager();
csrf.rotateToken();

const client = new HTTPClient({
  csrfManager: csrf,
  tokenProvider: () => tokenManager.getAccessToken(),
  outboundRequestPolicy: new SSRFGuard()
});
```

### 2. Wire React Adapter Providers

```js
import {
  AuthProvider,
  ACLProvider,
  RBACProvider,
  AuthGate,
  PermissionGate
} from "@owl/react-adapter";
```

Recommended provider order:

1. AuthProvider
2. ACLProvider
3. RBACProvider

### 3. Apply Security Patterns In Features

- Use AuthGate and PermissionGate for route/component protection.
- Use useSecureHttpClient for protected request flows.
- Use useInputSanitizer and InputValidator at trust boundaries.

## React Adapter Usage Patterns

### Protected View Pattern

- AuthGate blocks unauthenticated access.
- PermissionGate enforces action/resource authorization.

### Secure Request Pattern

- useSecureHttpClient applies security headers and CSRF integration.
- Outbound policy integration enables SSRF controls.

### Monitoring Pattern

- SecurityProvider and useSecurityMonitoring connect logs/events to app observability.

## Security Notes

- A01 enforces deny-overrides conflict handling.
- A07 token logic defaults to in-memory behavior.
- A08 request hardening can compose with A10 outbound policy.
- A09 logging should always preserve redaction rules.
- A05/A06 checks should be included in deployment gating.

## Team-Oriented Adoption Plan

| Team | Priority Modules | Immediate Value |
|---|---|---|
| Frontend | A07, A01, A03 | Safer UI guards and input handling |
| Backend/API | A08, A10, A03 | Hardened request paths and outbound controls |
| Platform | A05, A06, A09 | Better hardening and visibility |
| Security | A01-A10 | Policy consistency across systems |

## CI/CD Framework Integration

Minimum pipeline gates:

```bash
npm run lint
npm run test
npm run check
```

Recommended rule:

- Block deployment when security-critical policy checks fail.

## Common Anti-Patterns

- Reimplementing policy logic in feature components.
- Skipping provider composition and using hooks outside context.
- Logging secrets without redaction.
- Disabling outbound URL policy checks in production.

## Implementation Maturity Stages

### Stage 1 — Baseline Security

- A07 + A01 + baseline tests

### Stage 2 — Transport and Input Hardening

- A08 + A10 + A03 integration

### Stage 3 — Platform and Supply-Chain Security

- A05 + A06 + A09 operationalized

### Stage 4 — Governance and Scaling

- Policy versioning, secure design reviews, and module extension process
