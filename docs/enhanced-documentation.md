---
render_with_liquid: false
---

# OWASP Web Shield Library — Enhanced Overview

## What This Framework Does

OWL (OWASP Web Shield Library) is a JavaScript security framework that maps security controls directly to OWASP-style categories (A01-A10). It provides reusable security primitives in a framework-agnostic core and category-aligned React adapter APIs.

Unlike one-off utility snippets, OWL is designed as a policy-centric framework with deterministic decision behavior, typed security errors, and test-first delivery.

## How It Works

OWL follows a layered security model:

### 1. Core Policy Layer

Core modules implement the actual security behavior and enforcement rules:

- A01 access control (RBAC/ACL/decision engine)
- A02 cryptographic integrity and KDF adapters
- A03 input sanitization and validation
- A04 secure design workflow guards
- A05 misconfiguration detection and hardening reporting
- A06 vulnerable component policy and risk normalization
- A07 auth/session and token lifecycle
- A08 CSRF and secure HTTP workflows
- A09 eventing and secure logging
- A10 outbound SSRF defense controls

### 2. Adapter Integration Layer

The React adapter exposes category-native providers, hooks, and guards while consuming core logic rather than duplicating it.

### 3. Quality and Validation Layer

OWL enforces lint and test gates and ships module-focused tests for positive, negative, and abuse-path scenarios.

## Capability Matrix

| Category | Key Classes/Functions | Security Outcome |
|---|---|---|
| A01 | RBACManager, ACLManager, PermissionChecker | Deterministic authorization with deny-overrides |
| A02 | CryptoManager, PBKDF2Adapter, Argon2Adapter, SecretPolicy | Safer encryption and key derivation workflows |
| A03 | InputSanitizer, InputValidator | Input trust-boundary protection |
| A04 | ThreatModelGuard, DesignChecklist | Secure flow and design-time safeguards |
| A05 | SecurityConfigManager, HardeningReporter | Misconfiguration detection and remediation |
| A06 | DependencyRiskScanner, ComponentPolicy | Supply-chain risk policy enforcement |
| A07 | AuthManager, TokenManager | Consistent auth/session handling |
| A08 | CSRFTokenManager, HTTPClient | Request integrity and hardened transport |
| A09 | EventEmitter, SecurityLogger | Security observability with redaction |
| A10 | SSRFGuard, SafeFetcher | Safer outbound request controls |

## React Adapter Usage

The adapter is organized directly under a01-a10 modules, so teams adopt controls by threat category instead of generic folders.

Example:

```js
import {
	AuthProvider,
	ACLProvider,
	RBACProvider,
	AuthGate,
	PermissionGate,
	useSecureHttpClient
} from "@owl/react-adapter";
```

Recommended provider composition:

1. AuthProvider
2. ACLProvider
3. RBACProvider

## Security Notes

- Authorization uses deny-overrides behavior.
- Token handling defaults to in-memory storage.
- Security logging supports sensitive-field redaction.
- HTTP workflows can apply outbound SSRF policies.
- Configuration checks should run in CI before deployment.

## Testing and Operational Model

Run gates:

```bash
npm run lint
npm run test
npm run check
```

Coverage includes:

- Core modules A01-A10
- React adapter hook/provider flows
- Edge conditions such as token expiry and ACL deny precedence

## Use Cases

### Development Teams

- Add category-based security controls quickly.
- Keep app code focused on business logic.

### Security Teams

- Standardize controls across services and frontends.
- Track security decisions with typed metadata and events.

### DevSecOps

- Enforce quality gates with deterministic failures.
- Integrate policy checks into pull-request pipelines.

## Extension Path

To add a new module:

1. Add core module folder under src/core/aXX-name.
2. Add explicit exports and typed errors where needed.
3. Add category-specific tests.
4. Add matching React adapter module.
5. Document usage and security notes.

## API Reference

Use [docs/api-reference.md](./api-reference.md) for copyable examples covering every exported core class, helper, provider, hook, guard, and alert component.
