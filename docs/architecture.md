---
render_with_liquid: false
---

# OWASP Web Shield Library — Architecture & Adoption Guide

## What This Architecture Is Designed For

OWL is designed to make security controls composable, category-driven, and framework-portable.

Primary architecture outcomes:

- Threat-category ownership (A01-A10)
- Minimal duplication between core and adapters
- Deterministic policy behavior for runtime decisions
- Extensible interfaces for crypto, transport, and component risk policies

> Looking for runnable bootstrap code rather than concepts? See [core-js-usage.md](./core-js-usage.md) (framework-agnostic), [react-adapter-usage.md](./react-adapter-usage.md) (React), or [api-reference.md](./api-reference.md) for a copyable example per export.

## How The Architecture Works

### 1. Core Security Engine

Core modules are the authoritative security layer. They implement:

- Access and authorization decisions
- Authentication and session primitives
- Input trust-boundary controls
- Request integrity and outbound safety
- Logging, observability, and hardening checks

### 2. Adapter Integration Layer

React adapter modules expose framework-native hooks/providers/guards and consume core decisions.

Adapter principle:

- Orchestrate, do not reimplement core policy behavior.

### 3. Cross-Category Composition

OWL supports explicit cross-category policy composition.

Examples:

- A08 HTTP client accepts outbound request policy from A10.
- A02 crypto manager accepts pluggable KDF adapters.

## Category-to-Component Map

| Category | Core Engine | Adapter Surface |
|---|---|---|
| A01 | RBACManager, ACLManager, PermissionChecker | ACLProvider, RBACProvider, usePermission, PermissionGate |
| A02 | CryptoManager, PBKDF2Adapter, Argon2Adapter | useCryptoManager |
| A03 | InputSanitizer, InputValidator | useInputSanitizer, SanitizedText |
| A04 | ThreatModelGuard, DesignChecklist | useThreatModelGuard |
| A05 | SecurityConfigManager, HardeningReporter | useHardeningReport |
| A06 | DependencyRiskScanner, ComponentPolicy | useDependencyRiskScanner |
| A07 | AuthManager, TokenManager | AuthProvider, useAuth, useAuthToken, AuthGate |
| A08 | CSRFTokenManager, HTTPClient | useSecureHttpClient, withSecurityHeaders |
| A09 | EventEmitter, SecurityLogger | SecurityProvider, useSecurityMonitoring, SecurityAlert |
| A10 | SSRFGuard, SafeFetcher | useSafeFetcher |
| *(cross-cutting)* | `createOwlClient()` builds the A01/A07/A09 managers above from one config | `OwlProvider` composes the A01/A07/A09 providers above from that client |

## Request Lifecycle Example

1. User authentication state is established (A07).
2. Authorization decision is computed (A01).
3. Request is prepared with secure defaults and token/CSRF metadata (A08).
4. Outbound URL policy is validated (A10).
5. Security events and redacted logs are emitted (A09).

## Error and Decision Model

OWL uses typed errors and reason-bearing decision outputs.

Benefits:

- Cleaner app-level exception handling
- Better incident analysis and telemetry
- Lower risk of silent security fallback behavior

## Extensibility Model

### KDF Extension (A02)

- Plug custom derive behavior through Argon2Adapter derive function.

### Outbound Request Extension (A08/A10)

- Inject policy object with validateUrl to enforce transport rules.

### Dependency Risk Extension (A06)

- Inject provider-based scanner output and enforce policy thresholds.

## Testing and Quality Architecture

- Per-module tests for A01-A10 core components
- Adapter tests for key provider/hook integration paths
- Enforced lint and test gates via npm run check

## Security Notes

- Deny-overrides strategy is central to A01 conflict handling.
- In-memory token default reduces persistence exposure.
- SSRF checks block loopback/private targets by default behavior.
- Redaction in logs should remain mandatory in production sinks.
- A05/A06 hardening and dependency checks should be included in deployment gating, not just run ad hoc.

## Team-Oriented Adoption Plan

| Team | Priority Modules | Immediate Value |
|---|---|---|
| Frontend | A07, A01, A03 | Safer UI guards and input handling |
| Backend/API | A08, A10, A03 | Hardened request paths and outbound controls |
| Platform | A05, A06, A09 | Better hardening and visibility |
| Security | A01-A10 | Policy consistency across systems |

## Implementation Maturity Stages

### Stage 1 — Baseline Security

- A07 + A01 + baseline tests

### Stage 2 — Transport and Input Hardening

- A08 + A10 + A03 integration

### Stage 3 — Platform and Supply-Chain Security

- A05 + A06 + A09 operationalized

### Stage 4 — Governance and Scaling

- Policy versioning, secure design reviews, and module extension process (see [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-new-owasp-module))

## Common Anti-Patterns

- Reimplementing policy logic in feature components instead of calling `PermissionChecker`/adapter hooks.
- Skipping provider composition and using hooks outside their context (e.g. `usePermission` without `RBACProvider`/`ACLProvider`).
- Logging secrets without redaction, or extending `redactKeys` after the fact instead of before shipping.
- Disabling outbound URL policy checks (`SSRFGuard`) in production for convenience.

## Use Cases By Audience

- **Development teams** — add category-based security controls quickly and keep feature code focused on business logic instead of reimplementing checks.
- **Security teams** — standardize controls across services and frontends, and track decisions via typed metadata and events instead of ad hoc logging.
- **DevSecOps** — enforce quality gates with deterministic failures and integrate policy checks into pull-request pipelines (see [deployment-recipes.md](./deployment-recipes.md) and [github-actions-security-gate.md](./github-actions-security-gate.md)).

## Architecture Evolution Targets

- Publishable per-category package model (@owasp-js/owl-a01-...)
- Stronger DNS-backed SSRF validation mode
- Additional adapter layers for Angular and Vue
- ~~A browser-safe package root~~ — done: `CSRFTokenManager` (A08) is Web Crypto-based now, and both `@owasp-js/owl` and `@owasp-js/owl-react` ship a `"browser"`-conditioned build where `CryptoManager`/`KDFAdapters` (A02) are a same-shaped throwing stub instead of a build-breaking `node:crypto` import. A `./core/*` subpath also lets bundlers resolve individual files directly. Remaining follow-up: a genuinely async, Web-Crypto-backed `CryptoManager` for real browser-side encryption would need a breaking API change and a major version bump (see the [FAQ](https://owasp.org/www-project-webshield-library/faq#can-i-use-owl-in-a-browser-bundle))
