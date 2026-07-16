---
render_with_liquid: false
---

# OWASP Web Shield Library — Architecture

## What This Architecture Is Designed For

OWL is designed to make security controls composable, category-driven, and framework-portable.

Primary architecture outcomes:

- Threat-category ownership (A01-A10)
- Minimal duplication between core and adapters
- Deterministic policy behavior for runtime decisions
- Extensible interfaces for crypto, transport, and component risk policies

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

## Architecture Evolution Targets

- Publishable per-category package model (@owl/a01-...)
- Stronger DNS-backed SSRF validation mode
- Additional adapter layers for Angular and Vue
