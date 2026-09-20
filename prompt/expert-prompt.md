# OWASP Web Shield Library — Expert Implementation Prompt

## Purpose

This prompt is intended for an expert contributor or implementation agent who will review the OWASP Web Shield Library repository and complete the following goals:

- Identify and fill missing documentation gaps across core JS modules and the React adapter.
- Fix any incorrect or incomplete usage examples currently present in docs and examples.
- Provide clear, end-to-end usage examples for every core module and every React adapter export.
- Improve or add unit tests to cover all core security behaviors, adapter hooks, providers, and error paths.

## Current repository summary

- `src/index.js` exports the full core module surface from `src/core/index.js`.
- `src/core/` contains category modules A01 through A10, plus `error/SecurityError.js`.
- `src/adapters/react/` contains React wrappers for A01-A10 and a `package.json` for the adapter package.
- Existing tests are located under `src/__tests__/core/` and `src/__tests__/adapter/`.
- Existing docs are in `docs/` and usage examples are also in `examples/`.

## Key gaps to address

1. **Missing documentation for every exported core class/function.**
   - Ensure all exported core APIs have at least one example in docs.
   - If a core export is not presently documented, document it.

2. **Missing or incomplete React adapter usage examples.**
   - Document provider composition, hooks, and guard components.
   - Include React-specific examples for state, token handling, request wiring, and monitoring.

3. **Potential API usage uncertainties.**
   - Clarify whether `useSecureHttpClient` accepts both synchronous and asynchronous `tokenProvider` values.
   - Clarify how `AuthProvider`, `AuthGate`, and `useAuthToken` behave when tokens expire.

4. **Testing coverage gaps.**
   - Add tests for edge and failure conditions in core modules.
   - Ensure adapter tests verify provider composition and hook return values.
   - Add test cases for the security error codes and metadata payloads.

## Implementation checklist

### A. Documentation updates

- Add or extend documentation in `docs/framework.md`, `docs/enhanced-documentation.md`, or a new file if needed.
- Ensure the prompt file `docs/expert-prompt.md` remains the authoritative task list.
- Document the core exports for each category:
  - A01: `RBACManager`, `ACLManager`, `PermissionChecker`, `types.js` if exported.
  - A02: `CryptoManager`, `PBKDF2Adapter`, `Argon2Adapter`, `generateSalt`, `SecretPolicy`.
  - A03: `InputSanitizer`, `InputValidator`, `types.js`.
  - A04: `ThreatModelGuard`, `DesignChecklist`.
  - A05: `SecurityConfigManager`, `HardeningReporter`.
  - A06: `DependencyRiskScanner`, `ComponentPolicy`.
  - A07: `AuthManager`, `TokenManager`, `types.js`.
  - A08: `CSRFTokenManager`, `HTTPClient`, `types.js`.
  - A09: `EventEmitter`, `SecurityLogger`.
  - A10: `SSRFGuard`, `SafeFetcher`.
- Document the react adapter exports:
  - `AuthProvider`, `useAuth`, `useAuthToken`, `AuthGate`
  - `ACLProvider`, `RBACProvider`, `useACL`, `usePermission`, `PermissionGate`
  - `useCryptoManager`
  - `useInputSanitizer`, `SanitizedText`
  - `useThreatModelGuard`
  - `useHardeningReport`
  - `useDependencyRiskScanner`
  - `useSecureHttpClient`, `withSecurityHeaders`
  - `SecurityProvider`, `useSecurityMonitoring`, `SecurityAlert`
  - `useSafeFetcher`

### B. Usage examples to add or verify

#### Core JS usage

- `RBACManager` role definition and permission checks.
- `ACLManager` deny/allow policy evaluation and conflict resolution.
- `PermissionChecker` combining RBAC and ACL.
- `CryptoManager` key derivation, AES-GCM encryption, and decryption.
- `PBKDF2Adapter` default KDF usage and `Argon2Adapter` plugin pattern.
- `SecretPolicy.isEntropySufficient()` and secret validation.
- `InputSanitizer.sanitizeHTML()` and `InputValidator.validate()`.
- `ThreatModelGuard.validateTransition()` and `evaluateAbuseCase()`.
- `DesignChecklist.check()` or example of missing controls.
- `SecurityConfigManager.detectUnsafeSettings()` and `HardeningReporter.generate()`.
- `DependencyRiskScanner.scan()` and `passesPolicy()`.
- `TokenManager.setTokens()`, `refreshIfNeeded()`, `getAccessToken()`, and expiry behavior.
- `AuthManager.setSession()`, `clearSession()`, and `isAuthenticated()`.
- `CSRFTokenManager.rotateToken()`, `.attach()`, `.validate()`.
- `HTTPClient.request()` with CSRF token injection, auth header injection, interceptors, and outbound policy.
- `SecurityLogger.redact()`, `info()`, `warn()`, `error()` with sink customization.
- `SSRFGuard.validateUrl()` and `validateRedirectChain()`.
- `SafeFetcher.fetch()` with config and fetch override.

#### React adapter usage

- Full provider composition example with `AuthProvider`, `ACLProvider`, `RBACProvider`, and `SecurityProvider`.
- `useAuth()` and `useAuthToken()` in components.
- `AuthGate` and `PermissionGate` for protected UI flows.
- `useCryptoManager()` for password-based key generation.
- `useInputSanitizer()` plus `SanitizedText` for rendering sanitized HTML.
- `useThreatModelGuard()` and usage patterns in workflow state machines.
- `useHardeningReport()` in a configuration dashboard.
- `useDependencyRiskScanner()` with async scan lifecycle.
- `useSecureHttpClient()` request creation and `withSecurityHeaders()` application.
- `useSecurityMonitoring()` and `SecurityAlert` usage.
- `useSafeFetcher()` calling remote endpoints safely.

### C. Fixes to review and apply

- Confirm React adapter exports are all surfaced from `src/adapters/react/index.js` and match docs.
- Confirm `package.json` `main`/`module`/`exports` give proper package resolution for `@owasp-core/owl`.
- Confirm adapter package `package.json` dependency on `@owasp-core/owl` is valid for workspace installs.
- Confirm `HTTPClient` handles `tokenProvider` return types correctly; document async support or normalize to a promise.
- Confirm `TokenManager.refreshIfNeeded()` is exercised in docs/tests, especially when access token expires.
- Confirm `useAuthToken()` updates when the underlying token changes and does not stale.
- Confirm `useSecureHttpClient()` lazily creates `CSRFTokenManager` once per component and rotates token on auth boundary if required.
- Confirm `useDependencyRiskScanner()` returns a stable `runScan` callback and state shape.
- Confirm `SecurityProvider` values are memoized and `useSecurityMonitoring()` remains safe to use with or without a provider.
- Confirm `SecurityAlert` is documented as a simple presentational component.

## Unit testing guidance

- Add or improve tests for the following core scenarios:
  1. `RBACManager` inherited role permissions and wildcard matching.
  2. `ACLManager` direct policy, wildcard resources, deny overrides.
  3. `PermissionChecker` deny/prevent behavior for RBAC vs ACL conflicts.
  4. `CryptoManager` encrypt/decrypt success and error handling.
  5. `PBKDF2Adapter` and `Argon2Adapter` plugin error path.
  6. `SecretPolicy.isEntropySufficient()` boundary cases.
  7. `InputSanitizer` HTML/scripting sanitization and profile modes.
  8. `InputValidator` validation rule violations.
  9. `ThreatModelGuard` transition validation and abuse rule evaluation.
  10. `SecurityConfigManager` schema validation and unsafe setting detection.
  11. `DependencyRiskScanner.passesPolicy()` threshold blocking.
  12. `TokenManager` storage, expiration, refresh, and event emission.
  13. `AuthManager` session lifecycle and `isAuthenticated()`.
  14. `CSRFTokenManager` attach/validate and failed validation.
  15. `HTTPClient.request()` header injection, interceptors, fetch execution, and error wrapping.
  16. `SecurityLogger.redact()` sensitive fields and output sink.
  17. `SSRFGuard.validateUrl()` private hosts, bad protocols, and redirect chain enforcement.
  18. `SafeFetcher.fetch()` uses `SSRFGuard` before calling fetch.

- Add or improve React adapter tests for:
  1. `AuthProvider`, `useAuth`, and `useAuthToken` context behavior.
  2. `ACLProvider`, `RBACProvider`, `useACL`, `usePermission`, and `PermissionGate` guard behavior.
  3. `useCryptoManager`, `useInputSanitizer`, `useThreatModelGuard`, `useHardeningReport`, `useDependencyRiskScanner` return values and actions.
  4. `useSecureHttpClient` request creation with `tokenProvider` and CSRF injection.
  5. `withSecurityHeaders` header composition.
  6. `SecurityProvider`, `useSecurityMonitoring`, and `SecurityAlert` rendering.
  7. `useSafeFetcher` policy enforcement and fetch override.

- Ensure tests use the existing Jest configuration in `jest.config.js` and run with `npm run test`.
- Cover both successful flows and failure paths, especially security rejection paths.

## Acceptance criteria

- A new or extended docs entry exists that fully documents core module usage and React adapter usage.
- Examples are present for every major export in the library.
- There is no mismatch between docs and actual exported APIs.
- Unit tests exist or are improved for all major behaviors, including edge cases and error conditions.
- `npm run check` passes after implementation.

## Example doc snippet to include

```js
import {
  ACLManager,
  RBACManager,
  PermissionChecker,
  AuthManager,
  TokenManager,
  CSRFTokenManager,
  HTTPClient,
  SSRFGuard,
  SecurityLogger,
  DependencyRiskScanner
} from "@owasp-core/owl";

import {
  AuthProvider,
  ACLProvider,
  RBACProvider,
  AuthGate,
  PermissionGate,
  useSecureHttpClient,
  SecurityProvider,
  SecurityAlert,
  useSafeFetcher
} from "@owasp-core/owl-react";

const tokenManager = new TokenManager({
  onRefresh: async (refreshToken) => ({
    accessToken: "new-token",
    expiresAt: Date.now() + 60_000,
    refreshToken
  })
});

const authManager = new AuthManager({ tokenManager });
const rbacManager = new RBACManager();
const aclManager = new ACLManager();

rbacManager.defineRole("editor", ["read:articles", "update:articles"]);
aclManager.setPolicy("articles", "delete", "deny");

const httpClient = new HTTPClient({
  baseUrl: "https://api.example.com",
  csrfManager: new CSRFTokenManager(),
  tokenProvider: () => tokenManager.getAccessToken(),
  outboundRequestPolicy: new SSRFGuard()
});

function App() {
  return (
    <AuthProvider authManager={authManager}>
      <ACLProvider aclManager={aclManager}>
        <RBACProvider rbacManager={rbacManager}>
          <AuthGate fallback={<div>Please sign in</div>}>
            <PermissionGate action="read" resource="articles" fallback={<div>Denied</div>}>
              <SecureArticleList />
            </PermissionGate>
          </AuthGate>
        </RBACProvider>
      </ACLProvider>
    </AuthProvider>
  );
}
```

## Notes for the implementer

- Keep doc examples small, copyable, and aligned with real exports.
- Do not rely on browser globals in core Node-friendly code.
- Keep the `@owasp-core/owl` and `@owasp-core/owl-react` public API stable in the docs.
- Keep tests deterministic and avoid flaky async behaviors.
- Fix any mismatches between docs, examples, and test coverage.
