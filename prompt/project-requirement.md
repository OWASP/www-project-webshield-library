
OWL is a developer-friendly security framework for JavaScript applications that provides practical, ready-to-use solutions for addressing the OWASP Top 10 vulnerabilities across all major frameworks (React, Angular , Vue). Unlike traditional security libraries that require substantial configuration or deep security expertise, OWASP Web Shield offers intuitive JavaScript utilities with framework-specific adapters that seamlessly integrate into existing applications. The library enables developers to implement security best practices without extensive security knowledge through its innovative approach of encapsulating complex security logic within pure JavaScript that can be consumed through familiar framework patterns. Each utility and adapter directly corresponds to specific OWASP security concerns, making it easy for developers to identify and address potential vulnerabilities. OWASP Web Shield distinguishes itself by focusing on a framework-agnostic core with optimized framework-specific implementations, ensuring compatibility with modern JavaScript practices and optimal performance across frameworks. The library includes built-in javascript definitions, providing type safety and enabling IDE autocompletion. The project addresses a critical gap in the JavaScript ecosystem by providing a universal security toolset that balances robust protection with developer experience regardless of framework choice.

Project roadmap
Project roadmap is structured in 3 progressive phases.

Beginning with Foundation - where we'll complete the core util using java script to handle the top 10 owasp coverage

authentication module with token handling and CSRF protection, implement the RBAC system with permission hierarchy, develop framework-agnostic protection patterns with specific adapters for React, create input sanitization utilities, establish project infrastructure, and release v0.1.0.

During the expansion phase -  create adapter for Reactjs utilize the javascript utils.. 

During the Completion phase -  write examples how to integrate these reactjs adapter in sample application and we'll add include documentation

## Detailed AI Prompt to Generate the Project

Use the following prompt with an AI coding assistant to generate the complete OWL (OWASP Web Shield Library) project.

PROMPT START

You are a senior JavaScript security library engineer. Generate a production-quality monorepo-style JavaScript project named OWL (OWASP Web Shield Library), focused on practical mitigation helpers for OWASP Top 10 risks in modern web apps.

Primary objective:
- Build a framework-agnostic core security library in JavaScript.
- Build a React adapter package that consumes the core package.
- Use OWASP category numbering in package/module names for easy distinction (A01, A02, etc.).
- Prioritize developer experience: simple API, secure defaults, JSDoc docs, and concise guides.

Required naming convention (important):
- Use package/module prefixes with OWASP numbers, for example:
	- @owl/a01-access-control
	- @owl/a02-crypto-integrity
	- @owl/a03-injection-defense
	- @owl/a04-insecure-design-guard
	- @owl/a05-security-misconfiguration
	- @owl/a06-vulnerable-components
	- @owl/a07-auth-session
	- @owl/a08-data-integrity
	- @owl/a09-logging-monitoring
	- @owl/a10-ssrf-defense
- Every major feature must clearly map to one OWASP category in folder naming and exports.
- If a feature spans categories, assign a primary category and document cross-mapping in README.

Key principles:
- Security by default.
- Framework-agnostic core, framework-specific adapters.
- Clear module boundaries and stable public APIs.
- Test-first mindset with high unit test coverage.

Technical constraints:
- Language: JavaScript (ES2022+).
- Type support: JSDoc typedefs and IntelliSense-friendly APIs.
- Runtime target: modern Node + browser-compatible outputs.
- Test framework: Jest.
- Package manager: npm.
- Build output: ESM and CJS where practical.
- No unnecessary dependencies.

Expected repository structure:
- package.json
- jsconfig.json
- jest.config.js
- src/index.js
- src/core/index.js
- src/core/a01-access-control/
	- ACLManager.js
	- RBACManager.js
	- PermissionChecker.js
	- types.js
	- index.js
- src/core/a07-auth-session/
	- AuthManager.js
	- TokenManager.js
	- types.js
	- index.js
- src/core/a08-data-integrity/
	- CSRFTokenManager.js
	- HTTPClient.js
	- types.js
	- index.js
- src/core/a03-injection-defense/
	- InputSanitizer.js
	- InputValidator.js
	- types.js
	- index.js
- src/core/a09-logging-monitoring/
	- EventEmitter.js
	- SecurityLogger.js
	- index.js
- src/core/error/
	- SecurityError.js
	- index.js
- src/adapters/react/
	- package.json
	- index.js
	- context/
		- AuthContext.jsx
		- ACLContext.jsx
		- RBACContext.jsx
		- SecurityContext.jsx
		- index.js
	- hooks/
		- useAuth.js
		- useAuthToken.js
		- useACL.js
		- usePermission.js
		- index.js
	- components/
		- auth/
		- access-control/
		- security/
		- input/
		- index.js
	- middleware/
	- types/
	- utils/

Generate these capabilities in the core package:

1) A07: Authentication and session handling
- AuthManager for session lifecycle (set session, clear session, check authenticated).
- TokenManager supporting:
	- in-memory token handling by default.
	- optional pluggable storage adapter.
	- access token expiry checks.
	- refresh flow hooks (no hard-coded backend calls).
	- secure parsing and validation helpers.
- Include secure defaults and clear error handling.

2) A08: CSRF and request integrity
- CSRFTokenManager with:
	- token generation utility.
	- token storage strategy abstraction.
	- attach/validate token helpers for request workflows.
	- rotation support.
- HTTPClient wrapper with:
	- secure default headers.
	- CSRF header integration.
	- token injection hooks.
	- request/response interceptors.
	- centralized error normalization.

3) A01: Access control
- RBACManager:
	- role definition.
	- role inheritance support.
	- permission mapping.
	- can(role, action, resource) style checks.
- ACLManager:
	- per-resource allow/deny policies.
	- policy conflict resolution strategy documented and enforced.
- PermissionChecker:
	- combines RBAC + ACL checks.
	- deterministic output with reason metadata.

4) A03: Injection defense
- InputSanitizer:
	- HTML sanitization hooks.
	- script injection defense patterns.
	- configurable sanitization profile levels.
- InputValidator:
	- schema-based validation helpers.
	- email/url/length/pattern validators.
	- structured validation result objects.

5) A09: Security events and monitoring
- SecurityError hierarchy with error codes.
- EventEmitter for security eventing (auth changed, token rotated, denied access, etc.).
- SecurityLogger utility with redaction support for sensitive fields.

6) A02: Cryptographic failures
- CryptoManager with:
	- strong random generation helpers.
	- AES-GCM encryption/decryption wrappers.
	- secure key derivation utilities (PBKDF2/Argon2 adapter pattern).
	- safe defaults for nonce, salt, tag length, and encoding.
- SecretPolicy helpers for key rotation windows and minimum entropy checks.

7) A04: Insecure design
- ThreatModelGuard utilities with:
	- reusable secure workflow guards (state transitions, step validation).
	- abuse-case rule checks.
	- policy-by-default patterns for sensitive operations.
- DesignChecklist validator for common design-time security controls.

8) A05: Security misconfiguration
- SecurityConfigManager with:
	- environment configuration schema validation.
	- secure default profile presets.
	- unsafe setting detector (debug flags, wildcard CORS, weak cookie config).
- HardeningReporter that outputs actionable misconfiguration findings.

9) A06: Vulnerable and outdated components
- DependencyRiskScanner interface with:
	- pluggable provider for npm audit/SBOM sources.
	- risk normalization output (severity, package, fixed version).
	- policy gate helpers to fail CI on threshold.
- ComponentPolicy for allowlist/denylist and version floor rules.

10) A10: Server-side request forgery (SSRF)
- SSRFGuard with:
	- strict URL parser and protocol allowlist.
	- DNS/IP range checks to block private/loopback/link-local targets.
	- redirect hop validation.
	- outbound request policy integration for HTTPClient.
- SafeFetcher wrapper that enforces SSRFGuard before requests.

React adapter requirements:
- Create React contexts and provider patterns for auth and authorization state.
- Hooks required:
	- useAuth
	- useAuthToken
	- useACL
	- usePermission
- Components/utilities that make common checks ergonomic.
- Adapter must consume core package APIs, not duplicate core logic.

Public API and DX requirements:
- Export clean entry points from each module index.js.
- Add JSDoc for all public classes/functions/types.
- Avoid breaking changes in public exports.
- Include minimal practical usage examples in comments or docs.

Testing requirements:
- Add unit tests for every core module and key React hooks.
- Cover positive, negative, and edge cases.
- Include tests for:
	- expired tokens.
	- permission inheritance edge cases.
	- ACL deny-overrides.
	- sanitizer behavior for malicious payloads.
	- validator failure result structure.
- Keep test structure aligned with module folders.

Quality gates:
- Lint and tests pass.
- Jest tests pass.
- No dead exports.
- No placeholder TODO-only implementations.

Project roadmap implementation plan:

Phase 1: Foundation (v0.1.0)
- Implement core modules with OWASP-numbered naming.
- Deliver A01, A03, A07, A08, A09 baseline coverage.
- Publish stable core exports and complete unit tests.

Phase 2: Expansion
- Implement React adapter package using core utilities.
- Implement A02, A04, A05, A06, A10 modules in core with tests.
- Add provider/context/hook-level tests.
- Validate peer dependency setup for React.

Phase 3: Completion
- Provide sample app integration snippets.
- Write complete developer-facing docs.
- Add extension guidance for adding new OWASP-numbered modules (A02, A04, A05, A06, A10).

Deliverables format:
- Provide all source files with complete implementations.
- Provide package scripts for build, test, lint, and check.
- Provide concise README sections:
	- installation
	- quick start
	- module map by OWASP number
	- core usage
	- react adapter usage
	- security notes

Implementation style constraints:
- Keep modules cohesive and focused.
- Prefer composition over deep inheritance.
- Keep functions pure where possible.
- Use explicit interfaces for extension points.
- Throw typed security errors, not generic errors.

Now generate the project in incremental order:
1. Base configs and package scripts.
2. Core module implementations (A01 to A10, in order).
3. Core tests.
4. React adapter implementations.
5. Adapter tests.
6. Documentation and examples.

For each step, output:
- file path
- full file content
- brief rationale

PROMPT END