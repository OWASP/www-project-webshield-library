# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-06-28

### Added

- Core OWASP modules A01-A10 with JavaScript APIs.
- React adapter modules grouped by A01-A10.
- Access control, auth/session, CSRF/data integrity, logging, SSRF, crypto, misconfiguration, design guard, and vulnerable component helpers.
- Jest unit tests for core and key adapter hooks.
- ESLint quality gate and `check` script.

### Changed

- React adapter organization consolidated into A01-A10 folders.
- A08 HTTPClient now supports outbound SSRF policy integration.
- A02 crypto now supports pluggable KDF adapters (PBKDF2 default + Argon2 plugin pattern).

### Security

- Deny-overrides conflict strategy for ACL checks.
- Sensitive field redaction in security logging.
