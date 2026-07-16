# Changelog

<p align="center">
  <a href="https://github.com/OWASP/www-project-webshield-library/releases"><img src="https://img.shields.io/github/v/release/OWASP/www-project-webshield-library?sort=semver" alt="Latest Release" /></a>
  &nbsp;
  <img src="https://img.shields.io/badge/versioning-semver-blue" alt="Semver" />
</p>

All notable changes to this project are documented in this file.
This project follows [Semantic Versioning](https://semver.org/).

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-06-28

### Added

- Stable, documented public API for OWL core modules A01-A10.
- CI and security workflows for lint/test/build and dependency/static analysis gates.
- Tab-based OWASP project site content structure for overview, getting started, and contributing guidance.

### Changed

- Promoted package from `0.x` foundation to `1.0.0` stable release.
- Hardened npm publish metadata with explicit package files, repository metadata, and prepublish validation.
- Restricted package exports to stable entry points.

### Security

- Formalized `1.x` support expectations and release posture.
- Retained deny-overrides authorization behavior and security log redaction defaults.

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
