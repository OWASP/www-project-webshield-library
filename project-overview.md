---
title: Overview
layout: null
tab: true
order: 1
tags: owasp javascript react security-library top10
---

> # OWASP Web Shield Library (OWL)
> Practical, reusable security controls for modern JavaScript applications.

## What OWL Delivers

- OWASP-aligned module coverage from A01 to A10
- Framework-agnostic core package with predictable APIs
- React adapter organized by the same A01-A10 categories
- Secure defaults with explicit policy-driven behavior
- CI-ready engineering workflow with lint, test, and build gates

## Core Module Map (A01-A10)

| OWASP Category | Module | Primary Capabilities |
|---|---|---|
| A01 | a01-access-control | RBAC, ACL, PermissionChecker (deny-overrides) |
| A02 | a02-crypto-integrity | AES-GCM encryption, pluggable KDF adapters, secret policies |
| A03 | a03-injection-defense | Input sanitization and schema-style validation |
| A04 | a04-insecure-design-guard | Threat model guards and design checklists |
| A05 | a05-security-misconfiguration | Config validation and hardening reports |
| A06 | a06-vulnerable-components | Dependency risk scanning and component policy gating |
| A07 | a07-auth-session | Auth/session lifecycle and token management |
| A08 | a08-data-integrity | CSRF token management and secure HTTP client |
| A09 | a09-logging-monitoring | Security events and redaction-aware security logging |
| A10 | a10-ssrf-defense | URL policy validation and safe fetch wrapper |

## React Adapter Highlights

- A01: ACL/RBAC providers, useACL, usePermission, PermissionGate
- A07: AuthProvider, useAuth, useAuthToken, AuthGate
- A08: useSecureHttpClient with CSRF defaults and request policy support
- A09: SecurityProvider and monitoring hooks
