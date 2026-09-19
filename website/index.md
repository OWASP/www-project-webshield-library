---
layout: home

hero:
  name: "OWL"
  text: "OWASP Web Shield Library"
  tagline: Practical, reusable OWASP Top 10 security controls for modern JavaScript applications — a framework-agnostic core plus a full React adapter.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: API Reference
      link: /reference/a01-access-control
    - theme: alt
      text: View on GitHub
      link: https://github.com/OWASP/www-project-webshield-library

features:
  - icon: 🗂️
    title: OWASP-numbered modules
    details: Every module maps directly to an OWASP Top 10 category (A01–A10), so security code speaks the same language your threat model does.
  - icon: 🔒
    title: Deterministic access control
    details: RBACManager and ACLManager compose through PermissionChecker with a deny-overrides policy engine — no ambiguous allow/deny ordering.
  - icon: 🌐
    title: SSRF-aware HTTP client
    details: HTTPClient natively accepts an outboundRequestPolicy from SSRFGuard, so transport hardening and SSRF defense compose in one client.
  - icon: 🪪
    title: Redaction-first logging
    details: SecurityLogger redacts secrets by field name and by value pattern (JWT-shaped strings) before anything reaches a sink.
  - icon: ⚛️
    title: First-class React adapter
    details: AuthGate, PermissionGate, and a full set of hooks and providers bring every core module into React with the same OWASP-numbered API.
  - icon: ✅
    title: Typed, testable errors
    details: SecurityError / SecurityErrorCode gives every module a consistent, typed error surface across the whole library.
---
