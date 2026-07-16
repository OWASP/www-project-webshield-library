# OWASP Web Shield Library — Troubleshooting

## What This Document Covers

This guide provides a practical diagnostic workflow for common OWL integration and runtime issues across core modules (A01-A10) and the React adapter.

## How To Diagnose Issues

### Step 1: Validate Tooling and Gate Health

Run:

```bash
npm run lint
npm run test
npm run check
```

If check fails, resolve lint errors first, then test failures.

### Step 2: Identify the A-Category

Map issue to category before debugging:

- A01 authorization
- A07 auth/session
- A08 request integrity
- A10 outbound request policy
- A03 input handling
- A09 logging/eventing

### Step 3: Inspect Decision Metadata

For authorization and policy logic, inspect reason metadata and error codes before changing rules.

## Common Problems and Fixes

| Area | Symptom | Likely Cause | Fix |
|---|---|---|---|
| Setup | Adapter imports fail | Workspace install drift | Re-run npm install from repo root |
| A07 | isAuthenticated false after login | Missing/expired token | Set valid expiresAt and session |
| A07 | refresh not triggered | Missing onRefresh or refreshToken | Configure refresh hook and token payload |
| A01 | PermissionGate denies expected route | ACL deny overrides RBAC allow | Review ACL policy and PermissionChecker reason |
| A01 | useACL/usePermission throws | Missing providers in tree | Ensure AuthProvider + ACLProvider + RBACProvider wrapping order |
| A08/A10 | HTTP request blocked | Outbound URL rejected by policy | Validate host/protocol against SSRFGuard settings |
| A08 | CSRF validation errors | Rotated token mismatch | Re-attach latest CSRF header before retry |
| A03 | Sanitizer strips too much | strict profile behavior | Use moderate profile for controlled rich text |
| A03 | Validation false negatives | Schema/pattern mismatch | Add explicit schema tests and tune rules |
| A09 | Secrets appear in logs | Redaction key coverage incomplete | Extend redactKeys list in logger configuration |

## Category-Specific Playbooks

### A01 Access Control

Checklist:

1. Confirm role inheritance graph.
2. Confirm resource and action mapping format.
3. Inspect ACL wildcard denies.
4. Inspect PermissionChecker output reason.

### A07 Auth and Session

Checklist:

1. Confirm token presence and expiry units (ms).
2. Confirm session set before guarded render path.
3. Confirm refresh hook and refresh token availability.

### A08 and A10 Request Path

Checklist:

1. Confirm CSRF token lifecycle and attachment.
2. Confirm secure header composition.
3. Confirm outbound URL passes SSRF guard validation.

### A03 Injection Defense

Checklist:

1. Confirm sanitizer profile choice.
2. Validate schema rules (required, pattern, length).
3. Add regression tests for malicious payloads.

## CI/CD Failure Isolation

If local pass but CI fails:

1. Align Node version with CI.
2. Re-run clean install.
3. Check any environment-dependent tests.
4. Ensure no stale lockfile/workspace mismatch.

## Diagnostic Command Set

```bash
npm run lint
npm run test
npm run check
```

Use these commands before filing an issue.

## Issue Reporting Template

Include:

1. OWASP category affected (A01-A10)
2. Expected behavior
3. Actual behavior
4. Repro steps and sample inputs
5. Command output from lint/test/check
6. Environment details (OS, Node, npm)
