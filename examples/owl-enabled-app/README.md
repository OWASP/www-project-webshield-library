# OWL Enabled App

A multi-page Tailwind-powered reference app that includes:

- tutorial mode for learning each OWASP category (A01-A10)
- integrated TODO application mode for a realistic end-to-end product flow

## What it demonstrates

- A01: RBAC + ACL deny-overrides via permission decisions
- A02: Secret strength and rotation policy checks
- A03: HTML sanitization in user input flows
- A04: Threat model transition and abuse-case validation
- A05: Misconfiguration detection and hardening recommendations
- A06: Dependency risk scanning workflow
- A07: Session and token lifecycle handling
- A08: Secure HTTP client behavior with CSRF and auth headers
- A09: Security event emission and logging patterns
- A10: SSRF-safe outbound request validation

## Run locally

From this folder:

```bash
npm install
npm start
# or
npm run dev
```

Open the Vite URL shown in terminal.

## Page map

- `/`: Overview and module index
- `/integrated-app`: Todo Workspace with task creation, edits, transitions, sync, and activity timeline using A01-A10 controls in context
- `/a01` through `/a10`: dedicated demonstration pages for each category

## Notes

- The app uses deterministic mocks for HTTP and scan providers to keep demos runnable offline.
- CryptoManager in OWL uses Node crypto; for browser demos this app uses browser-safe policy checks from A02.
- Replace mock providers and static demo tokens with production adapters and environment secrets.
