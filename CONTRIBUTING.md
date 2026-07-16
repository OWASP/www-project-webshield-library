# Contributing to OWASP Web Shield Library

<p align="center">
  <a href="https://github.com/OWASP/www-project-webshield-library/graphs/contributors"><img src="https://img.shields.io/github/contributors/OWASP/www-project-webshield-library" alt="Contributors" /></a>
  &nbsp;
  <a href="https://owasp.org/slack/invite"><img src="https://img.shields.io/badge/chat-OWASP%20Slack-4A154B?logo=slack" alt="OWASP Slack" /></a>
</p>

Thank you for contributing to OWL. Security-focused open source only improves when practitioners collaborate — your work matters.

---

## Contents

- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Testing Requirements](#testing-requirements)
- [Adding a New OWASP Module](#adding-a-new-owasp-module)
- [Code of Conduct](#code-of-conduct)
- [Security Reporting](#security-reporting)

---

## Ways to Contribute

| Type | How |
|---|---|
| 🐛 Bug fix | Open an issue first, then a focused PR |
| ✨ New security control | Discuss on Slack or open a feature issue first |
| 📖 Docs improvement | Direct PR is welcome |
| 🧪 Additional test coverage | Always welcome |
| 🔍 Security review | Review open PRs for security impact |
| 💡 Design feedback | Comment on open issues and RFCs |

---

## Getting Started

**1. Join the OWASP community**

```
https://owasp.org/slack/invite
```
Look for `#project-webshield-library`.

**2. Fork and clone**

```bash
git clone https://github.com/<your-username>/www-project-webshield-library.git
cd www-project-webshield-library
```

**3. Install and verify**

```bash
npm install
npm run check
```

The gate must pass before any changes begin.

---

## Development Workflow

```
main
 └── feature/<short-description>     ← your branch
     └── PR → main (after review)
```

1. Create a branch from `main`
2. Make focused, atomic commits
3. Keep `npm run check` green at every commit
4. Open a pull request against `main`

---

## Pull Request Guidelines

Before submitting, confirm all of the following:

- [ ] `npm run check` passes (lint + tests)
- [ ] Changes align with OWASP principles and project goals
- [ ] Existing behavior is not silently changed or broken
- [ ] Tests cover new code, including failure and abuse paths
- [ ] PR description explains: **what**, **why**, and **how to test**
- [ ] Docs are updated if the public API or behavior changes

---

## Testing Requirements

OWL enforces security-first testing. Every contribution to a core module or adapter must include:

| Scenario | Required |
|---|---|
| Successful operation (happy path) | ✅ |
| Invalid input / boundary conditions | ✅ |
| Security rejection path (deny, block, throw) | ✅ |
| Error metadata shape (`code`, `details`) | ✅ for `SecurityError` throws |

Run tests:

```bash
npm run test
```

Add test files alongside the module under `src/__tests__/core/` or `src/__tests__/adapter/`.

---

## Adding a New OWASP Module

If you are adding an entirely new `aXX` category module:

1. Create `src/core/aXX-name/` with focused classes and an `index.js`
2. Export from `src/core/index.js`
3. Add tests in `src/__tests__/core/aXX-name.test.js` (success + failure paths)
4. Create a matching React adapter under `src/adapters/react/aXX-name/`
5. Export the adapter from `src/adapters/react/index.js`
6. Add adapter tests in `src/__tests__/adapter/`
7. Document the API in `docs/api-reference.md`
8. Add a usage example in `examples/`

---

## Code of Conduct

All contributors must follow the [OWASP Code of Conduct](https://owasp.org/www-policy/operational/code-of-conduct). See also [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## Security Reporting

Do **not** open public issues for vulnerabilities. Follow the private reporting process described in [SECURITY.md](SECURITY.md).

---

*OWL — making security controls as natural as any other dependency.*