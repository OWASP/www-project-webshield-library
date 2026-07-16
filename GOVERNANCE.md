# Project Governance

<p align="center">
  <a href="https://owasp.org/projects/"><img src="https://img.shields.io/badge/owasp-lab%20project-blue" alt="OWASP Lab Project" /></a>
</p>

---

## Project Roles

| Role | Responsibilities |
|---|---|
| **Project Leader** | Sets direction, approves major changes, manages releases, represents the project to OWASP |
| **Maintainer** | Reviews and merges PRs, triages issues, enforces coding and security standards |
| **Contributor** | Opens issues, submits pull requests, improves docs and tests |

See [leaders.md](leaders.md) for the current project leadership.

---

## Decision Making

| Change Type | Process |
|---|---|
| Bug fix or docs update | Single maintainer review and merge |
| New API surface or behavioral change | Two maintainer approvals recommended |
| Security-impacting change | Project Leader approval required; OWASP alignment checked |
| Breaking change | Documented in CHANGELOG; deprecation notice preferred before removal |

**Guiding principle:** security and user safety take precedence over convenience in all decisions.

---

## Release Process

```
1. Feature PRs merged to main
2. CHANGELOG updated with all notable changes
3. npm run check passes on clean checkout
4. Version bumped in package.json following semver
5. Git tag created (e.g. v1.1.0)
6. GitHub Release published with notes
7. npm package published (provenance enabled)
```

### Versioning Policy

OWL follows [Semantic Versioning](https://semver.org/):

- **Patch** — bug fixes, test additions, non-breaking doc updates
- **Minor** — new exports, new optional parameters, non-breaking behavior additions
- **Major** — breaking public API changes, removed exports, behavior changes that affect security semantics

---

## Security Governance

- Security vulnerabilities are handled via the private process in [SECURITY.md](SECURITY.md).
- All patches for security vulnerabilities include regression tests.
- Security-impacting API changes are documented in CHANGELOG under the `Security` section.
- OWL modules ship with secure defaults; any default change requires Project Leader sign-off.

---

## Community Standards

All project spaces are governed by the [OWASP Code of Conduct](https://owasp.org/www-policy/operational/code-of-conduct) and this project's [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

*Questions about governance? Reach out on OWASP Slack or open a discussion.*
