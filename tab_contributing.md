---
title: Contributing
layout: null
tab: true
order: 3
tags: owasp javascript react security-library top10
---

## Contributing to OWL

<p align="center">
  <a href="https://github.com/OWASP/www-project-webshield-library/graphs/contributors">
    <img src="https://img.shields.io/github/contributors/OWASP/www-project-webshield-library" alt="Contributors" />
  </a>
  &nbsp;
  <a href="https://owasp.org/slack/invite">
    <img src="https://img.shields.io/badge/chat-OWASP%20Slack-4A154B?logo=slack" alt="OWASP Slack" />
  </a>
</p>

---

### Project Leader

| Name | Role | Contact |
|---|---|---|
| **Sreejith Sreekandan Nair** | OWL Project Leader | [cybersreejith@gmail.com](mailto:cybersreejith@gmail.com) |

---

### Ways to Contribute

| Type | How |
|---|---|
| 🐛 Bug fix | Open an issue first, then a focused PR |
| ✨ New security control | Discuss on Slack or open a feature issue first |
| 📖 Docs improvement | Direct PR welcome |
| 🧪 Additional tests | Always welcome — especially failure paths |
| 🔍 Security review | Review open PRs for security impact |

---

### Quickstart

```bash
# 1. Fork and clone
git clone https://github.com/<you>/www-project-webshield-library.git
cd www-project-webshield-library

# 2. Install dependencies
npm install

# 3. Verify gate passes before any changes
npm run check

# 4. Create a branch
git checkout -b feature/your-change

# 5. Keep gate green throughout development
npm run check

# 6. Open a pull request against main
```

---

### Pull Request Checklist

Before submitting, confirm all of the following:

- [ ] `npm run check` passes (lint + tests)
- [ ] Changes align with OWASP principles and project goals
- [ ] Existing behavior is not silently broken
- [ ] Tests cover new code including **failure and abuse paths**
- [ ] PR description includes: **what**, **why**, and **how to verify**
- [ ] Docs updated if the public API or any security default changes

---

### Testing Requirements

OWL enforces security-first testing. All contributions to core modules or adapter hooks must include:

| Scenario | Required? |
|---|---|
| Successful operation | ✅ |
| Invalid input or boundary conditions | ✅ |
| Security rejection path (deny, block, throw) | ✅ |
| Error code and metadata shape | ✅ for `SecurityError` throws |

```bash
npm run test
```

---

### Community

- [Join OWASP Slack](https://owasp.org/slack/invite)
- Channel: `#project-webshield-library`
- [OWASP Code of Conduct](https://owasp.org/www-policy/operational/code-of-conduct)
- [CODE_OF_CONDUCT.md](https://github.com/OWASP/www-project-webshield-library/blob/main/CODE_OF_CONDUCT.md)

---

### Security Reporting

> Do not open public issues for vulnerabilities.

Follow the private reporting process in [SECURITY.md](https://github.com/OWASP/www-project-webshield-library/blob/main/SECURITY.md).
