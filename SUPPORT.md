# Support

<p align="center">
  <a href="https://owasp.slack.com"><img src="https://img.shields.io/badge/chat-OWASP%20Slack-4A154B?logo=slack" alt="OWASP Slack" /></a>
  &nbsp;
  <a href="https://github.com/OWASP/www-project-webshield-library/issues"><img src="https://img.shields.io/github/issues/OWASP/www-project-webshield-library" alt="Open issues" /></a>
</p>

---

## Getting Help

| Need | Where to go |
|---|---|
| 📖 Usage questions | [README](README.md) and [docs/api-reference.md](docs/api-reference.md) |
| 🐛 Bug reports | [Open a GitHub issue](https://github.com/OWASP/www-project-webshield-library/issues/new) |
| 💬 Community discussion | [#project-webshield-library on OWASP Slack](https://owasp.slack.com) — [join here](https://owasp.org/slack/invite) |
| 🔒 Security vulnerabilities | **Do not open a public issue** — follow [SECURITY.md](SECURITY.md) |
| 🤝 Contributions | See [CONTRIBUTING.md](CONTRIBUTING.md) |

---

## Before Opening an Issue

Please do these steps first — they make triaging much faster:

**1. Confirm you are on the latest code**
```bash
git pull origin main
```

**2. Run the quality gate**
```bash
npm run check
```

**3. Include in your issue**

```
- OWL version (or commit SHA)
- Node.js version (`node -v`)
- Affected module: A01–A10 category or class name
- Minimal reproduction (fewest lines that trigger the issue)
- Actual behavior vs. expected behavior
- Relevant error output or stack trace
```

---

## Documentation Resources

| Resource | Description |
|---|---|
| [docs/api-reference.md](docs/api-reference.md) | Full API reference with copyable examples |
| [docs/framework.md](docs/framework.md) | Adoption patterns and bootstrap guide |
| [docs/architecture.md](docs/architecture.md) | Module layout and design decisions |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common issues and resolutions |
| [examples/](examples/) | Runnable core and React adapter examples |

---

## Maintainer Expectations

This project is maintained on a best-effort basis by the project leaders.
Response time depends on maintainer availability.
Well-formed issues with reproductions are resolved significantly faster.

---

*Project leaders: see [leaders.md](leaders.md)*
