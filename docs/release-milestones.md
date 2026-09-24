# Release Milestones

A single timeline of what's queued for the next release and what shipped historically —
cross-referencing `CHANGELOG.md` (the authoritative record of *what* changed) against
git tags (*when* it was actually released).

## Shipped: 1.0.0 — first release as `@owasp-webshield/core` / `@owasp-webshield/react`

Full contents are in `CHANGELOG.md`'s `[1.0.0]` entry; in short:

- Full A01–A10 core API, including all the security-hardening work accumulated under
  the old name (SSRF fail-open/DNS-rebinding fixes, tokenizer-based sanitizer,
  cross-origin credential-leak protection, entropy estimation fix, logger cycle-DoS fix).
- React adapter with category-aligned providers/hooks/guards for A01–A10.
- `createOwlClient()` + `<OwlProvider>` — convenience wrappers collapsing manual manager
  wiring and 4-level provider nesting into one call/component each.
- Package-root browser bundling fixed for every export, including a same-shaped
  throwing stub for the genuinely-Node-only `CryptoManager`.

**Live on npm:**

- **Core:** [`@owasp-webshield/core@1.0.0`](https://www.npmjs.com/package/@owasp-webshield/core) — tag `core-v1.0.0`, published via `.github/workflows/release.yml`.
- **React adapter:** [`@owasp-webshield/react@1.0.0`](https://www.npmjs.com/package/@owasp-webshield/react) — tag `react-v1.0.0`, published via `.github/workflows/release-react-adapter.yml`, first-ever publish for this package.

### Still needs a manual one-time step

- **Live demo deployment (Netlify)** — `.github/workflows/release-owl-todo-app.yml` is ready and
  build-verified, but still needs the Netlify site created and `NETLIFY_AUTH_TOKEN` /
  `NETLIFY_TODO_APP_SITE_ID` repo secrets added (see `docs/todo-app-deployment.md`). An earlier
  attempt used `--allow-anonymous` to skip this step, but Netlify auto-deletes unclaimed anonymous
  deploys after 1 hour, so that path produced only dead links — reverted back to the authenticated
  setup. Add a "Try it live" badge to the root README once the secrets are in place and a deploy
  succeeds.

### Not yet started

- **TypeScript declaration files** — no `.d.ts` ships today despite `"typescript"` in `package.json` keywords.
- **Vue and Angular adapters** — named as goals in the original project roadmap; only the React adapter exists. Would become `@owasp-webshield/vue`/`@owasp-webshield/angular` under the current naming scheme.
- **A browser-safe package `.` root for real encryption** — today `CryptoManager` is a throwing stub in the browser build

- **A real, shipped CI security-gate GitHub Action** — `docs/github-actions-security-gate.md` currently documents a pattern, not a reusable action; `owl-enabled-node-secrets-app`'s `NpmAuditProvider` (a real `npm audit`-backed `DependencyRiskScanner` provider) is a candidate to upstream into the core package, since today `DependencyRiskScanner` ships with no built-in provider at all.
