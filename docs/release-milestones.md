# Release Milestones

A single timeline of what's queued for the next release and what shipped historically —
cross-referencing `CHANGELOG.md` (the authoritative record of *what* changed) against
git tags (*when* it was actually released).

## Upcoming: 1.0.0 — first release as `@owasp-webshield/core` / `@owasp-webshield/react`

Full contents are in `CHANGELOG.md`'s `[1.0.0]` entry; in short:

- Full A01–A10 core API, including all the security-hardening work accumulated under
  the old name (SSRF fail-open/DNS-rebinding fixes, tokenizer-based sanitizer,
  cross-origin credential-leak protection, entropy estimation fix, logger cycle-DoS fix).
- React adapter with category-aligned providers/hooks/guards for A01–A10.
- `createOwlClient()` + `<OwlProvider>` — convenience wrappers collapsing manual manager
  wiring and 4-level provider nesting into one call/component each.
- Package-root browser bundling fixed for every export, including a same-shaped
  throwing stub for the genuinely-Node-only `CryptoManager`.

**Ready to ship, pending the actual tag pushes:**

- **Core:** `git tag -a core-v1.0.0 -m "core-v1.0.0" && git push --follow-tags` (root `package.json` is already at `1.0.0`).
- **React adapter:** `git tag -a react-v1.0.0 -m "react-v1.0.0" && git push --follow-tags` (first-ever publish for this package — infra ready: `.github/workflows/release-react-adapter.yml`, `publishConfig`/`license`/`repository` metadata, its own README). Publish core first — the adapter's dependency range only resolves once core is live on the registry. See `docs/deployment-recipes.md` → "Publishing OWL itself" for the full command sequence for each, including the one-time `@owasp-webshield` npm org setup.

### Also ready, needs a manual one-time step

- **Live demo deployment (Netlify)** — `examples/owl-enabled-react-todo-app/netlify.toml` is ready and build-verified; needs a Netlify site created with **Base directory** = `examples/owl-enabled-react-todo-app` (see that example's README → "Deploying a live demo"). Add a "Try it live" badge to the root README once it's up.

### Not yet started

- **TypeScript declaration files** — no `.d.ts` ships today despite `"typescript"` in `package.json` keywords.
- **Vue and Angular adapters** — named as goals in the original project roadmap; only the React adapter exists. Would become `@owasp-webshield/vue`/`@owasp-webshield/angular` under the current naming scheme.
- **A browser-safe package `.` root for real encryption** — today `CryptoManager` is a throwing stub in the browser build

- **A real, shipped CI security-gate GitHub Action** — `docs/github-actions-security-gate.md` currently documents a pattern, not a reusable action; `owl-enabled-node-secrets-app`'s `NpmAuditProvider` (a real `npm audit`-backed `DependencyRiskScanner` provider) is a candidate to upstream into the core package, since today `DependencyRiskScanner` ships with no built-in provider at all.
