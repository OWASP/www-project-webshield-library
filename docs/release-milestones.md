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

## Next: 2.0.0

A major release: `CHANGELOG.md`'s `[Unreleased]` section already contains breaking changes
(the PBKDF2 default work factor, `useSecureHttpClient()` CSRF handling). All five packages ship
as `2.0.0`:

- **Core** and **React adapter:** the `[Unreleased]` fixes and changes.
- **Node server layer and Express adapter (first release):** `@owasp-webshield/node`
  (`src/adapters/node`) and `@owasp-webshield/express` (`src/adapters/express`). They come before
  Vue and Angular because most A01–A10 controls have to be enforced on the server, where a browser
  adapter can't.
- **Vue adapter (first release):** `@owasp-webshield/vue` (`src/adapters/vue`), the first of the
  two framework adapters named in the original roadmap.

Tag order: `core-v2.0.0`, then `react-v2.0.0`, `vue-v2.0.0` and `node-v2.0.0`, then `express-v2.0.0`. Each
adapter is published with a `^2.0.0` dependency on the package below it, so that package has to
be on npm first.

### Not yet started

- **TypeScript declaration files** — no `.d.ts` ships today despite `"typescript"` in `package.json` keywords.
- **Angular adapter** — named as a goal in the original project roadmap. Would become `@owasp-webshield/angular` under the current naming scheme. (The Vue adapter ships with 2.0.0.)
- **A browser-safe package `.` root for real encryption** — today `CryptoManager` is a throwing stub in the browser build

- **A real, shipped CI security-gate GitHub Action** — no reusable action exists yet; `owl-enabled-node-secrets-app`'s `NpmAuditProvider` (a real `npm audit`-backed `DependencyRiskScanner` provider) is a candidate to upstream into the core package, since today `DependencyRiskScanner` ships with no built-in provider at all.
