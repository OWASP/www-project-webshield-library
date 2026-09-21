# Deployment Recipes

Two audiences share this page: publishing/deploying **OWL itself** (this repo's packages and sites), and recipes for **apps built with OWL** (quality gates, environment profiles).

## Publishing OWL itself

### One-time prerequisite: claim the `@owasp-webshield` scope

Neither package has ever been published under this identity — this will be the **first-ever npm publish** for both `@owasp-webshield/core` and `@owasp-webshield/react`. Before the first release:

1. On [npmjs.com](https://www.npmjs.com), create the `owasp-webshield` organization (Avatar → **Add Organization** → free plan, unlimited public packages). You must be an owner/member before you can publish `@owasp-webshield/*` packages.
2. Generate an npm **Automation** access token scoped to that org (Account → Access Tokens), and add it as the `NPM_TOKEN` secret on the GitHub repo (Settings → Secrets and variables → Actions). Both release workflows read `secrets.NPM_TOKEN`.
3. `--provenance` (used by both workflows) requires the publish to run from GitHub Actions with `id-token: write` permission — already set in both workflow files — and npm CLI ≥ 9.5, which `actions/setup-node@v5` with `node-version: 22` satisfies.

### npm — `@owasp-webshield/core` (core)

Automated via [`.github/workflows/release.yml`](../.github/workflows/release.yml): push a `v*.*.*` tag matching the root `package.json` version, and the workflow validates the tag, runs `npm run check`, builds, and publishes with `--access public --provenance`.

```bash
npm version patch   # or minor/major — bumps package.json, commits, tags
git push --follow-tags
```

The workflow's own "Validate tag matches package version" step will hard-fail the release if the tag and `package.json` version ever drift — this has bitten the project before: an orphaned `v2.0.0` tag exists in the repo today (`git tag` lists it) whose commit's `package.json` never actually said `2.0.0`, so that push almost certainly failed this exact check and was never published (under the package's previous identity). Don't work around this gate; fix the version mismatch instead.

For the very first release, `package.json` is already at `1.0.0`, so just tag and push:

```bash
git tag v1.0.0
git push --follow-tags
```

### npm — `@owasp-webshield/react` (adapter)

Same pattern, separate workflow ([`.github/workflows/release-react-adapter.yml`](../.github/workflows/release-react-adapter.yml)) and its own tag prefix, since the adapter versions independently from core. **Use `--no-git-tag-version`** — plain `npm version patch` would auto-tag with the default `v*.*.*` prefix, colliding with the root package's own tag namespace in the same repo:

```bash
cd src/adapters/react
npm version patch --no-git-tag-version
cd ../../..
git add src/adapters/react/package.json
git commit -m "Bump @owasp-webshield/react to $(node -p "require('./src/adapters/react/package.json').version")"
git tag "owl-react-v$(node -p "require('./src/adapters/react/package.json').version")"
git push --follow-tags
```

For the very first release, `src/adapters/react/package.json` is already at `1.0.0`, so skip the `npm version` step and just tag and push:

```bash
git tag owl-react-v1.0.0
git push --follow-tags
```

`src/adapters/react/package.json`'s dependency on the core package is `file:../../..` (needed for reliable local monorepo installs — see the `[Unreleased]` `CHANGELOG.md` entry on the npm-workspaces self-link gotcha), and the release workflow rewrites it to a real semver range (`^<core-version>`) only inside the CI checkout, right before publishing. That means **a local `npm publish --dry-run` here will show the `file:` path in the packed tarball**, not the real dependency — that's expected and only reflects what's in the working tree, not what actually gets published. Use it to sanity-check the file list/size, not the dependency line.

Publish core **before** the adapter at least once, so the adapter's rewritten dependency range (`^1.0.0`) resolves to a version that actually exists on the registry.

### Netlify — two independent sites, one repo

Both sites point at this same GitHub repo, distinguished entirely by each site's **Base directory** setting, which determines which subdirectory's `netlify.toml` Netlify reads (see `docs/docs-site-deployment.md` for the underlying mechanism and the "publish resolves relative to base, not repo root" gotcha).

| Site | Base directory | Config | Deploys |
|---|---|---|---|
| Docs | *(repo root)* | `netlify.toml` | VitePress site (`website/`) |
| Todo app demo | `examples/owl-enabled-react-todo-app` | `examples/owl-enabled-react-todo-app/netlify.toml` | `owl-enabled-react-todo-app`'s `dist/` |

Full one-time setup steps for each: `docs/docs-site-deployment.md` (docs site) and `examples/owl-enabled-react-todo-app/README.md` → "Deploying a live demo" (Todo app). Both auto-deploy on every push to `main` once connected; no manual redeploy step.

### Release checklist (this repo)

1. `npm run check` and `npm run build` pass locally.
2. `CHANGELOG.md` has an entry for what's shipping — don't just bump the version number (this has happened before; see the `1.0.4` note in the changelog, from the package's previous identity).
3. First release only: confirm the `@owasp-webshield` org/scope is claimed on npm and `NPM_TOKEN` is set on the repo (see the prerequisite section above).
4. Tag and push per the npm sections above — root and adapter are released independently, so only bump/tag the one that actually changed. On the first release, publish core before the adapter.
5. Confirm the GitHub Release was created with the right notes, and that the npm page shows the new version.
6. For security-relevant fixes, follow `SECURITY.md`'s disclosure process (advisory, credit, coordinated timing) rather than just shipping silently.

## Recipes for apps built with OWL

### 1. Local quality gate

```bash
npm install
npm run check
npm run build
```

### 2. Environment profile recommendations

- Development:
  - verbose logging allowed
  - mock tokens only in local environments
- Staging:
  - production-like auth and SSRF policy enabled
  - strict config validation
- Production:
  - secure cookies and strict same-site policy
  - no debug flags
  - startup hardening report gate enabled

### 3. Release checklist (consumer apps)

1. Run lint/test/build.
2. Update your own CHANGELOG.
3. Tag release and publish artifacts.
4. Announce security-impacting changes in release notes.
