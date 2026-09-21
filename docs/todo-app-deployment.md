# Todo App Live Demo Deployment (Netlify)

`examples/owl-enabled-react-todo-app` — the full-featured React app demonstrating every A01–A10
category with `@owasp-webshield/core` / `@owasp-webshield/react` — deploys to Netlify as an
**independent second site** alongside the docs site, sharing the same GitHub repo (see
`docs/docs-site-deployment.md` for the underlying "one repo, base-directory-scoped `netlify.toml`"
mechanism).

Build configuration lives in [`netlify.toml`](../examples/owl-enabled-react-todo-app/netlify.toml)
inside the app's own folder:

```toml
[build]
  command = "cd ../.. && npm ci && npm run build && cd examples/owl-enabled-react-todo-app && npm run build"
  publish = "dist"
```

The `command` rebuilds the root `@owasp-webshield/core` package (and the workspace-linked
`@owasp-webshield/react`) **before** building the app itself. This is necessary because:

- The app depends on both packages via monorepo-relative `file:` paths (`file:../..` and
  `file:../../src/adapters/react`), not real npm-registry installs.
- The root package's `dist/` output (which `@owasp-webshield/core`'s `exports` map points at) is
  gitignored, so a fresh checkout — like Netlify's — doesn't have it until something builds it.

`publish` resolves relative to **Base directory**, not the repo root — the same gotcha called out
in `docs/docs-site-deployment.md`.

## One-time setup

### Recommended: Netlify CLI (avoids the web UI's monorepo-detection gap)

Netlify's "Add new site → Import an existing project" web flow auto-detects deployable
sub-projects from the repo's **npm/yarn/pnpm workspaces declaration**, not by scanning for
`netlify.toml` files directly. This repo's root `package.json` only declares `src/adapters/react`
as a workspace (deliberately — see `[Unreleased]` in `CHANGELOG.md` for why the example apps stay
out of the workspaces array), so the web UI's "detected projects" list has no way to know
`examples/owl-enabled-react-todo-app` exists as a site, even though it has its own valid
`netlify.toml`. The CLI sidesteps this entirely by scoping to a directory instead of asking Netlify
to guess one:

```bash
npm install -g netlify-cli   # one-time, if not already installed
cd examples/owl-enabled-react-todo-app
netlify init
```

`netlify init` runs from *inside* the app's own folder, so there's no "select a project" ambiguity
— it treats this directory as the site root from the start:

1. It opens a browser to log in / authorize (first run only).
2. Choose **Create & configure a new site**, pick the team (e.g. `cybersreejith's team`), and give
   it a name (e.g. `owl-todo-demo`) — or leave blank for a random subdomain.
3. It detects and links the GitHub repo automatically and reads *this folder's* `netlify.toml` for
   build command (`cd ../.. && npm ci && npm run build && ...`) and publish directory (`dist`) —
   both already correct, no prompts needed for them.
4. It sets up the GitHub webhook for continuous deployment the same as the web flow would, so every
   push to `main` still triggers an automatic production deploy afterward.
5. To trigger the first deploy immediately instead of waiting for the next push:
   ```bash
   netlify deploy --prod
   ```

No environment variables are required — every provider used by the demo (the HTTP client, the
dependency-risk scanner) is backed by deterministic mocks, so the app runs fully offline.

### Alternative: web UI (needs one manual override)

If you'd rather use [netlify.com](https://www.netlify.com)'s **Add new site → Import an existing
project** flow directly: pick `OWASP/www-project-webshield-library`, let it create the site with
whatever default it detects (it won't offer this app as a distinct "project" — see above), then go
to **Project configuration → Build & deploy → Continuous deployment → Build settings → Edit
settings** and set **Base directory** to `examples/owl-enabled-react-todo-app` by hand. Save and
trigger a new deploy. This works fine, but the CLI path above avoids this extra step entirely.

Either way, once live:
- Optional: **Site configuration → General → Site details → Change site name** to pick a
  memorable subdomain (e.g. `owl-todo-demo.netlify.app`) instead of the random one.
- Add a "Try it live" badge or link to the live URL in the root `README.md` and in
  `examples/owl-enabled-react-todo-app/README.md`.

### Alternative: GitHub Actions-driven deploy (CI orchestrates it, not Netlify's git integration)

[`.github/workflows/release-owl-todo-app.yml`](../.github/workflows/release-owl-todo-app.yml) builds and
deploys via the Netlify CLI from CI, the same "deploy from GitHub Actions" pattern already used for
npm publishing (`release.yml`/`release-react-adapter.yml`). It triggers on push to `main` (path-
filtered to files that actually affect this app) and on manual `workflow_dispatch`.

**Prerequisite — create the Netlify site *without* Git-integration auto-deploys**, so builds aren't
triggered twice (once by Netlify's own git App, once by this workflow):

```bash
cd examples/owl-enabled-react-todo-app
netlify sites:create   # creates a site but does NOT link it to the repo for auto-deploys
```

Then add two repo secrets (Settings → Secrets and variables → Actions):

| Secret | Where to get it |
|---|---|
| `NETLIFY_AUTH_TOKEN` | Netlify → User settings → Applications → **New access token** (personal, not site-scoped) |
| `NETLIFY_TODO_APP_SITE_ID` | Netlify → this site → **Site configuration → General → Site details → Site ID** |

If you already linked the site to GitHub via `netlify init` or the web UI (enabling Netlify's own
continuous deployment), disable that instead of deleting the site: **Site configuration → Build &
deploy → Continuous deployment → Stop builds** — otherwise every push builds and deploys twice,
once via Netlify's own git trigger and once via this workflow.

Once both secrets exist, every qualifying push to `main` runs the workflow: installs and builds the
root `@owasp-webshield/core` package, installs and builds the todo app, then runs
`netlify-cli deploy --prod --dir=dist` from inside the app's folder. `workflow_dispatch` lets you
trigger a deploy manually from the Actions tab without a push.

## After setup

The behavior below applies if you used Netlify's own Git integration (CLI `netlify init` or the web
UI). If you instead used the GitHub Actions workflow above, deploys are path-filtered by the
workflow's `on.push.paths` instead, and there's no automatic PR deploy preview — only `main`-branch
production deploys and manual `workflow_dispatch` runs.

- Every push to `main` triggers a new production deploy automatically.
- Every pull request gets its own **deploy preview** URL, posted as a PR check/comment by the
  Netlify GitHub App.
- Since the app's `netlify.toml` doesn't set a `base`-scoped ignore rule, Netlify's default change
  detection may still trigger a rebuild on pushes that only touch unrelated files (e.g. `website/`
  docs changes) — this is a minor inefficiency, not a correctness issue; it just means occasional
  redundant builds.
- Optional: **Site configuration → Build & deploy → Stop builds** can pause auto-deploys
  temporarily if needed.
- Optional: **Site configuration → Domain management** to attach a custom domain instead of the
  default `*.netlify.app` one.

## Local development / pre-deploy sanity check

Reproduce exactly what Netlify's build command does, from the repo root:

```bash
npm ci && npm run build                          # builds @owasp-webshield/core's dist/
cd examples/owl-enabled-react-todo-app
npm install
npm run build                                    # vite build -> dist/
npm run preview                                  # serve the production build locally
```

If `npm run build` fails inside the example app with a module-resolution error pointing at
`@owasp-webshield/core` or `@owasp-webshield/react`, the most common cause is a stale or missing
root `dist/` — rerun `npm run build` at the repo root first.

## Troubleshooting

- **"Deploy directory does not exist"** — usually means `publish` in `netlify.toml` was set
  relative to the repo root instead of the base directory (see the gotcha above), or the build
  command failed silently before producing `dist/`. Check the build log for the root package's
  build step specifically.
- **Module not found for `@owasp-webshield/core`/`@owasp-webshield/react` during the Netlify
  build** — confirm **Base directory** is actually `examples/owl-enabled-react-todo-app` and not
  the repo root; the wrong base directory means Netlify never runs this app's `netlify.toml` or
  its `file:`-relative dependency paths at all.
- **Build succeeds but the deployed site is blank or shows a stale version** — hard-refresh
  (Netlify's CDN caches aggressively) or check that the deploy that finished is the one currently
  published (**Deploys** tab → confirm the latest one is marked "Published").
