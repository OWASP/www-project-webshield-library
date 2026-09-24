# Todo App Live Demo Deployment (Netlify)

`examples/owl-enabled-react-todo-app` — the full-featured React app demonstrating every A01–A10
category with `@owasp-webshield/core` / `@owasp-webshield/react` — deploys via
[`.github/workflows/release-owl-todo-app.yml`](../.github/workflows/release-owl-todo-app.yml). It
triggers on push to `main` (path-filtered to files that affect this app) and on manual
`workflow_dispatch`: installs/builds the root `@owasp-webshield/core` package, installs/builds the
todo app, then deploys with:

```bash
npx netlify-cli deploy --prod --dir=dist
```

> **Do not add `--allow-anonymous` here.** It was tried once — it lets the deploy run without a
> Netlify account/site, but Netlify auto-deletes unclaimed anonymous deploys **1 hour** after
> creation, since nothing in CI ever logs in to claim them. Every anonymous run produces a dead link
> within the hour (this is what happened to `guileless-basbousa-a2bd63.netlify.app`). This workflow
> must stay pinned to a real, persistent site via the secrets below.

## One-time setup

1. Create the site once (from inside the app's folder, requires a one-time interactive Netlify
   login):
   ```bash
   cd examples/owl-enabled-react-todo-app
   npx netlify-cli sites:create   # creates a site but does NOT link it for git-integration auto-deploys
   ```
2. Add two repo secrets (GitHub → **Settings → Secrets and variables → Actions**):

   | Secret | Where to get it |
   |---|---|
   | `NETLIFY_AUTH_TOKEN` | Netlify → User settings → Applications → **New access token** (personal, not site-scoped) |
   | `NETLIFY_TODO_APP_SITE_ID` | Netlify → this site → **Site configuration → General → Site details → Site ID** |

Once both secrets exist, every qualifying push to `main` redeploys the **same** site, so the URL
stays stable. No other environment variables are needed — every provider used by the demo (the HTTP
client, the dependency-risk scanner) is backed by deterministic mocks, so the app runs fully offline.

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

- **"Deploy directory does not exist"** — the `npm run build` step in the workflow failed silently
  before producing `dist/`. Check the Actions log for the "Build todo app" step specifically.
- **Module not found for `@owasp-webshield/core`/`@owasp-webshield/react`** — the workflow's "Build
  core package" step (root `npm run build`) must succeed and run *before* "Install todo app" /
  "Build todo app", since the app depends on the root package's `dist/` output via monorepo-relative
  `file:` paths, not a registry install.
- **"Deploy not authorized" / 401 from the Deploy step** — `NETLIFY_AUTH_TOKEN` or
  `NETLIFY_TODO_APP_SITE_ID` is missing, wrong, or the token expired; re-check the repo secrets
  against the One-time setup steps above.
- **Live URL keeps changing or the site disappears after an hour** — the workflow has regressed to
  an anonymous deploy (`--allow-anonymous` re-added, or the `NETLIFY_SITE_ID`/`NETLIFY_AUTH_TOKEN`
  env vars removed from the Deploy step). Check the workflow file matches the command shown above.
