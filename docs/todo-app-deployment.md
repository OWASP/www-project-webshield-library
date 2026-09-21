# Todo App Live Demo Deployment (Netlify)

`examples/owl-enabled-react-todo-app` — the full-featured React app demonstrating every A01–A10
category with `@owasp-webshield/core` / `@owasp-webshield/react` — deploys via
[`.github/workflows/release-owl-todo-app.yml`](../.github/workflows/release-owl-todo-app.yml). It
triggers on push to `main` (path-filtered to files that affect this app) and on manual
`workflow_dispatch`: installs/builds the root `@owasp-webshield/core` package, installs/builds the
todo app, then deploys with:

```bash
npx netlify-cli deploy --prod --dir=dist --allow-anonymous
```

`--allow-anonymous` means this runs **without** a `NETLIFY_AUTH_TOKEN` or a linked site — no repo
secrets, no Netlify account tie-in required. No environment variables are needed either way — every
provider used by the demo (the HTTP client, the dependency-risk scanner) is backed by deterministic
mocks, so the app runs fully offline.

This convenience comes with a real caveat:

> **The live URL changes on every deploy.** Since no site ID is passed and nothing persists a site
> link between CI runs, each run creates a **brand-new random anonymous Netlify site** (e.g.
> `stunning-cat-488373.netlify.app` one run, `guileless-basbousa-a2bd63.netlify.app` the next).
> There is no stable "the todo app demo" URL under this setup — any link posted in the README/docs
> will go stale the next time `main` is pushed and the workflow runs again.

If a stable URL is ever needed (e.g. for a permanent README badge), create the site once with
`netlify sites:create`, add `NETLIFY_AUTH_TOKEN` (personal access token) and
`NETLIFY_TODO_APP_SITE_ID` (that site's Site ID) as repo secrets, and drop `--allow-anonymous` from
the workflow in favor of passing those as `env:` on the deploy step so every run redeploys the same
site instead of creating a new one.

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
- **Can't find the live URL** — it's printed at the end of the "Deploy to Netlify" step's log in the
  Actions run (look for the `Website URL` line); it isn't posted anywhere else since there's no
  linked site or PR-comment integration in the anonymous-deploy setup.
