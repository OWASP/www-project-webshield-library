# Docs Site Deployment (Netlify)

The VitePress documentation site lives in `website/` and deploys to Netlify — **not** GitHub Pages, because this repo's GitHub Pages slot is already used by the required OWASP Foundation project page (Jekyll, built from `index.md`/`_config.yml` at the repo root via `remote_theme: owasp/www--site-theme`). Only one source can serve GitHub Pages at a time, so the docs site is hosted separately to avoid any conflict.

Build configuration lives in [`netlify.toml`](../netlify.toml) at the repo root:

```toml
[build]
  base = "website"
  command = "npm run build"
  publish = ".vitepress/dist"
```

`publish` is resolved relative to `base`, not the repo root — a common Netlify gotcha (setting it to `website/.vitepress/dist` here would double up to `website/website/.vitepress/dist` and fail with "Deploy directory does not exist").

## One-time setup

1. Go to [netlify.com](https://www.netlify.com) and sign in (GitHub login is simplest).
2. Click **Add new site → Import an existing project**.
3. Choose **GitHub** as the Git provider. If this is the first time connecting anything from the `OWASP` GitHub org, Netlify's GitHub App may need an org owner to approve access to this specific repository — you'll be prompted if so.
4. Select `OWASP/www-project-webshield-library` from the repo list.
5. Netlify reads `netlify.toml` from the repo root automatically, so the **Base directory**, **Build command**, and **Publish directory** fields should already show `website`, `npm run build`, and `.vitepress/dist` respectively — no manual entry needed. Double-check they match before deploying.
6. No environment variables are required.
7. Click **Deploy site**. Netlify streams the build log live (~1–2 minutes).
8. Once it finishes, Netlify gives you a live URL on a random subdomain (e.g. `https://random-name-123abc.netlify.app`). Click through a few pages to confirm it matches what `npm run build` produces locally.
9. Optional: **Site configuration → General → Site details → Change site name** to pick a memorable subdomain (e.g. `owl-docs.netlify.app`) instead of the random one.

## After setup

- Every push to `main` triggers a new production deploy automatically.
- Every pull request gets its own **deploy preview** URL, posted as a PR check/comment by the Netlify GitHub App.
- Optional: **Site configuration → Build & deploy → Stop builds** can pause auto-deploys temporarily if needed.
- Optional: **Site configuration → Domain management** to attach a custom domain instead of the default `*.netlify.app` one.
- Since `netlify.toml` sets `base = "website"`, Netlify only rebuilds when files under `website/` (or the repo's dependency lockfiles) change — pushes that only touch the library source don't trigger a docs rebuild.

## Local development

```bash
cd website
npm install
npm run dev       # http://localhost:5173
npm run build     # outputs to .vitepress/dist
npm run preview   # serve the production build locally
```

## A second Netlify site: the live Todo app demo

The same repo also deploys `examples/owl-enabled-react-todo-app` as an **independent second Netlify site** — same "one repo, base-directory-scoped `netlify.toml`" pattern as above, just with a different base directory (`examples/owl-enabled-react-todo-app` instead of `website`) and its own `netlify.toml` living in that folder instead of the repo root. See `docs/todo-app-deployment.md` for the full setup walkthrough.
