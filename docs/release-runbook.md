# v2.0.0 Release Runbook

The commands to release OWL 2.0.0, in order, from the state of `release/v2.0.0` on 2026-10-04.
Run them in Git Bash from the repository root. Each step lists what to expect; stop and fix
anything that doesn't match before moving on.

**Starting point:** `release/v2.0.0` is pushed and 5 commits ahead of `main`. The single-tag
release workflow and the release scripts are committed (`eb0594e`), no PR is open yet, and all six
packages are still at `1.0.0`.

**What gets released:** `@owasp-webshield/core`, `react`, `vue`, `node`, `express` and `next`, all
as `2.0.0`, from one tag (`v2.0.0`) through
[`.github/workflows/release.yml`](../.github/workflows/release.yml). See
[the release process](./release-process.md) for how the workflow works, and
[the release gate](./release-v2.0.0-gate.md) for what each check proves.

---

## 0. One-time checks (on GitHub and npm)

- [ ] The repository secret `NPM_TOKEN` can publish to the `@owasp-webshield` scope, including the
      four packages that have never been published: `vue`, `node`, `express` and `next`.
- [ ] **Settings → Security → Dependency graph** is on. The dependency-review check on the PR needs it.
- [ ] Nobody else is merging into `main` while you release.

## 1. Start from the release branch

```bash
git switch release/v2.0.0
git pull origin release/v2.0.0
```

Optional: commit the release docs, which are still untracked:

```bash
git add docs/release-process.md docs/release-v2.0.0-checklist.md docs/release-v2.0.0-gate.md docs/release-v2.0.0-runbook.md
git commit -m "docs: v2.0.0 release process, checklist, gate and runbook"
```

## 2. Bump all six packages to 2.0.0

```bash
npm version 2.0.0 --no-git-tag-version --workspaces --include-workspace-root
grep -h '"version"' package.json src/adapters/*/package.json
```

**Expect:** six lines, all `"version": "2.0.0"`, plus a changed `package-lock.json`. Leave the
adapters' `file:` dependencies as they are: the release workflow rewrites them to `^2.0.0` when
publishing.

## 3. Date the CHANGELOG

This adds `## [2.0.0] — 2026-10-04` under `## [Unreleased]`, so the existing entries become the
2.0.0 section and an empty Unreleased section stays on top. Change the date if you release on
another day.

```bash
node -e "const fs=require('fs');const s=fs.readFileSync('CHANGELOG.md','utf8');if(!s.includes('## [Unreleased]'))throw new Error('no Unreleased section');fs.writeFileSync('CHANGELOG.md',s.replace('## [Unreleased]','## [Unreleased]\n\n## [2.0.0] — 2026-10-04'))"

node scripts/release/check-versions.mjs 2.0.0
node scripts/release/changelog-section.mjs 2.0.0 | head
```

**Expect:** `All 6 packages are at 2.0.0, and CHANGELOG.md has its section.`, then the start of the
release notes (`### Added` ...).

## 4. Run the release gate locally

```bash
npm ci
npm run check
npm run test:coverage
npm run build
npm run lint:docs
npm audit --audit-level=high
node scripts/release-gate/consumer-check.mjs
for p in core react vue node express next; do node scripts/release/publish-package.mjs $p --dry-run; done
```

**Expect:**
- 327 tests pass, and the coverage thresholds are met.
- 0 broken links, and 0 vulnerabilities.
- `consumer-check` ends with `Release gate consumer check passed`.
- Each dry run shows `file:… -> ^2.0.0` for its dependencies, with these file counts: core 102, react 35, vue 29, node 25, express 8, next 19.

Optional: the example apps (Gate 5):

```bash
(cd examples/owl-enabled-node-secrets-app && npm ci && npm test)
(cd examples/owl-enabled-vue-express-incident-desk && npm ci && npm test && npm run build)
(cd examples/owl-enabled-react-todo-app && npm ci && npm run build)
(cd examples/owl-enabled-react-banking-dashboard && npm ci && npm run build)
(cd examples/owl-enabled-nextjs-expense-portal && npm ci && npm test)
```

**Expect:** 9, 23 and 24 + 24 tests pass, and every build succeeds.

## 5. Commit the version bump and push

Add only these files. The build may leave line-ending-only changes in `.d.ts` files, and those
don't belong in this commit.

```bash
git add package.json package-lock.json src/adapters/*/package.json CHANGELOG.md
git commit -m "chore: release v2.0.0"
git push origin release/v2.0.0
```

## 6. Open the PR, wait for checks, merge

```bash
gh pr create --base main --head release/v2.0.0 --title "Release v2.0.0" \
  --body "Release v2.0.0: core, react, vue, node, express and next. See CHANGELOG.md [2.0.0]."
gh pr checks --watch
```

**Expect:** CI (lint, typecheck, tests, build and pack on Node 20 and 22) and Security (CodeQL,
dependency review, `npm audit`) green. Then, after a maintainer approves:

```bash
gh pr merge release/v2.0.0 --merge
```

## 7. Tag `main` and release

```bash
git switch main
git pull origin main
node scripts/release/check-versions.mjs 2.0.0

git tag -a v2.0.0 -m "Release OWL 2.0.0"
git push origin v2.0.0
```

The last `check-versions` runs on the exact commit you're about to tag. Then watch the run:

```bash
gh run list --workflow release.yml --limit 1
gh run watch $(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

**Expect:** `verify` → `core` → `react`/`vue`/`node` → `express`/`next` → `github-release`, all green.

### If something fails here

```bash
# A publish job failed because of npm, the token or a registry delay: fix the cause, then re-run.
# Packages that already published are skipped.
gh run rerun $(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')

# "verify" failed: nothing was published. Delete the tag, fix through a PR, and tag again.
git tag -d v2.0.0
git push origin --delete v2.0.0

# A published version turns out to be broken: it can't be republished, so release 2.0.1 instead.
for p in core react vue node express next; do npm deprecate @owasp-webshield/$p@2.0.0 "Broken release, use 2.0.1"; done
```

## 8. Check what was published

```bash
for p in core react vue node express next; do echo "$p: $(npm view @owasp-webshield/$p version)"; done
gh release view v2.0.0
```

**Expect:** all six at `2.0.0`, and a `v2.0.0` release whose notes are the `[2.0.0]` CHANGELOG
section.

From an empty folder outside the repository:

```bash
mkdir owl-verify && cd owl-verify && npm init -y && npm pkg set type=module
npm install @owasp-webshield/core@2.0.0 @owasp-webshield/react@2.0.0 @owasp-webshield/vue@2.0.0 \
  @owasp-webshield/express@2.0.0 @owasp-webshield/next@2.0.0 react react-dom vue express next
npm ls @owasp-webshield/node
node -e "import('@owasp-webshield/next').then(m => console.log(typeof m.withOwl))"
node -e "console.log(Object.keys(require('@owasp-webshield/core')).length, 'core exports (CommonJS)')"
cd .. && rm -rf owl-verify
```

**Expect:** `npm ls` shows `@owasp-webshield/node@2.0.0` from npm (not a `file:` path), then
`function`, then `32 core exports (CommonJS)`.

Also open each package's npm page and check for the provenance badge.

## 9. After the release

- [ ] **`SECURITY.md`:** give the actual end date for 1.x support.
- [ ] **`docs/release-milestones.md`:** move "Next: 2.0.0" under "Shipped", with npm links.
- [ ] **Docs site:** redeploy so the Vue, Node & Express and Next.js pages go live.
- [ ] **Todo demo:** it redeploys automatically on the merge to `main`. Open it and check the browser
      console for CSP errors.
- [ ] **Security advisories:** if the release fixes a private advisory, set the patched version
      (`>= 2.0.0`) and publish it.
- [ ] Optional: a 1.x maintenance branch from the 1.0.0 release:

  ```bash
  git switch -c release/1.x core-v1.0.0
  git push -u origin release/1.x
  ```
