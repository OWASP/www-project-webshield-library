# Release Runbook

The commands to release a new version of OWL, in order. Run them in Git Bash from the repository
root. Each step lists what to expect; stop and fix anything that doesn't match before moving on.

**What gets released:** all six packages (`@owasp-webshield/core`, `react`, `vue`, `node`, `express`
and `next`) at the same version, from one `vX.Y.Z` tag, through
[`.github/workflows/release.yml`](../.github/workflows/release.yml). That workflow publishes them in
dependency order (core → react/vue/node → express/next), skips any package already on npm at that
version, and creates one GitHub release.

**Set the version once** for this shell session. Every command below uses it:

```bash
VERSION=X.Y.Z                 # e.g. 2.1.0; a prerelease such as 2.1.0-beta.1 is published under the npm "next" tag
RELEASE_DATE=$(date +%F)      # today, as YYYY-MM-DD
```

Pick the number with [Semantic Versioning](https://semver.org/): read the `## [Unreleased]` section of
[CHANGELOG.md](../CHANGELOG.md) first. Anything that can break an existing user is a **major** release.

---

## 0. One-time checks (on GitHub and npm)

- [ ] The repository secret `NPM_TOKEN` can publish to the `@owasp-webshield` scope, including any
      package that has never been published before.
- [ ] **Settings → Security → Dependency graph** is on. The dependency-review check on the PR needs it.
- [ ] Nobody else is merging into `main` while you release.

## 1. Create the release branch from `main`

```bash
git switch main
git pull origin main
git switch -c "release/v$VERSION"
```

## 2. Bump all six packages

```bash
npm version "$VERSION" --no-git-tag-version --workspaces --include-workspace-root
grep -h '"version"' package.json src/adapters/*/package.json
```

**Expect:** six lines, all `"version": "X.Y.Z"`, plus a changed `package-lock.json`. Only core and
the five adapters change; the example apps are private and keep their own versions. Leave the
adapters' `file:` dependencies as they are: the release workflow rewrites them to `^X.Y.Z` when
publishing.

## 3. Date the CHANGELOG

This adds `## [X.Y.Z] — YYYY-MM-DD` under `## [Unreleased]`, so the existing entries become this
version's section and an empty Unreleased section stays on top.

```bash
VERSION="$VERSION" RELEASE_DATE="$RELEASE_DATE" node -e "const fs=require('fs');const s=fs.readFileSync('CHANGELOG.md','utf8');if(!s.includes('## [Unreleased]'))throw new Error('no Unreleased section');fs.writeFileSync('CHANGELOG.md',s.replace('## [Unreleased]','## [Unreleased]\n\n## ['+process.env.VERSION+'] — '+process.env.RELEASE_DATE))"

node scripts/release/check-versions.mjs "$VERSION"
node scripts/release/changelog-section.mjs "$VERSION" | head
```

**Expect:** `All 6 packages are at X.Y.Z, and CHANGELOG.md has its section.`, then the start of the
release notes. Make sure every behaviour change is listed under **Changed**, with what users have to
do.

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
- `npm run check` passes: lint, all tests, typecheck.
- `test:coverage` meets the thresholds in `jest.config.js`.
- 0 broken links, and no high or critical vulnerabilities.
- `consumer-check` ends with `Release gate consumer check passed`.
- Each dry run shows `file:… -> ^X.Y.Z` for its dependencies. No package contains tests, and core contains no `dist/<adapter>` folders.

Optional: the example apps. They link the packages from this checkout and load core from `dist/`,
so run this after the `npm run build` above. Every app runs even if one fails, and the summary at the
end names the ones that failed:

```bash
failed=""
check() { echo "== $1: $2"; (cd "examples/$1" && npm ci --no-audit --no-fund && bash -c "$2") || failed="$failed $1"; }
check owl-enabled-node-secrets-app          "npm test"
check owl-enabled-vue-express-incident-desk "npm test && npm run build"
check owl-enabled-react-todo-app            "npm run build"
check owl-enabled-react-banking-dashboard   "npm run build"
check owl-enabled-nextjs-expense-portal     "npm test"
if [ -z "$failed" ]; then echo "All example apps passed."; else echo "FAILED:$failed"; false; fi
```

**Expect:** `All example apps passed.` These lines are expected and don't mean a failure:
- The React builds warn that `node:dns/promises` was externalized.
- The Next.js HTTP tests log `Invalid Server Actions request` twice, from a deliberately
  cross-origin call.

## 5. Commit the version bump and push

Add only these files. The build may leave line-ending-only changes in `.d.ts` files, and those
don't belong in this commit.

```bash
git add package.json package-lock.json src/adapters/*/package.json CHANGELOG.md
git commit -m "chore: release v$VERSION"
git push -u origin "release/v$VERSION"
```

## 6. Open the PR

On GitHub, open a pull request from `release/vX.Y.Z` into `main`. Before merging, wait for:

- [ ] **CI**: lint, typecheck, tests, build and pack on Node 20 and 22
- [ ] **Security**: CodeQL, dependency review and `npm audit`
- [ ] At least one maintainer approval

Merging doesn't publish anything; the tag in the next step does.

## 7. Tag `main` and release

```bash
git switch main
git pull origin main
node scripts/release/check-versions.mjs "$VERSION"

git tag -a "v$VERSION" -m "Release OWL $VERSION"
git push origin "v$VERSION"
```

The last `check-versions` runs on the exact commit you're about to tag. Then watch the run:

```bash
gh run list --workflow release.yml --limit 1
gh run watch $(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

**Expect:** `verify` → `core` → `react`/`vue`/`node` → `express`/`next` → `github-release`, all green.


## 8. Check what was published

```bash
for p in core react vue node express next; do echo "$p: $(npm view @owasp-webshield/$p@$VERSION version)"; done
gh release view "v$VERSION"
```

**Expect:** all six at `X.Y.Z`, and a `vX.Y.Z` release whose notes are the `[X.Y.Z]` CHANGELOG
section.

From an empty folder outside the repository:

```bash
mkdir owl-verify && cd owl-verify && npm init -y && npm pkg set type=module
npm install @owasp-webshield/core@$VERSION @owasp-webshield/react@$VERSION @owasp-webshield/vue@$VERSION \
  @owasp-webshield/express@$VERSION @owasp-webshield/next@$VERSION react react-dom vue express next
npm ls @owasp-webshield/node
node -e "import('@owasp-webshield/next').then(m => console.log(typeof m.withOwl))"
node -e "console.log(Object.keys(require('@owasp-webshield/core')).length, 'core exports (CommonJS)')"
cd .. && rm -rf owl-verify
```

**Expect:** `npm ls` shows `@owasp-webshield/node@X.Y.Z` from npm (not a `file:` path), then
`function`, then core's export count.

Also open each package's npm page and check for the provenance badge.

## 9. After the release

- [ ] **`docs/release-milestones.md`:** record the release, with npm links.
- [ ] **Docs site:** redeploy it if the docs changed.
- [ ] **Todo demo:** it redeploys automatically on the merge to `main`. Open it and check the browser
      console for CSP errors.
- [ ] **Security advisories:** if the release fixes a private advisory, set the patched version
      (`>= X.Y.Z`) and publish it.
- [ ] **Major release only:** update the supported versions in `SECURITY.md`, and point users of the
      previous major to the CHANGELOG's **Changed** section. Optionally, keep a maintenance branch
      for the previous major from its last release commit:

  ```bash
  git switch -c release/1.x <last-1.x-release-tag>   # e.g. core-v1.0.0, or v1.2.3 for later releases
  git push -u origin release/1.x
  ```



### If something fails here

```bash
# A publish job failed because of npm, the token or a registry delay: fix the cause, then re-run.
# Packages that already published are skipped.
gh run rerun $(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')

# "verify" failed: nothing was published. Delete the tag, fix through a PR, and tag again.
git tag -d "v$VERSION"
git push origin --delete "v$VERSION"

# A published version turns out to be broken: it can't be republished. Deprecate it and release
# the next patch version for all six.
NEXT=X.Y.Z+1   # the fixed version, e.g. 2.1.1
for p in core react vue node express next; do npm deprecate @owasp-webshield/$p@$VERSION "Broken release, use $NEXT"; done
```
