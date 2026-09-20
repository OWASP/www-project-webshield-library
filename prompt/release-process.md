# Release Process

This document covers every step required to ship a new version of `@owasp-core/owl`.

---

## Quick steps

```bash
npm run check   # lint + tests, must be green
npm run build   # generate dist/index.js and dist/index.cjs
npm publish --access public
```

---

## Step 1 — Run the quality gate locally

```bash
npm run check
```

This runs **lint + all 63 tests**. Must be fully green before proceeding.

---

## Step 2 — Build the distribution outputs

```bash
npm run build
```

Generates `dist/index.js` (ESM) and `dist/index.cjs` (CJS) via esbuild. These are what gets published to npm.

---

## Step 3 — Verify the package contents

```bash
npm pack --dry-run
```

Confirm the output shows **exactly these 7 files** and nothing more:

```
CHANGELOG.md
LICENSE.md
README.md
SECURITY.md
dist/index.cjs
dist/index.js
package.json
```

If unexpected files appear, check the `"files"` array in `package.json`.

---

## Step 4 — Update the CHANGELOG

Open `CHANGELOG.md` and add a new section at the top of the entries:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- ...

### Changed
- ...

### Security
- ...
```

Replace `X.Y.Z` with the new version and `YYYY-MM-DD` with today's date.

---

## Step 5 — Bump the version in package.json

```bash
# For a patch release (bug fixes only)
npm version patch --no-git-tag-version

# For a minor release (new backwards-compatible features)
npm version minor --no-git-tag-version

# For a major release (breaking changes)
npm version major --no-git-tag-version
```

The `--no-git-tag-version` flag updates `package.json` only — the git tag is created manually in Step 8.

---

## Step 6 — Commit the release preparation

```bash
git add CHANGELOG.md package.json
git commit -m "chore: release vX.Y.Z"
```




---

## Step 7 — Push and open a Pull Request to `main`

```bash
git push origin <your-branch>
```

Open a PR from your feature branch into `main` on GitHub. The CI workflow ([.github/workflows/ci.yml](../.github/workflows/ci.yml)) will automatically run lint, test, build, and a pack dry-run on Node 20 and 22.

Wait for CI to pass and get at least one maintainer approval before merging.

---

## Step 8 — After merge: tag `main` as the release version

```bash
git checkout main
git pull origin main

# Create an annotated tag (replace X.Y.Z with the actual version)
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git tag -a v2.0.1 -m "Release v2.0.1"

# Push the tag — this triggers the release workflow
git push origin vX.Y.Z
```


For eg:


git tag -d v1.0.3 ( To delete a tag )
git push origin --delete v1.0.3


-----------------

git tag -a v1.0.4 -m "Release v1.0.4"
git push origin v1.0.4



The release workflow ([.github/workflows/release.yml](../.github/workflows/release.yml)) will:

1. Validate that the tag version matches `package.json`
2. Run `npm run check` (lint + tests)
3. Run `npm run build`
4. Publish `@owasp-core/owl@X.Y.Z` to npm with provenance
5. Create a GitHub Release with the CHANGELOG as the release body

---

## Step 9 — Verify the release

```bash
# Check the package is live on npm
npm view @owasp-core/owl version

# Confirm the published file list
npm view @owasp-core/owl dist-tags
```

Also verify on GitHub that the Release was created under:
```
https://github.com/OWASP/www-project-webshield-library/releases
```

---

## Hotfix releases (patch on `main` directly)

For urgent security fixes:

```bash
git checkout main
git pull origin main
git checkout -b hotfix/vX.Y.Z

# Make the fix, add tests, update CHANGELOG
npm run check

git add .
git commit -m "fix: <description> (vX.Y.Z)"
git push origin hotfix/vX.Y.Z

# Open PR → main, get approval, merge, then tag as above
```

---

## Rollback a bad release

npm does not allow deleting published versions, but you can deprecate one:

```bash
npm deprecate @owasp-core/owl@X.Y.Z "Critical bug — use X.Y.Z+1 instead"
```

Then release the fix as a patch version immediately.

---

## NPM_TOKEN setup (one-time)

0. **Create the `owasp-core` npm organization first**, if it doesn't already exist: [npmjs.com](https://www.npmjs.com) → Avatar → **Add Organization** → name it `owasp-core` → free plan (unlimited public packages). You must be an owner/member of this org before you can publish `@owasp-core/*` packages.
1. Log in to [npmjs.com](https://www.npmjs.com) → Avatar → **Access Tokens**
2. **Generate New Token** → **Granular Access Token**
   - Name: `owasp-core-github-actions`
   - Permission: **Read and write**
   - Under "Select packages and scopes", pick the **Scopes** tab (not "Packages") and select `@owasp-core` — a package-level scope can't be selected for a package that hasn't been published yet, which is why this must be scoped to the whole org/scope for the very first publish of any new package under it.
3. Copy the token
4. In the GitHub repo: **Settings → Secrets and variables → Actions → New repository secret**
   - Name: `NPM_TOKEN`
   - Value: the token you copied

---

## Quick reference

```bash
# Full local release validation
npm run check && npm run build && npm pack --dry-run

# After PR merged to main
git checkout main && git pull origin main
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

---

*See [CHANGELOG.md](../CHANGELOG.md) for the full release history.*
