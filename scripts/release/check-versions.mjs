// Fails unless every package is at the version being released (lockstep), the
// CHANGELOG has a section for it, and each package's local dependencies are
// listed earlier in the publish order.
//
//   node scripts/release/check-versions.mjs 2.0.0
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { PACKAGES, readManifest, ROOT } from "./packages.mjs";
import { changelogSection } from "./changelog-section.mjs";

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version || "")) {
  console.error(`Usage: check-versions.mjs <version>, got "${version ?? ""}"`);
  process.exit(1);
}

const problems = [];
const byDir = new Map(PACKAGES.map((pkg, index) => [resolve(ROOT, pkg.dir), { ...pkg, index }]));

PACKAGES.forEach((pkg, index) => {
  const manifest = readManifest(pkg.dir);
  if (manifest.version !== version) problems.push(`${manifest.name} is at ${manifest.version}, not ${version}`);
  for (const [name, spec] of Object.entries(manifest.dependencies || {})) {
    if (!spec.startsWith("file:")) continue;
    const dependency = byDir.get(resolve(ROOT, pkg.dir, spec.slice("file:".length)));
    if (!dependency) problems.push(`${manifest.name} depends on ${name} (${spec}), which isn't a published package`);
    else if (dependency.index >= index) problems.push(`${manifest.name} depends on ${name}, which is published after it`);
  }
});

if (!changelogSection(readFileSync(join(ROOT, "CHANGELOG.md"), "utf8"), version)) {
  problems.push(`CHANGELOG.md has no "## [${version}]" section`);
}

if (problems.length) {
  console.error(`Not ready to release ${version}:\n- ${problems.join("\n- ")}`);
  process.exit(1);
}
console.log(`All ${PACKAGES.length} packages are at ${version}, and CHANGELOG.md has its section.`);
