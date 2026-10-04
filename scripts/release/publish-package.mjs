// Publishes one package of the release, safely re-runnable:
//
//   node scripts/release/publish-package.mjs <id>             # core, react, vue, node, express, next
//   node scripts/release/publish-package.mjs <id> --dry-run   # npm publish --dry-run, nothing changes
//
// 1. If <name>@<version> is already on npm, does nothing (a re-run after a partial
//    failure skips what was published).
// 2. Each `file:` dependency on another package of this repo (used for local
//    installs) is rewritten to `^<version>`, after waiting until that version is
//    visible on npm. The rewrite happens in the CI checkout only and is undone
//    afterwards; nothing is committed.
// 3. Runs `npm publish --access public --provenance` in the package folder.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { PACKAGES, readManifest, ROOT } from "./packages.mjs";

const [id, ...flags] = process.argv.slice(2);
const dryRun = flags.includes("--dry-run");
const target = PACKAGES.find((pkg) => pkg.id === id);
if (!target) {
  console.error(`Usage: publish-package.mjs <${PACKAGES.map((pkg) => pkg.id).join("|")}> [--dry-run]`);
  process.exit(1);
}

const WAIT_MS = 10 * 60_000;
const POLL_MS = 15_000;

function npm(args, cwd = ROOT) {
  return execFileSync("npm", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], shell: process.platform === "win32" });
}

function isPublished(name, version) {
  try {
    return npm(["view", `${name}@${version}`, "version"]).trim() === version;
  } catch {
    return false; // E404: not published
  }
}

async function waitUntilPublished(name, version) {
  const deadline = Date.now() + WAIT_MS;
  while (!isPublished(name, version)) {
    if (Date.now() > deadline) throw new Error(`${name}@${version} is still not on npm after ${WAIT_MS / 60_000} minutes`);
    console.log(`  waiting for ${name}@${version} to appear on npm...`);
    await new Promise((done) => setTimeout(done, POLL_MS));
  }
}

const dir = join(ROOT, target.dir);
const manifestPath = join(dir, "package.json");
const original = readFileSync(manifestPath, "utf8");
const manifest = readManifest(target.dir);
const label = `${manifest.name}@${manifest.version}`;

if (!dryRun && isPublished(manifest.name, manifest.version)) {
  console.log(`${label} is already on npm; skipping.`);
  process.exit(0);
}

const byDir = new Map(PACKAGES.map((pkg) => [resolve(ROOT, pkg.dir), pkg]));
try {
  for (const [name, spec] of Object.entries(manifest.dependencies || {})) {
    if (!spec.startsWith("file:")) continue;
    const dependency = byDir.get(resolve(dir, spec.slice("file:".length)));
    if (!dependency) throw new Error(`${name} (${spec}) isn't one of this repo's published packages`);
    const { version } = readManifest(dependency.dir);
    if (!dryRun) await waitUntilPublished(name, version);
    manifest.dependencies[name] = `^${version}`;
    console.log(`  ${name}: ${spec} -> ^${version}`);
  }
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

  const args = ["publish", "--access", "public", dryRun ? "--dry-run" : "--provenance"];
  // A prerelease (2.1.0-beta.1) must not become what `npm install` picks by default.
  if (manifest.version.includes("-")) args.push("--tag", "next");
  console.log(`${dryRun ? "Dry run: " : ""}npm ${args.join(" ")} (${label})`);
  execFileSync("npm", args, { cwd: dir, stdio: "inherit", shell: process.platform === "win32" });
  if (!dryRun) console.log(`Published ${label}.`);
} finally {
  writeFileSync(manifestPath, original);
}
