// Prints one version's CHANGELOG section, for the GitHub release body.
//
//   node scripts/release/changelog-section.mjs 2.0.0 > release-notes.md
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** The body of the `## [version]` section (without its heading), or null. */
export function changelogSection(changelog, version) {
  const lines = changelog.replace(/\r\n/g, "\n").split("\n");
  const heading = new RegExp(`^## \\[${escape(version)}\\]`);
  const start = lines.findIndex((line) => heading.test(line));
  if (start === -1) return null;
  let end = lines.findIndex((line, index) => index > start && /^## \[/.test(line));
  if (end === -1) end = lines.length;
  const body = lines.slice(start + 1, end).join("\n").replace(/\n---\s*$/, "").trim();
  return body || null;
}

// Run as a script (not imported). Compared case-insensitively: Windows drive letters vary.
if (process.argv[1]?.toLowerCase() === fileURLToPath(import.meta.url).toLowerCase()) {
  const version = process.argv[2];
  const section = changelogSection(readFileSync(join(fileURLToPath(new URL("../..", import.meta.url)), "CHANGELOG.md"), "utf8"), version);
  if (!section) {
    console.error(`CHANGELOG.md has no "## [${version}]" section`);
    process.exit(1);
  }
  process.stdout.write(`${section}\n`);
}
