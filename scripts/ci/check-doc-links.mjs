#!/usr/bin/env node
// Checks relative links in the repository's Markdown: the target file must exist and,
// for a "#fragment", the target page must have that heading or an explicit <a id>/<a name>.
// External (http, mailto) and site-absolute ("/guide/...") links are not checked.
//
// Usage: node scripts/ci/check-doc-links.mjs
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const SCAN = ["README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md", "GOVERNANCE.md", "docs", "examples"];
const SKIP_DIRS = new Set(["node_modules", "dist", ".git"]);

function collect(path, out = []) {
  const full = join(ROOT, path);
  if (!existsSync(full)) return out;
  if (statSync(full).isDirectory()) {
    for (const entry of readdirSync(full)) {
      if (!SKIP_DIRS.has(entry)) collect(join(path, entry), out);
    }
  } else if (path.endsWith(".md")) {
    out.push(path);
  }
  return out;
}

// Removes fenced code blocks and inline code, so example links inside code aren't checked.
function stripCode(markdown) {
  return markdown.replace(/^(```|~~~)[\s\S]*?^\1/gm, "").replace(/`[^`\n]*`/g, "");
}

// GitHub's heading slug: lowercase, drop punctuation and emoji, spaces become "-",
// and repeated headings get "-1", "-2", ... suffixes.
function anchorsOf(markdown) {
  const anchors = new Set();
  const seen = new Map();
  for (const [, text] of stripCode(markdown).matchAll(/^#{1,6}\s+(.+?)\s*#*\s*$/gm)) {
    const plain = text.replace(/\[([^\]]*)\]\([^)]*\)/g, "$1").replace(/<[^>]+>/g, "").replace(/[*_~]/g, "");
    const slug = plain.toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, "").replace(/\s/g, "-");
    const count = seen.get(slug) || 0;
    anchors.add(count ? `${slug}-${count}` : slug);
    seen.set(slug, count + 1);
  }
  for (const [, id] of markdown.matchAll(/<a\s+(?:id|name)="([^"]+)"/g)) anchors.add(id);
  return anchors;
}

const anchorCache = new Map();
function hasAnchor(file, fragment) {
  if (!anchorCache.has(file)) anchorCache.set(file, anchorsOf(readFileSync(file, "utf8")));
  return anchorCache.get(file).has(decodeURIComponent(fragment).toLowerCase()) || anchorCache.get(file).has(decodeURIComponent(fragment));
}

const errors = [];
const files = SCAN.flatMap((path) => collect(path));
for (const file of files) {
  const source = join(ROOT, file);
  const lines = stripCode(readFileSync(source, "utf8")).split("\n");
  lines.forEach((line, index) => {
    for (const [, rawTarget] of line.matchAll(/\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g)) {
      if (/^[a-z][a-z0-9+.-]*:/i.test(rawTarget) || rawTarget.startsWith("/")) continue;
      const [pathPart, fragment] = rawTarget.split("#");
      const target = pathPart ? resolve(dirname(source), decodeURIComponent(pathPart)) : source;
      const where = `${file.replace(/\\/g, "/")}:${index + 1}`;
      if (!existsSync(target)) {
        errors.push({ where, message: `missing file: ${rawTarget}` });
      } else if (fragment && target.endsWith(".md") && !hasAnchor(target, fragment)) {
        errors.push({ where, message: `missing anchor #${fragment} in ${relative(ROOT, target).replace(/\\/g, "/")}` });
      }
    }
  });
}

for (const { where, message } of errors) {
  const [file, line] = where.split(":");
  console.log(`::error file=${file},line=${line}::Broken link: ${message}`);
}
console.log(`Checked ${files.length} Markdown file(s): ${errors.length} broken relative link(s).`);
process.exit(errors.length ? 1 : 0);
