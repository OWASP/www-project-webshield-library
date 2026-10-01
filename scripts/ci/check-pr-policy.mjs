#!/usr/bin/env node
// PR review policy for OWL: a change to library source must come with tests and a
// CHANGELOG entry, because OWL's release notes are the record of every security fix.
//
// CI:    BASE_SHA, HEAD_SHA and PR_LABELS (JSON array of label names) come from the workflow.
// Local: node scripts/ci/check-pr-policy.mjs [base-ref]   (default: origin/main)
import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";

const base = process.env.BASE_SHA || process.argv[2] || "origin/main";
const head = process.env.HEAD_SHA || "HEAD";
const labels = new Set(JSON.parse(process.env.PR_LABELS || "[]"));

const changed = execFileSync("git", ["diff", "--name-only", `${base}...${head}`], { encoding: "utf8" })
  .split("\n")
  .filter(Boolean);

const isLibrarySource = (file) =>
  /^src\/(core|adapters\/react)\/.+\.jsx?$/.test(file) && !file.includes("/__tests__/");
const isTest = (file) => /^src\/__tests__\/.+\.test\.jsx?$/.test(file);

const sourceFiles = changed.filter(isLibrarySource);
const rules = [
  {
    name: "Tests accompany source changes",
    label: "skip-test-check",
    applies: sourceFiles.length > 0,
    passed: changed.some(isTest),
    failure: "Library source changed but no test under src/__tests__/ did. Add or update a test that covers the change."
  },
  {
    name: "CHANGELOG entry for source changes",
    label: "skip-changelog",
    applies: sourceFiles.length > 0,
    passed: changed.includes("CHANGELOG.md"),
    failure: "Library source changed but CHANGELOG.md did not. Add an entry under [Unreleased] (Security, Changed, Added or Fixed)."
  }
];

const summary = [
  "## PR review policy",
  "",
  `${changed.length} changed file(s); ${sourceFiles.length} library source file(s).`,
  "",
  "| Rule | Result |",
  "|---|---|"
];
let failed = false;
for (const rule of rules) {
  let result;
  if (!rule.applies) {
    result = "➖ Not applicable";
  } else if (rule.passed) {
    result = "✅ Passed";
  } else if (labels.has(rule.label)) {
    result = `⏭️ Skipped by \`${rule.label}\` label`;
  } else {
    result = `❌ ${rule.failure} If this change genuinely doesn't need it, a maintainer can add the \`${rule.label}\` label.`;
    console.log(`::error title=${rule.name}::${rule.failure}`);
    failed = true;
  }
  summary.push(`| ${rule.name} | ${result} |`);
}

const report = summary.join("\n") + "\n";
console.log(report);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, report);
process.exit(failed ? 1 : 0);
