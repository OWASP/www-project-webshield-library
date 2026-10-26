/**
 * @jest-environment node
 */
import { describe, expect, test } from "@jest/globals";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import * as nodeBuild from "../../index.js";
import * as browserBuild from "../../index.browser.js";
import * as reactNodeEntry from "../../adapters/react/index.js";
import * as reactBrowserEntry from "../../adapters/react/index.browser.js";

const ROOT = process.cwd();
const ADAPTERS = ["react", "vue", "node", "express", "next"];

function listFiles(dir, suffix) {
  const out = [];
  for (const name of readdirSync(dir)) {
    if (name === "node_modules") continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...listFiles(path, suffix));
    else if (name.endsWith(suffix)) out.push(path);
  }
  return out;
}

describe("published package shape", () => {
  test("core's browser build exports the same names as the Node build", () => {
    // Shared client/server code imports from the package root; a name missing
    // from one build breaks that bundle (e.g. DEFAULT_PBKDF2_ITERATIONS).
    expect(Object.keys(browserBuild).sort()).toEqual(Object.keys(nodeBuild).sort());
  });

  test("the React adapter's browser entry exports the same names as its Node entry", () => {
    // Bundlers pick one or the other by export condition, so a name missing from
    // one entry only breaks apps built for that target.
    expect(Object.keys(reactBrowserEntry).sort()).toEqual(Object.keys(reactNodeEntry).sort());
  });

  test.each(ADAPTERS)("@owasp-webshield/%s declares TypeScript types that exist", (adapter) => {
    const dir = join(ROOT, "src", "adapters", adapter);
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    expect(pkg.types).toBeTruthy();
    expect(existsSync(join(dir, pkg.types))).toBe(true);
    expect(pkg.exports["."].types).toBe(pkg.types);
  });

  test.each(ADAPTERS)("@owasp-webshield/%s declarations have no untyped destructured options", (adapter) => {
    // `function f({ a } = {})` without a JSDoc type compiles to `{ a }?: {}`,
    // which doesn't type-check for consumers (property 'a' does not exist on type '{}').
    const dir = join(ROOT, "src", "adapters", adapter);
    const untyped = listFiles(dir, ".d.ts").filter((file) => /\}\?: \{\}\)/.test(readFileSync(file, "utf8")));
    expect(untyped.map((file) => relative(ROOT, file))).toEqual([]);
  });

  test.each(ADAPTERS)("@owasp-webshield/%s declarations only import paths inside the package", (adapter) => {
    // A relative import that leaves the package (e.g. "../../core/...") only
    // resolves inside this repository; published, it breaks the types.
    const dir = join(ROOT, "src", "adapters", adapter);
    const escaping = [];
    for (const file of listFiles(dir, ".d.ts")) {
      const source = readFileSync(file, "utf8");
      for (const [, specifier] of source.matchAll(/(?:from\s+|import\(|path=)["'](\.{1,2}\/[^"']+)["']/g)) {
        const target = resolve(dirname(file), specifier);
        if (relative(dir, target).startsWith("..")) escaping.push(`${relative(ROOT, file)} -> ${specifier}`);
      }
    }
    expect(escaping).toEqual([]);
  });
});
