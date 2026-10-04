import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const tsc = fileURLToPath(new URL("../node_modules/typescript/bin/tsc", import.meta.url));
const run = (project) => execFileSync(process.execPath, [tsc, "--project", project], { stdio: "inherit" });

// Core's declarations go to dist/ and ship with @owasp-webshield/core.
run("tsconfig.types.json");

// Each adapter's declarations are generated into dist/<adapter> and copied next
// to its source, which is what that adapter's package publishes. Order matters:
// express's declarations import @owasp-webshield/node, so node's must exist first.
for (const adapter of ["react", "vue", "node", "express"]) {
  run(`tsconfig.${adapter}.types.json`);
  cpSync(`dist/${adapter}`, `src/adapters/${adapter}`, { recursive: true });
  // Core publishes all of dist/, so the adapter copies must not stay there.
  rmSync(`dist/${adapter}`, { recursive: true, force: true });
}

// The Express adapter's hand-written request.d.ts augments Express's Request type
// with req.owl; reference it from the generated entry point so it's always loaded.
const expressTypes = "src/adapters/express/index.d.ts";
const reference = '/// <reference path="./request.d.ts" />\n';
const generated = readFileSync(expressTypes, "utf8");
if (!generated.startsWith(reference)) writeFileSync(expressTypes, reference + generated);
