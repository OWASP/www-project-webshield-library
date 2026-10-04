import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const tsc = fileURLToPath(new URL("../node_modules/typescript/bin/tsc", import.meta.url));
const run = (project) => execFileSync(process.execPath, [tsc, "--project", project], { stdio: "inherit" });

// Core's declarations go to dist/ and ship with @owasp-webshield/core.
run("tsconfig.types.json");

// The adapters resolve @owasp-webshield/core to src/index.js (jsconfig paths), and
// TypeScript reads the .d.ts next to a .js file in preference to the file itself.
// Refresh those copies from what was just generated, so the adapters' declarations
// are built against core's current API, not against whatever was committed last.
// (They are not published: package.json's "files" excludes them.)
cpSync("dist/core", "src/core", { recursive: true });
for (const entry of ["index.d.ts", "index.browser.d.ts"]) cpSync(`dist/${entry}`, `src/${entry}`);

// Each adapter's declarations are generated into dist/<adapter> and copied next
// to its source, which is what that adapter's package publishes. Order matters:
// express's and next's declarations import @owasp-webshield/node (next's also
// @owasp-webshield/react), so those must exist first.
for (const adapter of ["react", "vue", "node", "express", "next"]) {
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
