// Release gate: install the six packages the way a user does and check them.
//
//   node scripts/release-gate/consumer-check.mjs
//
// Packs core and every adapter from this checkout, installs the tarballs into an
// empty project in the OS temp folder (with React, Vue, Express and Next.js), then
// runs consumer/smoke.mjs (ESM + CommonJS imports, one copy of core, Express and
// Next.js requests) and a strict TypeScript check of every entry (consumer/check.ts).
// Run `npm run build` first: core's tarball ships dist/.
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../..", import.meta.url));
const here = fileURLToPath(new URL(".", import.meta.url));
const work = mkdtempSync(join(tmpdir(), "owl-release-gate-"));
const tarballs = join(work, "tgz");
const project = join(work, "consumer");

const npm = (args, cwd) => execFileSync("npm", args, { cwd, stdio: ["ignore", "pipe", "inherit"], shell: true, encoding: "utf8" });
const run = (command, args, cwd) => execFileSync(command, args, { cwd, stdio: "inherit", shell: process.platform === "win32" });

const packages = [
  { name: "@owasp-webshield/core", dir: root },
  ...["react", "vue", "node", "express", "next"].map((adapter) => ({ name: `@owasp-webshield/${adapter}`, dir: join(root, "src", "adapters", adapter) }))
];

console.log(`Working in ${work}`);
mkdirSync(tarballs);
const spec = {};
for (const pkg of packages) {
  const [{ filename, entryCount }] = JSON.parse(npm(["pack", "--json", "--pack-destination", JSON.stringify(tarballs)], pkg.dir));
  spec[pkg.name] = `file:${join(tarballs, filename).replace(/\\/g, "/")}`;
  console.log(`packed ${pkg.name}: ${entryCount} files`);
}

cpSync(join(here, "consumer"), project, { recursive: true });
writeFileSync(
  join(project, "package.json"),
  JSON.stringify(
    {
      name: "owl-release-gate-consumer",
      private: true,
      type: "module",
      dependencies: {
        ...spec,
        react: "^19.3.0",
        "react-dom": "^19.3.0",
        vue: "^3.5.0",
        "vue-router": "^4.6.0",
        express: "^5.2.1",
        next: "^16.3.8",
        typescript: "^5.9.3",
        "@types/node": "^22",
        "@types/express": "^5"
      },
      // The adapters' own dependencies on each other must resolve to these tarballs
      // too, not to the npm registry (where this version may not exist yet).
      overrides: {
        "@owasp-webshield/core": spec["@owasp-webshield/core"],
        "@owasp-webshield/node": spec["@owasp-webshield/node"],
        "@owasp-webshield/react": spec["@owasp-webshield/react"]
      }
    },
    null,
    2
  )
);

npm(["install", "--no-audit", "--no-fund"], project);

// One physical copy of core, or `instanceof SecurityError` breaks across adapters.
const tree = npm(["ls", "@owasp-webshield/core", "--all"], project);
const copies = tree.split("\n").filter((line) => line.includes("@owasp-webshield/core@") && !line.includes("deduped")).length;
if (copies !== 1) throw new Error(`expected one copy of @owasp-webshield/core, found ${copies}:\n${tree}`);
console.log("ok   one copy of @owasp-webshield/core in the install");

run(process.execPath, ["smoke.mjs"], project);
run(process.execPath, [join(project, "node_modules", "typescript", "bin", "tsc"), "--noEmit", "--strict", "--skipLibCheck", "--module", "esnext", "--moduleResolution", "bundler", "--target", "es2022", "--types", "node", "check.ts"], project);
console.log("ok   tsc --strict: every package and subpath typechecks");

const versions = packages.map((pkg) => `${pkg.name}@${JSON.parse(readFileSync(join(pkg.dir, "package.json"), "utf8")).version}`);
console.log(`\nRelease gate consumer check passed for ${versions.join(", ")}`);
