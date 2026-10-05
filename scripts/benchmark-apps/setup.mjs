#!/usr/bin/env node
// Sets up the actual-app benchmark environment (issue #54): pinned source
// checkouts of OWASP Juice Shop and OWASP NodeGoat under
// $OWL_BENCH_APPS_DIR (default ~/.cache/owl-issue54-apps), their dependency
// installs and builds, the local MongoDB container NodeGoat needs, and the
// OWL dist build the wiring imports. Idempotent: every step is guarded by a
// precondition check, so a partially built environment is completed, not
// rebuilt. Set OWL_BENCH_SKIP_BUILD=1 to skip the OWL package build.
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const APPS_DIR = process.env.OWL_BENCH_APPS_DIR || path.join(os.homedir(), ".cache", "owl-issue54-apps");
const MONGO_CONTAINER = "owl-bench-mongo";

const PINS = [
  {
    name: "juice-shop",
    url: "https://codeload.github.com/OWASP/OWASPJuiceShop/tar.gz/1618a61",
    pin: "1618a61 (v20.2.0)"
  },
  {
    name: "nodegoat",
    url: "https://codeload.github.com/OWASP/NodeGoat/tar.gz/c5cb68a",
    pin: "c5cb68a"
  }
];

const run = (cmd, cmdArgs, options = {}) => {
  console.log(`$ ${cmd} ${cmdArgs.join(" ")}`);
  execFileSync(cmd, cmdArgs, { stdio: "inherit", ...options });
};
const tryRun = (cmd, cmdArgs, options = {}) => {
  try {
    execFileSync(cmd, cmdArgs, { stdio: "ignore", ...options });
    return true;
  } catch {
    return false;
  }
};

// --- Pinned source checkouts --------------------------------------------------- //
function ensureCheckout(pin) {
  const target = path.join(APPS_DIR, pin.name);
  if (existsSync(path.join(target, "package.json"))) {
    console.log(`${pin.name}: present (${pin.pin})`);
    return target;
  }
  const stage = mkdtempSync(path.join(os.tmpdir(), `owl-bench-src-`));
  const tarball = path.join(stage, "src.tgz");
  console.log(`${pin.name}: downloading ${pin.url}`);
  run("curl", ["-L", "--fail", "--silent", "--show-error", "-o", tarball, pin.url]);
  run("tar", ["-xzf", tarball], { cwd: stage });
  const top = readdirSync(stage).filter((entry) => entry !== "src.tgz" && entry !== pin.name);
  if (top.length !== 1) throw new Error(`expected one extracted directory in ${stage}, found: ${top.join(", ")}`);
  renameSync(path.join(stage, top[0]), target);
  rmSync(stage, { recursive: true, force: true });
  console.log(`${pin.name}: extracted to ${target}`);
  return target;
}

function ensureNpmInstall(dir) {
  if (existsSync(path.join(dir, "node_modules"))) return;
  run("npm", ["install"], { cwd: dir });
}

// --- Juice Shop build chain ---------------------------------------------------- //
const juiceFrontendPreconditions = (dir) => {
  const frontend = path.join(dir, "frontend", "dist", "frontend");
  const required = ["index.html", "styles.css", "main.js", "polyfills.js"].map((file) => path.join(frontend, file));
  const hackingInstructor = existsSync(frontend) && readdirSync(frontend).some((file) => file.startsWith("hacking-instructor-"));
  return required.every((file) => existsSync(file)) && hackingInstructor;
};

function ensureJuiceShop(dir) {
  ensureNpmInstall(dir);
  const sqliteBinding = path.join(dir, "node_modules", "sqlite3", "build", "Release", "node_sqlite3.node");
  if (!existsSync(sqliteBinding)) run("npm", ["rebuild", "sqlite3"], { cwd: dir });
  if (!existsSync(path.join(dir, "build", "app.js"))) {
    run(process.execPath, [path.join(dir, "node_modules", "typescript", "bin", "tsc")], { cwd: dir });
  }
  const frontend = path.join(dir, "frontend");
  if (!juiceFrontendPreconditions(dir)) {
    ensureNpmInstall(frontend);
    try {
      run("npm", ["run", "build"], { cwd: frontend });
    } catch (error) {
      // The trailing `sbom` step needs stats.json the bundle step may skip;
      // accept the build when the served files exist.
      if (!juiceFrontendPreconditions(dir)) throw error;
      console.log("juice-shop frontend: build exited non-zero but all served files are present - continuing");
    }
  }
  if (!juiceFrontendPreconditions(dir)) throw new Error("juice-shop frontend preconditions not met");
}

// --- MongoDB container for NodeGoat -------------------------------------------- //
function ensureDocker() {
  if (tryRun("docker", ["info"])) return;
  if (process.platform === "darwin") {
    console.log("docker: daemon not running - starting Docker Desktop");
    execFileSync("open", ["-a", "Docker"], { stdio: "ignore" });
    const deadline = Date.now() + 90_000;
    while (Date.now() < deadline && !tryRun("docker", ["info"])) {
      execSyncSleep(1000);
    }
  }
  if (!tryRun("docker", ["info"])) throw new Error("docker is required for NodeGoat's MongoDB but is not available");
}
function execSyncSleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function ensureMongo() {
  ensureDocker();
  let state = "";
  try {
    state = execFileSync("docker", ["inspect", "-f", "{{.State.Running}}", MONGO_CONTAINER], { encoding: "utf8" }).trim();
  } catch {
    state = "";
  }
  if (state === "true") {
    console.log(`mongo: container ${MONGO_CONTAINER} running`);
    return;
  }
  if (state === "false") {
    run("docker", ["start", MONGO_CONTAINER]);
    return;
  }
  // mongo:4.4 - the NodeGoat driver (mongodb ^2.1.18) cannot talk to mongo:8+.
  run("docker", ["run", "-d", "--name", MONGO_CONTAINER, "-p", "27017:27017", "mongo:4.4"]);
}

// --- Main ----------------------------------------------------------------------- //
function main() {
  console.log(`apps dir: ${APPS_DIR}`);
  const dirs = {};
  for (const pin of PINS) dirs[pin.name] = ensureCheckout(pin);
  ensureJuiceShop(dirs["juice-shop"]);
  ensureNpmInstall(dirs.nodegoat);
  ensureMongo();
  if (process.env.OWL_BENCH_SKIP_BUILD !== "1") run("npm", ["run", "build"], { cwd: REPO_ROOT });
  writeFileSync(
    path.join(APPS_DIR, ".setup-complete"),
    `${JSON.stringify({ date: new Date().toISOString(), pins: PINS.map((pin) => `${pin.name}: ${pin.pin}`) }, null, 2)}\n`
  );
  console.log("\nsetup complete - run `npm run benchmark:apps`");
}

try {
  main();
} catch (error) {
  console.error(`setup failed: ${error.message || error}`);
  process.exit(1);
}
