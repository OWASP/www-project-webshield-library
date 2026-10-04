#!/usr/bin/env node
// Actual-app benchmark runner (issue #54).
//
// For every selected app it starts the pinned deployment twice - `baseline`
// as shipped, `owl` through the OWL wiring preloads - runs the attack probes
// and their legitimate-flow checks, and compares each observed outcome with
// the documented expectation. Exits non-zero on any mismatch or failed
// legitimate check. See docs/benchmarks/upstream-verification.md for results
// and reproduction steps.
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PROBES } from "./probes.mjs";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const APPS_DIR = process.env.OWL_BENCH_APPS_DIR || path.join(os.homedir(), ".cache", "owl-issue54-apps");
const JUICE_PORT = Number(process.env.OWL_BENCH_JUICE_PORT || 3100);
const NODE_PORT = Number(process.env.OWL_BENCH_NODE_PORT || 5100);
const WIRING_DIR = path.join(REPO_ROOT, "scripts", "benchmark-apps", "wiring");

const APPS = {
  juice: {
    id: "juice",
    label: "juice-shop",
    probeApp: "juice-shop",
    dir: path.join(APPS_DIR, "juice-shop"),
    entry: "build/app",
    entryCheck: "build/app.js",
    port: JUICE_PORT,
    readyPath: "/api/Products",
    wiring: "juice-shop.mjs",
    env: () => ({ PORT: String(JUICE_PORT) })
  },
  node: {
    id: "node",
    label: "nodegoat",
    probeApp: "nodegoat",
    dir: path.join(APPS_DIR, "nodegoat"),
    entry: "server.js",
    entryCheck: "server.js",
    port: NODE_PORT,
    readyPath: "/",
    wiring: "nodegoat.mjs",
    env: () => ({ PORT: String(NODE_PORT), OWL_BENCH_NODEGOAT_DIR: path.join(APPS_DIR, "nodegoat") })
  }
};

const args = process.argv.slice(2);
const argValue = (name, fallback) => {
  const found = args.find((arg) => arg.startsWith(`--${name}=`));
  return found ? found.split("=")[1] : fallback;
};
const selectedApps = argValue("app", "all");
const selectedModes = argValue("mode", "all");

function fail(message) {
  console.error(`benchmark: ${message}`);
  process.exit(2);
}

// --- Preflight ---------------------------------------------------------------- //
if (!existsSync(path.join(REPO_ROOT, "dist", "index.js"))) {
  fail("@owasp-webshield/core is not built - run `npm run benchmark:apps:setup` first");
}
for (const key of selectedApps === "all" ? Object.keys(APPS) : [selectedApps]) {
  const app = APPS[key];
  if (!app) fail(`unknown --app=${selectedApps} (use juice, node or all)`);
  if (!existsSync(path.join(app.dir, app.entryCheck))) {
    fail(`${app.label} deployment missing at ${app.dir} - run \`npm run benchmark:apps:setup\``);
  }
}
const modes = selectedModes === "all" ? ["baseline", "owl"] : [selectedModes];
for (const mode of modes) {
  if (!["baseline", "owl"].includes(mode)) fail(`unknown --mode=${selectedModes} (use baseline, owl or all)`);
}
const appKeys = selectedApps === "all" ? ["juice", "node"] : [selectedApps];

// --- Internal metadata service (JS-03 SSRF target) ---------------------------- //
const internalHits = [];
const internalServer = http.createServer((req, res) => {
  internalHits.push(req.url);
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("internal-only");
});
await new Promise((resolve) => internalServer.listen(0, "127.0.0.1", resolve));
const internalUrl = `http://127.0.0.1:${internalServer.address().port}`;
const markerDir = mkdtempSync(path.join(os.tmpdir(), "owl-bench-"));

// --- Child process helpers ----------------------------------------------------- //
let activeChild = null;
let activeSuite = null;

async function waitPortFree(port, label) {
  const inUse = await new Promise((resolve) => {
    const probe = http.get({ host: "127.0.0.1", port, timeout: 1000 }, (res) => {
      res.resume();
      resolve(true);
    });
    probe.on("error", () => resolve(false));
    probe.on("timeout", () => {
      probe.destroy();
      resolve(true);
    });
  });
  if (inUse) fail(`port ${port} is already in use - stop the process serving ${label} first`);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitReady(app, logs, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last = "no response yet";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${app.port}${app.readyPath}`, { signal: AbortSignal.timeout(2000), redirect: "manual" });
      if (response.status === 200 || response.status === 302) return;
      last = `status ${response.status}`;
    } catch (error) {
      last = String((error && error.message) || error);
    }
    await sleep(500);
  }
  throw new Error(`${app.label} not ready on port ${app.port} within ${timeoutMs}ms (${last}); log tail:\n${logs().slice(-2000)}`);
}

function spawnApp(app, mode) {
  const wiring = mode === "owl" ? path.join(WIRING_DIR, app.wiring) : null;
  const nodeArgs = wiring ? ["--import", wiring, app.entry] : [app.entry];
  const child = spawn(process.execPath, nodeArgs, {
    cwd: app.dir,
    env: { ...process.env, ...app.env() },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let logText = "";
  const collect = (chunk) => {
    logText += chunk;
    if (logText.length > 1_000_000) logText = logText.slice(-1_000_000);
  };
  child.stdout.on("data", collect);
  child.stderr.on("data", collect);
  const exited = new Promise((resolve) => child.on("exit", (code, signal) => resolve({ code, signal })));
  activeChild = child;
  return {
    child,
    logs: () => logText,
    exited,
    stop: async () => {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill("SIGTERM");
      const result = await Promise.race([exited, sleep(5000).then(() => null)]);
      if (result === null) {
        child.kill("SIGKILL");
        await Promise.race([exited, sleep(2000)]);
      }
      activeChild = null;
    }
  };
}

// --- Suite / probe execution --------------------------------------------------- //
function makeContext(app, mode, runtime, logStart) {
  const baseUrl = `http://127.0.0.1:${app.port}`;
  return {
    mode,
    appName: app.label,
    appDir: app.dir,
    baseUrl,
    markerDir,
    internalUrl,
    logStart,
    logs: runtime.logs,
    internalHits: () => [...internalHits],
    resetHits: () => {
      internalHits.length = 0;
    },
    request: async ({ method = "GET", path: requestPath, headers = {}, body, form }) => {
      const init = { method, headers: { ...headers }, redirect: "manual", signal: AbortSignal.timeout(15000) };
      if (form !== undefined) {
        init.headers["content-type"] = "application/x-www-form-urlencoded";
        init.body = new URLSearchParams(form).toString();
      } else if (body !== undefined) {
        init.headers["content-type"] = init.headers["content-type"] || "application/json";
        init.body = JSON.stringify(body);
      }
      const response = await fetch(baseUrl + requestPath, init);
      const text = await response.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
      return { status: response.status, text, json, headers: response.headers };
    }
  };
}

const rows = [];
let mismatches = 0;
let legitFailures = 0;

async function runSuite(app, mode) {
  await waitPortFree(app.port, app.label);
  // A fresh seed keeps state written by one suite (e.g. the raw memo NG-06
  // stores in baseline) from changing what the next suite observes.
  if (app.id === "node") await seedNodeGoat();
  console.log(`\n=== ${app.label} [${mode}] ===`);
  const runtime = spawnApp(app, mode);
  try {
    await waitReady(app, runtime.logs, app.id === "juice" ? 120_000 : 60_000);
    const probes = PROBES.filter((probe) => probe.app === app.probeApp);
    for (const probe of probes) {
      const logStart = runtime.logs().length;
      const ctx = makeContext(app, mode, runtime, logStart);
      let result;
      try {
        result = await probe.probe(ctx);
      } catch (error) {
        result = { outcome: "error", evidence: String((error && error.stack) || error) };
      }
      const expected = probe.expect[mode];
      const match = result.outcome === expected;
      if (!match) mismatches += 1;

      let legit;
      if (typeof probe.legit === "function") {
        try {
          legit = await probe.legit(ctx);
        } catch (error) {
          legit = { allowed: false, evidence: String((error && error.message) || error) };
        }
        if (legit.allowed === false) legitFailures += 1;
      } else {
        legit = { skipped: true, evidence: probe.legit && probe.legit.skip };
      }
      rows.push({ app: app.label, id: probe.id, mode, outcome: result.outcome, expected, match, legit, evidence: result.evidence });
      const flag = match ? "ok" : "MISMATCH";
      const legitFlag = legit.skipped ? "skipped" : legit.allowed ? "allowed" : "FAILED";
      console.log(
        `  ${probe.id} ${mode.padEnd(8)} outcome=${result.outcome} expected=${expected} [${flag}] legit=${legitFlag}` +
          `\n    evidence: ${result.evidence}` +
          (legitFlag === "FAILED" ? `\n    legit:    ${legit.evidence}` : "")
      );
    }
  } finally {
    const logFile = path.join(os.tmpdir(), `owl-bench-${app.id}-${mode}.log`);
    writeFileSync(logFile, runtime.logs());
    await runtime.stop();
    if (rows.some((row) => !row.match)) console.log(`  app log: ${logFile}`);
  }
}

// --- NodeGoat needs its seeded users ------------------------------------------- //
function mongoContainerRunning() {
  try {
    return execFileSync("docker", ["inspect", "-f", "{{.State.Running}}", "owl-bench-mongo"], { encoding: "utf8" }).trim() === "true";
  } catch {
    return false;
  }
}

async function seedNodeGoat() {
  if (!mongoContainerRunning()) fail("mongo container owl-bench-mongo is not running - run `npm run benchmark:apps:setup`");
  const app = APPS.node;
  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["artifacts/db-reset.js"], { cwd: app.dir, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (chunk) => (out += chunk));
    child.stderr.on("data", (chunk) => (out += chunk));
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`db-reset exited ${code}:\n${out.slice(-2000)}`))));
  });
  console.log("nodegoat database reseeded (artifacts/db-reset.js)");
}

process.on("SIGINT", () => {
  if (activeChild) activeChild.kill("SIGKILL");
  if (activeSuite) console.error(`\ninterrupted during ${activeSuite}`);
  process.exit(130);
});

// --- Main ----------------------------------------------------------------------- //
try {
  for (const key of appKeys) {
    const app = APPS[key];
    for (const mode of modes) {
      activeSuite = `${app.label} [${mode}]`;
      await runSuite(app, mode);
      activeSuite = null;
    }
  }
} finally {
  internalServer.close();
}

// --- Report --------------------------------------------------------------------- //
console.log("\n=== results ===");
console.log("app        id     mode     outcome         expected      match  legit");
for (const row of rows) {
  const legit = row.legit.skipped ? "skipped" : row.legit.allowed ? "allowed" : "FAILED";
  console.log(
    `${row.app.padEnd(10)} ${row.id.padEnd(6)} ${row.mode.padEnd(8)} ${row.outcome.padEnd(15)} ${row.expected.padEnd(13)} ` +
      `${(row.match ? "ok" : "MISMATCH").padEnd(6)} ${legit}`
  );
}

const owlRows = rows.filter((row) => row.mode === "owl");
const blocked = owlRows.filter((row) => row.outcome === "blocked").length;
const gaps = owlRows.filter((row) => row.match && row.outcome === "success");
const categories = [...new Set(PROBES.map((probe) => probe.owasp))].sort();
console.log(
  `\nowl: ${blocked} blocked, ${gaps.length} documented gap(s)${gaps.length ? ` (${gaps.map((row) => row.id).join(", ")})` : ""}; ` +
    `OWASP categories exercised: ${categories.join(", ")}`
);
for (const row of gaps) console.log(`  gap ${row.id}: ${row.evidence}`);

if (mismatches > 0 || legitFailures > 0) {
  console.error(`\nFAILED: ${mismatches} expectation mismatch(es), ${legitFailures} legitimate-flow failure(s)`);
  process.exit(1);
}
console.log("\nAll expectations and legitimate-flow checks passed.");
