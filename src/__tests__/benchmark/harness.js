// Runtime benchmark runner (issue #54): starts one isolated loopback server
// per target and mode, runs every scenario probe against both, and returns a
// report the test suite asserts on and the docs quote.
//
// Isolation: all five servers (an internal "metadata" service plus two app
// targets x two modes) bind to 127.0.0.1 on OS-assigned ports; no fixed port,
// no external address, no extra dependency.
import { httpRequest, listen } from "./http.js";
import { SCENARIOS } from "./scenarios.js";
import { createJuiceShopTarget } from "./targets/juice-shop.js";
import { createNodeGoatTarget } from "./targets/nodegoat.js";

const MODES = ["baseline", "owl"];
const APPS = ["juice-shop", "nodegoat"];

// Stands in for a cloud instance-metadata endpoint: reachable only from this
// machine, and the only address the SSRF probe is ever allowed to reach.
function startInternalService() {
  return listen((_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"secret":"internal-only"}');
  });
}

export async function startBenchmark() {
  const internal = await startInternalService();
  const apps = {};
  for (const app of APPS) {
    apps[app] = {};
    for (const mode of MODES) {
      const target =
        app === "juice-shop"
          ? createJuiceShopTarget({ mode, internalServiceUrl: internal.baseUrl })
          : createNodeGoatTarget(mode);
      const { baseUrl, close } = await listen(target.handler);
      apps[app][mode] = { baseUrl, close, state: target.state };
    }
  }
  return {
    internal,
    apps,
    stop: async () => {
      const closes = APPS.flatMap((app) => MODES.map((mode) => apps[app][mode].close));
      await Promise.all([...closes.map((close) => close()), internal.close()]);
    }
  };
}

async function runChecked(kind, fn, ctx) {
  try {
    return await fn(ctx);
  } catch (error) {
    const evidence = `probe error: ${error?.stack || error}`;
    return kind === "legit" ? { allowed: false, evidence } : { outcome: "error", evidence };
  }
}

function summarise(results) {
  const categories = {};
  const summary = { total: results.length, blocked: 0, succeeded: 0, errors: 0, mismatches: 0, categories };
  for (const result of results) {
    categories[result.owasp] = (categories[result.owasp] || 0) + 1;
    if (result.owl.outcome === "blocked") summary.blocked++;
    if (result.owl.outcome === "success") summary.succeeded++;
    if (result.baseline.outcome === "error" || result.owl.outcome === "error") summary.errors++;
    if (result.baseline.outcome !== result.expect.baseline || result.owl.outcome !== result.expect.owl) {
      summary.mismatches++;
    }
  }
  return summary;
}

export async function runBenchmark() {
  const env = await startBenchmark();
  const results = [];

  for (const scenario of SCENARIOS) {
    const result = {
      id: scenario.id,
      app: scenario.app,
      title: scenario.title,
      owasp: scenario.owasp,
      cwe: scenario.cwe,
      upstream: scenario.upstream,
      control: scenario.control,
      gap: scenario.gap || null,
      expect: scenario.expect,
      baseline: null,
      owl: null,
      legit: null
    };

    for (const mode of MODES) {
      const target = env.apps[scenario.app][mode];
      const ctx = {
        mode,
        baseUrl: target.baseUrl,
        state: target.state,
        internalServiceUrl: env.internal.baseUrl,
        request: (options) => httpRequest(target.baseUrl, options)
      };
      result[mode] = await runChecked("probe", scenario.probe, ctx);
      if (scenario.legit) {
        result.legit ||= {};
        result.legit[mode] = await runChecked("legit", scenario.legit, ctx);
      }
    }

    results.push(result);
  }

  return { results, summary: summarise(results), stop: env.stop };
}

/** Markdown summary + evidence, printed by the test suite and quoted in docs. */
export function renderReport(report) {
  const lines = [
    "",
    "OWL runtime security benchmark - results",
    "",
    "| ID | App | OWASP | Attack | Baseline | OWL-protected | Expected (OWL) |",
    "|---|---|---|---|---|---|---|"
  ];
  for (const result of report.results) {
    lines.push(
      `| ${result.id} | ${result.app} | ${result.owasp} | ${result.title} | ${result.baseline.outcome} | ${result.owl.outcome} | ${result.expect.owl} |`
    );
  }
  const { total, blocked, succeeded, errors, mismatches } = report.summary;
  lines.push("");
  lines.push(
    `Total: ${total} probes | blocked under OWL: ${blocked} | succeeded under OWL: ${succeeded} | errors: ${errors} | expectation mismatches: ${mismatches}`
  );
  lines.push(`Categories: ${Object.entries(report.summary.categories).map(([id, count]) => `${id}(${count})`).join(" ")}`);
  lines.push("", "Evidence:");
  for (const result of report.results) {
    lines.push(`- ${result.id} baseline [${result.baseline.outcome}]: ${result.baseline.evidence}`);
    lines.push(`- ${result.id} owl [${result.owl.outcome}]: ${result.owl.evidence}`);
    if (result.legit) {
      lines.push(
        `- ${result.id} legit: baseline=${result.legit.baseline.allowed} (${result.legit.baseline.evidence}) | owl=${result.legit.owl.allowed} (${result.legit.owl.evidence})`
      );
    }
  }
  return lines.join("\n");
}
