/**
 * Runtime security benchmark for OWL against OWASP Juice Shop and NodeGoat
 * weakness replicas (issue #54).
 *
 * Each scenario runs twice against isolated loopback servers: once on the
 * baseline target (upstream wiring, no OWL) and once on the OWL-protected
 * target. The expectations below are the published result: `owl: "blocked"`
 * means OWL stopped the attack; `owl: "success"` is a documented coverage gap
 * (see docs/benchmarks/runtime-verification.md).
 *
 * @jest-environment node
 */
import { afterAll, beforeAll, describe, expect, test } from "@jest/globals";
import { renderReport, runBenchmark } from "./harness.js";
import { OWASP_CATEGORIES, SCENARIOS } from "./scenarios.js";

let report;

beforeAll(async () => {
  report = await runBenchmark();
}, 60000);

afterAll(async () => {
  if (!report) return;
  // The full result table plus per-probe evidence, for the docs and for
  // anyone rerunning the benchmark.
  console.log(renderReport(report));
  await report.stop();
});

describe("OWL runtime security benchmark (issue #54)", () => {
  test("every probe produced a result in both modes, none errored", () => {
    expect(report.results).toHaveLength(SCENARIOS.length);
    for (const result of report.results) {
      expect(result.baseline?.outcome).toBeDefined();
      expect(result.owl?.outcome).toBeDefined();
      expect(result.baseline.outcome).not.toBe("error");
      expect(result.owl.outcome).not.toBe("error");
    }
  });

  test("representative attacks cover OWASP A01-A10", () => {
    const covered = new Set(SCENARIOS.map((scenario) => scenario.owasp));
    expect(OWASP_CATEGORIES.filter((category) => !covered.has(category))).toEqual([]);
  });

  for (const scenario of SCENARIOS) {
    test(`${scenario.id} [${scenario.owasp}] ${scenario.title}`, () => {
      const result = report.results.find((entry) => entry.id === scenario.id);
      expect(result.baseline.outcome).toBe(scenario.expect.baseline);
      expect(result.owl.outcome).toBe(scenario.expect.owl);
      if (scenario.legit) {
        // The protected target must keep serving legitimate traffic: a control
        // that blocks everything is not a passing result.
        expect(result.legit.owl.allowed).toBe(true);
        expect(result.legit.baseline.allowed).toBe(true);
      }
    });
  }
});
