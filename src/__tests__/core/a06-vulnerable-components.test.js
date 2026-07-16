import { describe, expect, test } from "@jest/globals";
import { ComponentPolicy, DependencyRiskScanner } from "../../core/a06-vulnerable-components/index.js";

describe("A06 vulnerable components", () => {
  test("normalizes dependency risk and fails threshold", async () => {
    const scanner = new DependencyRiskScanner({
      scan: async () => [{ name: "x", severity: "high", fixedVersion: "2.0.0", currentVersion: "1.0.0" }]
    });
    const policy = await scanner.passesPolicy("high");
    expect(policy.pass).toBe(false);
    expect(policy.blocked[0].package).toBe("x");
  });

  test("allows findings below the configured threshold", async () => {
    const scanner = new DependencyRiskScanner({
      scan: async () => [{ name: "x", severity: "medium", fixedVersion: "2.0.0", currentVersion: "1.0.0" }]
    });

    const policy = await scanner.passesPolicy("high");
    expect(policy.pass).toBe(true);
    expect(policy.blocked).toEqual([]);
  });

  test("component policy enforces denylist and minimum version", () => {
    const policy = new ComponentPolicy({ denylist: ["bad-lib"], minVersions: { safe: "1.2.0" } });
    expect(policy.evaluate({ name: "bad-lib", version: "1.0.0" }).allowed).toBe(false);
    expect(policy.evaluate({ name: "safe", version: "1.0.0" }).allowed).toBe(false);
  });

  test("component policy can enforce an allowlist", () => {
    const policy = new ComponentPolicy({ allowlist: ["safe-lib"] });
    expect(policy.evaluate({ name: "safe-lib", version: "1.0.0" })).toEqual({ allowed: true, reason: "allowed" });
    expect(policy.evaluate({ name: "other-lib", version: "1.0.0" })).toEqual({
      allowed: false,
      reason: "not_in_allowlist"
    });
  });
});