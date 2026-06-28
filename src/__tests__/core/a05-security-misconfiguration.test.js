import { describe, expect, test } from "@jest/globals";
import { HardeningReporter, SecurityConfigManager } from "../../core/a05-security-misconfiguration/index.js";

describe("A05 security misconfiguration", () => {
  test("reports hardening findings", () => {
    const manager = new SecurityConfigManager({ debug: true, cors: { origin: "*" }, cookies: { secure: false } });
    const report = new HardeningReporter(manager).generate();
    expect(report.length).toBeGreaterThan(0);
  });
});