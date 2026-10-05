import { describe, expect, jest, test } from "@jest/globals";
import {
  ComponentPolicy,
  DependencyRiskScanner,
  NpmAuditProvider
} from "../../core/a06-vulnerable-components/index.js";
import { SecurityError } from "../../core/error/index.js";

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

  test("normalizes scanner severities and blocks unrecognized ones", async () => {
    const scanner = new DependencyRiskScanner({
      scan: async () => [
        { name: "a", severity: "moderate" },
        { name: "b", severity: "CRITICAL" },
        { name: "c", severity: "info" }
      ]
    });
    const policy = await scanner.passesPolicy("medium");
    expect(policy.pass).toBe(false);
    expect(policy.blocked.map((b) => b.package)).toEqual(["a", "b"]);

    const unknown = new DependencyRiskScanner({ scan: async () => [{ name: "d", severity: "severe" }] });
    expect((await unknown.passesPolicy("critical")).pass).toBe(false);
    await expect(unknown.passesPolicy("urgent")).rejects.toThrow("Unknown severity threshold");
  });

  test("minimum version check uses semver precedence and fails closed", () => {
    const policy = new ComponentPolicy({ minVersions: { lib: "2.0.0" } });
    const allowed = (version) => policy.evaluate({ name: "lib", version }).allowed;
    expect(allowed(undefined)).toBe(false);
    expect(allowed("v1.0.0")).toBe(false);
    expect(allowed("2.0.0-beta.1")).toBe(false);
    expect(allowed("^2.0.0")).toBe(false);
    expect(allowed("1.10.0")).toBe(false);
    expect(allowed("v2.0.0")).toBe(true);
    expect(allowed("2.0.1")).toBe(true);
    expect(allowed("10.0.0")).toBe(true);
    expect(policy.evaluate({ name: "lib", version: "latest" }).reason).toBe("unparsable_version");
  });

  test("orders pre-release identifiers per semver", () => {
    const policy = new ComponentPolicy({ minVersions: { lib: "1.0.0-alpha.10" } });
    expect(policy.evaluate({ name: "lib", version: "1.0.0-alpha.9" }).allowed).toBe(false);
    expect(policy.evaluate({ name: "lib", version: "1.0.0-beta" }).allowed).toBe(true);
    expect(policy.evaluate({ name: "lib", version: "1.0.0" }).allowed).toBe(true);
  });

  test("rejects an invalid minimum version at construction", () => {
    expect(() => new ComponentPolicy({ minVersions: { lib: ">=2" } })).toThrow("not a valid version");
  });
});

describe("A06 npm audit provider", () => {
  const auditReport = {
    auditReportVersion: 2,
    vulnerabilities: {
      lodash: {
        name: "lodash",
        severity: "high",
        isDirect: true,
        via: [{ source: 1, name: "lodash", severity: "high", range: "<4.17.21" }],
        range: "<4.17.21",
        fixAvailable: { name: "lodash", version: "4.17.21", isSemVerMajor: false },
        nodes: ["node_modules/lodash"]
      },
      minimist: {
        name: "minimist",
        severity: "moderate",
        via: ["advisory-entry"],
        range: "<1.2.6",
        fixAvailable: true,
        nodes: ["node_modules/minimist"]
      },
      legacy: {
        severity: "info",
        version: "0.9.0",
        via: [],
        fixAvailable: false
      }
    },
    metadata: {
      vulnerabilities: { info: 1, low: 0, moderate: 1, high: 1, critical: 0 },
      dependencies: 3
    }
  };

  const execReturning = (stdout) => jest.fn(async () => ({ stdout }));

  test("normalizes npm audit --json findings into the scanner shape", async () => {
    const exec = execReturning(JSON.stringify(auditReport));
    const provider = new NpmAuditProvider({ cwd: "/srv/app", exec });

    const findings = await provider.scan();

    expect(exec).toHaveBeenCalledWith("npm", ["audit", "--json"], {
      cwd: "/srv/app",
      shell: true,
      maxBuffer: 10 * 1024 * 1024
    });
    expect(findings).toEqual([
      { name: "lodash", severity: "high", currentVersion: "<4.17.21", fixedVersion: "4.17.21" },
      { name: "minimist", severity: "moderate", currentVersion: "<1.2.6", fixedVersion: null },
      { name: "legacy", severity: "info", currentVersion: "0.9.0", fixedVersion: null }
    ]);
  });

  test("reads the report from a rejected run, since npm audit exits non-zero when it finds vulnerabilities", async () => {
    const exec = jest.fn(async () => {
      throw Object.assign(new Error("Command failed: npm audit --json"), {
        stdout: JSON.stringify(auditReport)
      });
    });
    const provider = new NpmAuditProvider({ exec });

    expect(await provider.scan()).toHaveLength(3);
    expect(exec).toHaveBeenCalledWith("npm", ["audit", "--json"], expect.objectContaining({ shell: true }));
  });

  test("drops straight into DependencyRiskScanner.passesPolicy", async () => {
    const provider = new NpmAuditProvider({ exec: execReturning(JSON.stringify(auditReport)) });
    const scanner = new DependencyRiskScanner(provider);

    const gate = await scanner.passesPolicy("high");
    expect(gate.pass).toBe(false);
    expect(gate.blocked.map((finding) => finding.package)).toEqual(["lodash"]);

    expect((await scanner.passesPolicy("critical")).pass).toBe(true);
  });

  test("reports no findings only for a valid clean-audit report", async () => {
    const cleanReport = JSON.stringify({
      auditReportVersion: 2,
      vulnerabilities: {},
      metadata: { vulnerabilities: {}, dependencies: 3 }
    });

    const provider = new NpmAuditProvider({ exec: execReturning(cleanReport) });
    expect(await provider.scan()).toEqual([]);

    const gate = await new DependencyRiskScanner(provider).passesPolicy("high");
    expect(gate).toEqual({ pass: true, blocked: [], results: [] });
  });

  test("fails closed on findings whose severity the report does not provide", async () => {
    const provider = new NpmAuditProvider({
      exec: execReturning('{"vulnerabilities":{"ghost":{"range":"<1.0.0"},"bare":{}}}')
    });

    expect(await provider.scan()).toEqual([
      { name: "ghost", severity: "", currentVersion: "<1.0.0", fixedVersion: null },
      { name: "bare", severity: "", currentVersion: null, fixedVersion: null }
    ]);
    expect((await new DependencyRiskScanner(provider).passesPolicy("critical")).pass).toBe(false);
  });

  test("rejects malformed or incomplete npm audit output instead of passing the gate", async () => {
    const malformedOutputs = [
      "npm ERR! code EUSAGE\nnpm ERR! The `npm audit` command requires a package-lock.json",
      "",
      "[]",
      "null",
      "{}",
      '{"auditReportVersion":2}',
      '{"vulnerabilities":"broken"}',
      '{"vulnerabilities":[]}',
      '{"vulnerabilities":{"legacy":"oops"}}'
    ];

    for (const stdout of malformedOutputs) {
      const provider = new NpmAuditProvider({ exec: execReturning(stdout) });
      await expect(provider.scan()).rejects.toThrow(SecurityError);
    }

    // An incomplete report must also keep the severity gate shut.
    const scanner = new DependencyRiskScanner(new NpmAuditProvider({ exec: execReturning("{}") }));
    await expect(scanner.passesPolicy("high")).rejects.toThrow(SecurityError);
  });

  test("fails closed when npm audit cannot run at all", async () => {
    const exec = jest.fn(async () => {
      throw new Error("spawn npm ENOENT");
    });
    const provider = new NpmAuditProvider({ cwd: "/srv/app", exec });

    await expect(provider.scan()).rejects.toThrow("npm audit failed to run");
  });

  test("runs npm audit through Node's child_process when no exec is injected", async () => {
    const provider = new NpmAuditProvider({ cwd: "/no/such/directory/for/owl-audit" });

    await expect(provider.scan()).rejects.toThrow(SecurityError);
  });
});
