import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/**
 * A real DependencyRiskScanner provider — shells out to `npm audit --json`
 * instead of returning a hand-written fixture, unlike the mocked provider
 * used in the browser example (which can't spawn a subprocess). `npm audit`
 * exits non-zero when it finds vulnerabilities, so a rejected exec still has
 * its JSON report on `error.stdout`.
 */
export class NpmAuditProvider {
  constructor({ cwd = process.cwd() } = {}) {
    this.cwd = cwd;
  }

  async scan() {
    let stdout;
    try {
      ({ stdout } = await execFileAsync("npm", ["audit", "--json"], {
        cwd: this.cwd,
        shell: true, // npm ships as a .cmd shim on Windows; execFile needs a shell to resolve it
        maxBuffer: 10 * 1024 * 1024
      }));
    } catch (error) {
      stdout = error.stdout;
    }

    if (!stdout) return [];

    let report;
    try {
      report = JSON.parse(stdout);
    } catch {
      return [];
    }

    const vulnerabilities = report.vulnerabilities || {};
    return Object.values(vulnerabilities).map((entry) => ({
      name: entry.name,
      severity: entry.severity,
      currentVersion: entry.range || "unknown",
      fixedVersion:
        entry.fixAvailable && typeof entry.fixAvailable === "object"
          ? entry.fixAvailable.version
          : entry.fixAvailable
            ? "available"
            : null
    }));
  }
}
