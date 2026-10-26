import { SecurityError, SecurityErrorCode } from "../../error/SecurityError.js";

const MAX_BUFFER = 10 * 1024 * 1024;

function defaultCwd() {
  // Guarded so constructing the provider stays safe in a browser bundle, where
  // only calling scan() is expected to fail (see the CryptoManager browser stub).
  return typeof process !== "undefined" && typeof process.cwd === "function" ? process.cwd() : undefined;
}

// Loaded lazily and wrapped in try/catch the same way SSRFGuard loads
// "node:dns/promises": the try block tells bundlers (esbuild) the import may be
// unresolvable, which keeps the browser build from failing on a Node-only
// builtin, while a genuinely missing child_process still fails closed.
async function loadExecFile() {
  try {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    return promisify(execFile);
  } catch (error) {
    throw new SecurityError(SecurityErrorCode.MISCONFIGURATION, "npm audit requires a Node.js runtime", {
      cause: error
    });
  }
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function malformed(output) {
  return new SecurityError(SecurityErrorCode.INVALID_INPUT, "npm audit returned malformed output", {
    output: String(output).slice(0, 200)
  });
}

// npm reports the installed version in `version` and the affected *range*
// separately. `currentVersion` must stay an installed version (or null when npm
// names none): a range there would be read as a real version by every consumer.
function currentVersion(entry) {
  if (typeof entry.version === "string" && entry.version) return entry.version;
  return null;
}

// The vulnerable range is still worth carrying, just under its own key so it
// can never be confused with an installed version (ComponentPolicy fails closed
// on a value it cannot parse, but a finding should not have to rely on that).
function vulnerableRange(entry) {
  if (typeof entry.range === "string" && entry.range) return entry.range;
  return null;
}

function fixedVersion(entry, affectedPackageName = (typeof entry?.name === "string" && entry.name ? entry.name : null)) {
  // `fixAvailable: true` means a fix exists but npm named no version; reporting
  // a non-version placeholder here would break semver comparisons downstream.
  // In transitive vulnerabilities, npm may report a fix on a dependent package
  // instead of the affected dependency; only use fixAvailable.version when
  // fixAvailable.name exactly matches the affected package name, returning null otherwise.
  const fix = entry?.fixAvailable;
  if (
    isPlainObject(fix) &&
    affectedPackageName &&
    fix.name === affectedPackageName &&
    typeof fix.version === "string" &&
    fix.version
  ) {
    return fix.version;
  }
  return null;
}

function normalizeReport(stdout) {
  const text = String(stdout ?? "").trim();
  if (!text) {
    throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "npm audit produced no output");
  }

  let report;
  try {
    report = JSON.parse(text);
  } catch {
    throw malformed(text);
  }

  if (!isPlainObject(report)) throw malformed(text);
  const vulnerabilities = report.vulnerabilities;
  // npm always includes `vulnerabilities` ({} on a clean tree); a report without
  // it is incomplete, and an incomplete report must not read as "no findings".
  if (!isPlainObject(vulnerabilities)) throw malformed(text);

  return Object.entries(vulnerabilities).map(([key, entry]) => {
    if (!isPlainObject(entry)) throw malformed(text);
    const name = typeof entry.name === "string" && entry.name ? entry.name : key;
    return {
      name,
      // A severity the report does not provide stays null rather than a
      // placeholder string: DependencyRiskScanner fails closed on severities it
      // does not know, and null can never read as a real (weaker) severity.
      severity: typeof entry.severity === "string" && entry.severity ? entry.severity : null,
      currentVersion: currentVersion(entry),
      range: vulnerableRange(entry),
      fixedVersion: fixedVersion(entry, name)
    };
  });
}

/**
 * @typedef {(command: string, args: string[], options: {cwd?: string, shell?: boolean, maxBuffer?: number}) => Promise<{stdout: string}>} NpmAuditExec
 */

/**
 * A DependencyRiskScanner provider backed by a real `npm audit --json` run.
 */
export class NpmAuditProvider {
  /**
   * @param {{cwd?: string, exec?: NpmAuditExec}} [options]
   *   `cwd` is the project to audit (defaults to the current working directory);
   *   `exec` is injectable for tests, and defaults to a promisified
   *   `child_process.execFile`.
   */
  constructor({ cwd = defaultCwd(), exec } = {}) {
    this.cwd = cwd;
    this.exec = exec;
  }

  /**
   * @returns {Promise<Array<{name: string, severity: string|null, currentVersion: string|null, range: string|null, fixedVersion: string|null}>>}
   */
  async scan() {
    const exec = this.exec || (await loadExecFile());

    let stdout;
    try {
      ({ stdout } = await exec("npm", ["audit", "--json"], {
        cwd: this.cwd,
        // On Windows, npm is installed as a `.cmd` shim which child_process.execFile
        // cannot execute directly without invoking a shell. On non-Windows platforms,
        // npm is spawned directly without a shell to avoid unnecessary shell
        // interpretation. Guarded so an injected exec still runs where process is absent.
        shell: typeof process !== "undefined" && process.platform === "win32",
        maxBuffer: MAX_BUFFER
      }));
    } catch (error) {
      // `npm audit` exits non-zero when it finds vulnerabilities, so a rejected
      // exec still carries the full JSON report on error.stdout.
      if (!error?.stdout) {
        const exitCode =
          typeof error?.exitCode === "number"
            ? error.exitCode
            : typeof error?.code === "number"
              ? error.code
              : typeof error?.status === "number"
                ? error.status
                : undefined;
        const message =
          exitCode !== undefined
            ? `npm audit failed to run (exit code ${exitCode})`
            : "npm audit failed to run";
        const details = { cwd: this.cwd };
        if (exitCode !== undefined) {
          details.exitCode = exitCode;
        }
        throw new SecurityError(SecurityErrorCode.MISCONFIGURATION, message, details);
      }
      stdout = error.stdout;
    }

    return normalizeReport(stdout);
  }
}
