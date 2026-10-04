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

// npm reports the vulnerable *range*, not the installed version, so the range
// is what the finding carries when npm names no version (ComponentPolicy fails
// closed on a value it cannot parse, so a range is never mistaken for a version).
function currentVersion(entry) {
  if (typeof entry.version === "string" && entry.version) return entry.version;
  if (typeof entry.range === "string" && entry.range) return entry.range;
  return null;
}

function fixedVersion(entry) {
  // `fixAvailable: true` means a fix exists but npm named no version; reporting
  // a non-version placeholder here would break semver comparisons downstream.
  const fix = entry.fixAvailable;
  if (isPlainObject(fix) && typeof fix.version === "string" && fix.version) return fix.version;
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
    return {
      name: typeof entry.name === "string" && entry.name ? entry.name : key,
      // An unrecognized severity is left as-is on purpose: DependencyRiskScanner
      // fails closed on severities it does not know.
      severity: String(entry.severity ?? ""),
      currentVersion: currentVersion(entry),
      fixedVersion: fixedVersion(entry)
    };
  });
}

/**
 * A DependencyRiskScanner provider backed by a real `npm audit --json` run.
 */
export class NpmAuditProvider {
  /**
   * @param {{cwd?: string, exec?: (command: string, args: string[], options: {cwd?: string, shell?: boolean, maxBuffer?: number}) => Promise<{stdout: string}>}} [options]
   *   `cwd` is the project to audit (defaults to the current working directory);
   *   `exec` is injectable for tests, and defaults to a promisified
   *   `child_process.execFile`.
   */
  constructor({ cwd = defaultCwd(), exec } = {}) {
    this.cwd = cwd;
    this.exec = exec;
  }

  /**
   * @returns {Promise<Array<{name: string, severity: string, currentVersion: string|null, fixedVersion: string|null}>>}
   */
  async scan() {
    const exec = this.exec || (await loadExecFile());

    let stdout;
    try {
      ({ stdout } = await exec("npm", ["audit", "--json"], {
        cwd: this.cwd,
        shell: true, // npm ships as a .cmd shim on Windows; execFile needs a shell to resolve it
        maxBuffer: MAX_BUFFER
      }));
    } catch (error) {
      // `npm audit` exits non-zero when it finds vulnerabilities, so a rejected
      // exec still carries the full JSON report on error.stdout.
      if (!error?.stdout) {
        throw new SecurityError(SecurityErrorCode.MISCONFIGURATION, "npm audit failed to run", {
          cwd: this.cwd,
          message: error?.message
        });
      }
      stdout = error.stdout;
    }

    return normalizeReport(stdout);
  }
}
