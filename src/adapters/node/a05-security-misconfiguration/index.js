import { HardeningReporter, SecurityConfigManager, SecurityError, SecurityErrorCode } from "@owasp-webshield/core";

/**
 * Response headers for a JSON API. The CSP is the strictest one that still lets
 * a browser render an error page; an app that serves HTML should pass its own.
 */
export const DEFAULT_SECURITY_HEADERS = Object.freeze({
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()"
});

/**
 * The default headers merged with `overrides`; an override of `false` or `null`
 * drops that header. Header names are matched case-insensitively.
 * @param {Record<string, string|false|null>} [overrides]
 * @returns {Record<string, string>}
 */
export function securityHeaders(overrides = {}) {
  const headers = new Map(Object.entries(DEFAULT_SECURITY_HEADERS).map(([name, value]) => [name.toLowerCase(), [name, value]]));
  for (const [name, value] of Object.entries(overrides)) {
    if (value === false || value === null) headers.delete(name.toLowerCase());
    else headers.set(name.toLowerCase(), [name, String(value)]);
  }
  return Object.fromEntries(headers.values());
}

const SEVERITY_RANK = { low: 1, medium: 2, high: 3 };

/**
 * Startup gate: runs `HardeningReporter` over the app's real runtime config and
 * throws `MISCONFIGURATION` if any finding is at or above `failOn`. Call it
 * before the server starts listening, so a debug flag or a wildcard CORS origin
 * that leaked into production stops the deploy instead of shipping.
 *
 * `SecurityConfigManager` fills unset values with secure defaults, so pass the
 * values the app actually uses (from env/config), not a hand-written ideal.
 *
 * @param {SecurityConfigManager | ConstructorParameters<typeof SecurityConfigManager>[0]} config
 * @param {{failOn?: "low"|"medium"|"high"|false, logger?: {warn: (event: string, details: object) => void}}} [options]
 * @returns {Array<{id: string, severity: string, recommendation: string}>} every finding, including non-blocking ones
 */
export function assertHardened(config, { failOn = "high", logger } = {}) {
  const manager = config instanceof SecurityConfigManager ? config : new SecurityConfigManager(config);
  manager.validateSchema();
  const report = new HardeningReporter(manager).generate();
  for (const finding of report) logger?.warn("config.unsafe", finding);

  if (failOn === false) return report;
  const threshold = SEVERITY_RANK[failOn];
  if (!threshold) {
    throw new SecurityError(SecurityErrorCode.MISCONFIGURATION, `failOn must be low, medium, high or false, got ${failOn}`);
  }
  const blocking = report.filter((finding) => (SEVERITY_RANK[finding.severity] || SEVERITY_RANK.high) >= threshold);
  if (blocking.length) {
    throw new SecurityError(
      SecurityErrorCode.MISCONFIGURATION,
      `Refusing to start with unsafe configuration: ${blocking.map((finding) => finding.id).join(", ")}`,
      { findings: blocking }
    );
  }
  return report;
}
