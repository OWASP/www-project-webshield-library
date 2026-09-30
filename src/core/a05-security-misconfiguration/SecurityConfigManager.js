import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

const secureDefaults = {
  debug: false,
  cors: {
    origin: "self"
  },
  cookies: {
    secure: true,
    httpOnly: true,
    sameSite: "Strict"
  }
};

export class SecurityConfigManager {
  constructor(config = {}) {
    this.config = {
      ...secureDefaults,
      ...config,
      cors: { ...secureDefaults.cors, ...(config.cors || {}) },
      cookies: { ...secureDefaults.cookies, ...(config.cookies || {}) }
    };
  }

  validateSchema() {
    if (typeof this.config.debug !== "boolean") {
      throw new SecurityError(SecurityErrorCode.MISCONFIGURATION, "debug must be a boolean");
    }
    return true;
  }

  detectUnsafeSettings() {
    const findings = [];
    if (this.config.debug) findings.push({ id: "debug_enabled", severity: "high" });
    const { origin, credentials } = this.config.cors;
    const isWildcard = origin === "*" || (Array.isArray(origin) && origin.includes("*"));
    // origin: true (as in the `cors` npm package) reflects any caller's Origin back.
    const isReflected = origin === true;
    if (isWildcard) findings.push({ id: "wildcard_cors", severity: "high" });
    if (isReflected) findings.push({ id: "reflected_cors", severity: "high" });
    if ((isWildcard || isReflected) && credentials === true) {
      findings.push({ id: "credentialed_any_origin_cors", severity: "high" });
    }
    if (!this.config.cookies.secure) findings.push({ id: "insecure_cookie", severity: "high" });
    if (this.config.cookies.httpOnly !== true) findings.push({ id: "cookie_not_httponly", severity: "medium" });
    if (String(this.config.cookies.sameSite).toLowerCase() === "none") {
      findings.push({ id: "samesite_none", severity: "medium" });
    }
    return findings;
  }
}