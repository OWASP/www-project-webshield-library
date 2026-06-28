import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

const secureDefaults = {
  debug: false,
  cors: {
    origin: "self"
  },
  cookies: {
    secure: true,
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
    if (this.config.cors.origin === "*") findings.push({ id: "wildcard_cors", severity: "high" });
    if (!this.config.cookies.secure) findings.push({ id: "insecure_cookie", severity: "high" });
    if (String(this.config.cookies.sameSite).toLowerCase() === "none") {
      findings.push({ id: "samesite_none", severity: "medium" });
    }
    return findings;
  }
}