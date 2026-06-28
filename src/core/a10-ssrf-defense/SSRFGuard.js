import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

const PRIVATE_IP_RANGES = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^192\.168\./,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i
];

export class SSRFGuard {
  constructor({ allowProtocols = ["https:", "http:"], maxRedirectHops = 3 } = {}) {
    this.allowProtocols = new Set(allowProtocols);
    this.maxRedirectHops = maxRedirectHops;
  }

  isPrivateHost(hostname) {
    const lowered = hostname.toLowerCase();
    if (["localhost", "127.0.0.1", "::1"].includes(lowered) || lowered.endsWith(".local")) {
      return true;
    }
    return PRIVATE_IP_RANGES.some((regex) => regex.test(lowered));
  }

  validateUrl(input) {
    const url = new URL(input);
    if (!this.allowProtocols.has(url.protocol)) {
      throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Protocol not allowed", { protocol: url.protocol });
    }
    if (this.isPrivateHost(url.hostname)) {
      throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Private or loopback target blocked", { host: url.hostname });
    }
    return url;
  }

  validateRedirectChain(chain) {
    if (chain.length > this.maxRedirectHops) {
      throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Redirect hop limit exceeded", {
        max: this.maxRedirectHops
      });
    }
    chain.forEach((url) => this.validateUrl(url));
    return true;
  }
}