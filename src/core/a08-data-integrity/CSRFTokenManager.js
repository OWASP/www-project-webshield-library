import { randomBytes } from "node:crypto";
import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

function defaultStorage() {
  let value = null;
  return {
    get: () => value,
    set: (v) => {
      value = v;
    }
  };
}

export class CSRFTokenManager {
  /**
   * @param {{storage?: {get:()=>string|null,set:(value:string)=>void}, tokenLength?: number}} [options]
   */
  constructor(options = {}) {
    this.storage = options.storage || defaultStorage();
    this.tokenLength = options.tokenLength || 32;
  }

  generateToken() {
    return randomBytes(this.tokenLength).toString("base64url");
  }

  getToken() {
    return this.storage.get();
  }

  rotateToken() {
    const token = this.generateToken();
    this.storage.set(token);
    return token;
  }

  attach(headers = {}) {
    const token = this.getToken();
    if (!token) return headers;
    return { ...headers, "X-CSRF-Token": token };
  }

  validate(token) {
    const expected = this.getToken();
    const valid = Boolean(expected && token && expected === token);
    if (!valid) {
      throw new SecurityError(SecurityErrorCode.CSRF_INVALID, "CSRF token validation failed");
    }
    return true;
  }
}