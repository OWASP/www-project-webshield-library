import { EventEmitter } from "../a09-logging-monitoring/EventEmitter.js";
import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

export class AuthManager {
  /**
   * @param {{tokenManager: import('./TokenManager.js').TokenManager}} options
   */
  constructor(options) {
    if (!options || !options.tokenManager) {
      throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "tokenManager is required");
    }
    this.tokenManager = options.tokenManager;
    this.session = null;
    this.events = new EventEmitter();
  }

  setSession(session) {
    this.session = {
      userId: String(session.userId),
      roles: Array.isArray(session.roles) ? session.roles : [],
      metadata: session.metadata || {}
    };
    this.events.emit("auth:changed", this.session);
  }

  clearSession() {
    this.session = null;
    this.tokenManager.clearTokens();
    this.events.emit("auth:changed", null);
  }

  getSession() {
    return this.session;
  }

  isAuthenticated() {
    return Boolean(this.session && this.tokenManager.getAccessToken());
  }
}