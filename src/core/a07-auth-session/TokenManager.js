import { EventEmitter } from "../a09-logging-monitoring/EventEmitter.js";
import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

function memoryAdapter() {
  const store = new Map();
  return {
    getItem: (key) => store.get(key) || null,
    setItem: (key, value) => store.set(key, value),
    removeItem: (key) => store.delete(key)
  };
}

export class TokenManager {
  /**
   * @param {{storageAdapter?: {getItem:(k:string)=>string|null,setItem:(k:string,v:string)=>void,removeItem:(k:string)=>void}, now?:()=>number, onRefresh?: (refreshToken:string, currentAccess:string|null)=>Promise<{accessToken:string, expiresAt:number, refreshToken?:string}>}} [options]
   */
  constructor(options = {}) {
    this.storage = options.storageAdapter || memoryAdapter();
    this.now = options.now || (() => Date.now());
    this.onRefresh = options.onRefresh;
    this.events = new EventEmitter();
    this.key = "owl.auth.tokens";
    this._refreshing = null;
    // Incremented whenever tokens are set or cleared from outside a refresh, so a
    // refresh that started before a logout or a new login can't write its result back.
    this._generation = 0;
  }

  _read() {
    const raw = this.storage.getItem(this.key);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  _write(tokens) {
    this.storage.setItem(this.key, JSON.stringify(tokens));
    this.events.emit("token:changed", tokens);
  }

  setTokens(tokens) {
    this._endSession();
    this._store(tokens);
  }

  _store(tokens) {
    if (!tokens || typeof tokens.accessToken !== "string") {
      throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "Invalid token payload");
    }
    this._write({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken || null,
      expiresAt: Number(tokens.expiresAt || 0)
    });
  }

  clearTokens() {
    this._endSession();
    this.storage.removeItem(this.key);
    this.events.emit("token:cleared", undefined);
  }

  // Detaches any in-flight refresh from the current session.
  _endSession() {
    this._generation++;
    this._refreshing = null;
  }

  getTokens() {
    return this._read();
  }

  isAccessTokenExpired() {
    const tokens = this._read();
    if (!tokens || !tokens.expiresAt) return true;
    return this.now() >= tokens.expiresAt;
  }

  getAccessToken() {
    const tokens = this._read();
    if (!tokens || this.isAccessTokenExpired()) return null;
    return tokens.accessToken;
  }

  async refreshIfNeeded() {
    const tokens = this._read();
    if (!tokens || !this.isAccessTokenExpired()) return this.getAccessToken();
    if (!this.onRefresh || !tokens.refreshToken) {
      throw new SecurityError(SecurityErrorCode.TOKEN_EXPIRED, "Token expired and no refresh hook configured");
    }
    // Concurrent callers share one in-flight refresh, so a rotating refresh token is
    // presented only once (servers that detect refresh-token reuse revoke the session).
    if (!this._refreshing) {
      const refreshing = this._refresh(tokens).finally(() => {
        if (this._refreshing === refreshing) this._refreshing = null;
      });
      this._refreshing = refreshing;
    }
    return this._refreshing;
  }

  async _refresh(tokens) {
    const generation = this._generation;
    const next = await this.onRefresh(tokens.refreshToken, tokens.accessToken);
    if (generation !== this._generation) {
      // Logged out (or a new session was set) while the refresh was in flight: storing
      // these tokens would silently sign the previous user back in.
      throw new SecurityError(SecurityErrorCode.AUTH_REQUIRED, "Session changed during token refresh; result discarded");
    }
    // Servers that don't rotate refresh tokens omit it; keep the current one.
    this._store({ ...next, refreshToken: next?.refreshToken || tokens.refreshToken });
    this.events.emit("token:rotated", next);
    return next.accessToken;
  }
}