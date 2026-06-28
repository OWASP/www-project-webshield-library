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
    this.storage.removeItem(this.key);
    this.events.emit("token:cleared", undefined);
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
    const next = await this.onRefresh(tokens.refreshToken, tokens.accessToken);
    this.setTokens(next);
    this.events.emit("token:rotated", next);
    return next.accessToken;
  }
}