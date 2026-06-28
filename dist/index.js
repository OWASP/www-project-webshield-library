// src/core/a01-access-control/ACLManager.js
var ACLManager = class {
  constructor() {
    this.policies = /* @__PURE__ */ new Map();
  }
  /**
   * Deny overrides allow for deterministic conflict resolution.
   */
  setPolicy(resource, action, effect) {
    const key = `${action}:${resource}`;
    this.policies.set(key, effect);
  }
  evaluate(resource, action) {
    const direct = this.policies.get(`${action}:${resource}`);
    const wildcard = this.policies.get(`${action}:*`);
    const effect = direct || wildcard || "neutral";
    return {
      effect,
      allowed: effect === "allow"
    };
  }
};

// src/core/a01-access-control/RBACManager.js
var RBACManager = class {
  constructor() {
    this.roles = /* @__PURE__ */ new Map();
  }
  defineRole(role, permissions = [], inherits = []) {
    this.roles.set(role, {
      permissions: new Set(permissions),
      inherits: new Set(inherits)
    });
  }
  _flattenPermissions(role, visited = /* @__PURE__ */ new Set()) {
    if (visited.has(role)) return /* @__PURE__ */ new Set();
    visited.add(role);
    const current = this.roles.get(role);
    if (!current) return /* @__PURE__ */ new Set();
    const output = new Set(current.permissions);
    for (const parentRole of current.inherits) {
      for (const perm of this._flattenPermissions(parentRole, visited)) {
        output.add(perm);
      }
    }
    return output;
  }
  can(role, action, resource) {
    const key = `${action}:${resource}`;
    const wildcard = `${action}:*`;
    const perms = this._flattenPermissions(role);
    return perms.has(key) || perms.has(wildcard) || perms.has("*");
  }
};

// src/core/a01-access-control/PermissionChecker.js
var PermissionChecker = class {
  /**
   * @param {{rbacManager: import('./RBACManager.js').RBACManager, aclManager: import('./ACLManager.js').ACLManager}} options
   */
  constructor(options) {
    this.rbacManager = options.rbacManager;
    this.aclManager = options.aclManager;
  }
  check({ role, action, resource }) {
    const rbacAllowed = this.rbacManager.can(role, action, resource);
    const aclResult = this.aclManager.evaluate(resource, action);
    if (aclResult.effect === "deny") {
      return { allowed: false, reason: "acl_deny_override", metadata: { rbacAllowed, aclResult } };
    }
    if (!rbacAllowed) {
      return { allowed: false, reason: "rbac_denied", metadata: { rbacAllowed, aclResult } };
    }
    return { allowed: true, reason: "allowed", metadata: { rbacAllowed, aclResult } };
  }
};

// src/core/a01-access-control/types.js
var ACCESS_CONTROL_TYPES = {};

// src/core/a02-crypto-integrity/CryptoManager.js
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "node:crypto";

// src/core/error/SecurityError.js
var SecurityError = class extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {Record<string, unknown>} [details]
   */
  constructor(code, message, details = {}) {
    super(message);
    this.name = "SecurityError";
    this.code = code;
    this.details = details;
  }
};
var SecurityErrorCode = Object.freeze({
  INVALID_INPUT: "INVALID_INPUT",
  AUTH_REQUIRED: "AUTH_REQUIRED",
  TOKEN_EXPIRED: "TOKEN_EXPIRED",
  ACCESS_DENIED: "ACCESS_DENIED",
  CSRF_INVALID: "CSRF_INVALID",
  MISCONFIGURATION: "MISCONFIGURATION",
  SSRF_BLOCKED: "SSRF_BLOCKED",
  CRYPTO_ERROR: "CRYPTO_ERROR"
});

// src/core/a02-crypto-integrity/CryptoManager.js
function toBase64(buffer) {
  return Buffer.from(buffer).toString("base64");
}
function fromBase64(value) {
  return Buffer.from(value, "base64");
}
var CryptoManager = class {
  constructor(options = {}) {
    this.iterations = options.iterations || 21e4;
    this.keyLength = options.keyLength || 32;
    this.digest = options.digest || "sha256";
  }
  random(size = 32) {
    return randomBytes(size);
  }
  deriveKey(password, salt = this.random(16)) {
    const key = pbkdf2Sync(password, salt, this.iterations, this.keyLength, this.digest);
    return { key, salt };
  }
  encrypt(plaintext, key) {
    try {
      const iv = this.random(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
      const encrypted = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
      const tag = cipher.getAuthTag();
      return {
        ciphertext: toBase64(encrypted),
        iv: toBase64(iv),
        tag: toBase64(tag),
        alg: "aes-256-gcm"
      };
    } catch (error) {
      throw new SecurityError(SecurityErrorCode.CRYPTO_ERROR, "Encryption failed", { cause: String(error) });
    }
  }
  decrypt(payload, key) {
    try {
      const decipher = createDecipheriv("aes-256-gcm", key, fromBase64(payload.iv), { authTagLength: 16 });
      decipher.setAuthTag(fromBase64(payload.tag));
      const output = Buffer.concat([
        decipher.update(fromBase64(payload.ciphertext)),
        decipher.final()
      ]);
      return output.toString("utf8");
    } catch (error) {
      throw new SecurityError(SecurityErrorCode.CRYPTO_ERROR, "Decryption failed", { cause: String(error) });
    }
  }
};

// src/core/a02-crypto-integrity/SecretPolicy.js
var SecretPolicy = class _SecretPolicy {
  static minimumEntropyBits(secret) {
    const unique = new Set(String(secret || "").split(""));
    const charsetEstimate = Math.max(unique.size, 1);
    return Math.round(Math.log2(charsetEstimate) * String(secret || "").length);
  }
  static isEntropySufficient(secret, minimumBits = 60) {
    return _SecretPolicy.minimumEntropyBits(secret) >= minimumBits;
  }
  static isRotationWindowExceeded(issuedAtMs, maxAgeMs) {
    return Date.now() - issuedAtMs > maxAgeMs;
  }
};

// src/core/a03-injection-defense/InputSanitizer.js
var profiles = {
  strict: {
    stripTags: true,
    stripEventHandlers: true,
    stripScriptProtocols: true
  },
  moderate: {
    stripTags: false,
    stripEventHandlers: true,
    stripScriptProtocols: true
  }
};
var InputSanitizer = class {
  constructor(profile = "strict") {
    this.profile = profiles[profile] || profiles.strict;
  }
  sanitizeHTML(input) {
    let output = String(input || "");
    output = output.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "");
    if (this.profile.stripTags) {
      output = output.replace(/<[^>]+>/g, "");
    }
    if (this.profile.stripEventHandlers) {
      output = output.replace(/\son[a-z]+\s*=\s*(["']).*?\1/gi, "");
      output = output.replace(/\son[a-z]+\s*=\s*[^\s>]+/gi, "");
    }
    if (this.profile.stripScriptProtocols) {
      output = output.replace(/javascript\s*:/gi, "");
    }
    return output;
  }
};

// src/core/a03-injection-defense/InputValidator.js
var InputValidator = class {
  validateSchema(input, schema) {
    const errors = [];
    for (const [key, rule] of Object.entries(schema)) {
      const value = input[key];
      if (rule.required && (value === void 0 || value === null || value === "")) {
        errors.push({ field: key, code: "required", message: `${key} is required` });
        continue;
      }
      if (value === void 0 || value === null) continue;
      if (rule.type && typeof value !== rule.type) {
        errors.push({ field: key, code: "type", message: `${key} must be ${rule.type}` });
      }
      if (rule.minLength && String(value).length < rule.minLength) {
        errors.push({ field: key, code: "minLength", message: `${key} must be at least ${rule.minLength}` });
      }
      if (rule.maxLength && String(value).length > rule.maxLength) {
        errors.push({ field: key, code: "maxLength", message: `${key} must be at most ${rule.maxLength}` });
      }
      if (rule.pattern && !rule.pattern.test(String(value))) {
        errors.push({ field: key, code: "pattern", message: `${key} format is invalid` });
      }
    }
    return { valid: errors.length === 0, errors };
  }
  validateEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || ""));
  }
  validateUrl(value) {
    try {
      const url = new URL(String(value || ""));
      return ["http:", "https:"].includes(url.protocol);
    } catch {
      return false;
    }
  }
  validateLength(value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
    const len = String(value || "").length;
    return len >= min && len <= max;
  }
};

// src/core/a03-injection-defense/types.js
var INJECTION_DEFENSE_TYPES = {};

// src/core/a04-insecure-design-guard/ThreatModelGuard.js
var ThreatModelGuard = class {
  constructor({ transitions = {}, abuseRules = [] } = {}) {
    this.transitions = transitions;
    this.abuseRules = abuseRules;
  }
  canTransition(from, to) {
    const allowed = this.transitions[from] || [];
    return allowed.includes(to);
  }
  validateTransition(from, to) {
    return {
      valid: this.canTransition(from, to),
      reason: this.canTransition(from, to) ? "allowed" : "forbidden_transition"
    };
  }
  evaluateAbuseCase(context) {
    const violations = this.abuseRules.filter((rule) => !rule.check(context)).map((rule) => ({ id: rule.id, message: rule.message }));
    return {
      valid: violations.length === 0,
      violations
    };
  }
};

// src/core/a04-insecure-design-guard/DesignChecklist.js
var DesignChecklist = class {
  constructor(requiredControls = []) {
    this.requiredControls = requiredControls;
  }
  validate(controlSet) {
    const present = new Set(controlSet || []);
    const missing = this.requiredControls.filter((control) => !present.has(control));
    return {
      valid: missing.length === 0,
      missing
    };
  }
};

// src/core/a05-security-misconfiguration/SecurityConfigManager.js
var secureDefaults = {
  debug: false,
  cors: {
    origin: "self"
  },
  cookies: {
    secure: true,
    sameSite: "Strict"
  }
};
var SecurityConfigManager = class {
  constructor(config = {}) {
    this.config = {
      ...secureDefaults,
      ...config,
      cors: { ...secureDefaults.cors, ...config.cors || {} },
      cookies: { ...secureDefaults.cookies, ...config.cookies || {} }
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
};

// src/core/a05-security-misconfiguration/HardeningReporter.js
var HardeningReporter = class {
  constructor(configManager) {
    this.configManager = configManager;
  }
  generate() {
    const findings = this.configManager.detectUnsafeSettings();
    return findings.map((finding) => ({
      ...finding,
      recommendation: `Fix ${finding.id} to align with secure defaults.`
    }));
  }
};

// src/core/a06-vulnerable-components/DependencyRiskScanner.js
var DependencyRiskScanner = class {
  /**
   * @param {{scan: () => Promise<Array<{name:string,severity:string,fixedVersion?:string,currentVersion?:string}>>}} provider
   */
  constructor(provider) {
    this.provider = provider;
  }
  async scan() {
    const findings = await this.provider.scan();
    return findings.map((item) => ({
      package: item.name,
      severity: item.severity,
      fixedVersion: item.fixedVersion || null,
      currentVersion: item.currentVersion || null
    }));
  }
  async passesPolicy(threshold = "high") {
    const severities = ["low", "medium", "high", "critical"];
    const thresholdIdx = severities.indexOf(threshold);
    const results = await this.scan();
    const blocked = results.filter((r) => severities.indexOf(r.severity) >= thresholdIdx);
    return { pass: blocked.length === 0, blocked, results };
  }
};

// src/core/a06-vulnerable-components/ComponentPolicy.js
var ComponentPolicy = class {
  constructor({ allowlist = null, denylist = [], minVersions = {} } = {}) {
    this.allowlist = allowlist ? new Set(allowlist) : null;
    this.denylist = new Set(denylist);
    this.minVersions = minVersions;
  }
  evaluate(pkg) {
    if (this.allowlist && !this.allowlist.has(pkg.name)) {
      return { allowed: false, reason: "not_in_allowlist" };
    }
    if (this.denylist.has(pkg.name)) {
      return { allowed: false, reason: "in_denylist" };
    }
    const minVersion = this.minVersions[pkg.name];
    if (minVersion && String(pkg.version).localeCompare(minVersion, void 0, { numeric: true }) < 0) {
      return { allowed: false, reason: "below_minimum_version", required: minVersion };
    }
    return { allowed: true, reason: "allowed" };
  }
};

// src/core/a09-logging-monitoring/EventEmitter.js
var EventEmitter = class {
  constructor() {
    this.listeners = /* @__PURE__ */ new Map();
  }
  on(eventName, listener) {
    const existing = this.listeners.get(eventName) || /* @__PURE__ */ new Set();
    existing.add(listener);
    this.listeners.set(eventName, existing);
    return () => this.off(eventName, listener);
  }
  off(eventName, listener) {
    const existing = this.listeners.get(eventName);
    if (!existing) return;
    existing.delete(listener);
    if (existing.size === 0) this.listeners.delete(eventName);
  }
  emit(eventName, payload) {
    const existing = this.listeners.get(eventName);
    if (!existing) return;
    for (const listener of existing) {
      listener(payload);
    }
  }
};

// src/core/a07-auth-session/AuthManager.js
var AuthManager = class {
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
};

// src/core/a07-auth-session/TokenManager.js
function memoryAdapter() {
  const store = /* @__PURE__ */ new Map();
  return {
    getItem: (key) => store.get(key) || null,
    setItem: (key, value) => store.set(key, value),
    removeItem: (key) => store.delete(key)
  };
}
var TokenManager = class {
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
    this.events.emit("token:cleared", void 0);
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
};

// src/core/a07-auth-session/types.js
var AUTH_TYPES = {};

// src/core/a08-data-integrity/CSRFTokenManager.js
import { randomBytes as randomBytes2 } from "node:crypto";
function defaultStorage() {
  let value = null;
  return {
    get: () => value,
    set: (v) => {
      value = v;
    }
  };
}
var CSRFTokenManager = class {
  /**
   * @param {{storage?: {get:()=>string|null,set:(value:string)=>void}, tokenLength?: number}} [options]
   */
  constructor(options = {}) {
    this.storage = options.storage || defaultStorage();
    this.tokenLength = options.tokenLength || 32;
  }
  generateToken() {
    return randomBytes2(this.tokenLength).toString("base64url");
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
};

// src/core/a08-data-integrity/HTTPClient.js
var HTTPClient = class {
  /**
   * @param {{baseUrl?: string, csrfManager?: import('./CSRFTokenManager.js').CSRFTokenManager, tokenProvider?: ()=>Promise<string|null>|string|null, fetchImpl?: typeof fetch}} [options]
   */
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || "";
    this.csrfManager = options.csrfManager || null;
    this.tokenProvider = options.tokenProvider || null;
    this.fetchImpl = options.fetchImpl || fetch;
    this.requestInterceptors = [];
    this.responseInterceptors = [];
  }
  addRequestInterceptor(interceptor) {
    this.requestInterceptors.push(interceptor);
  }
  addResponseInterceptor(interceptor) {
    this.responseInterceptors.push(interceptor);
  }
  async request(url, options = {}) {
    let config = {
      ...options,
      headers: {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        ...options.headers || {}
      }
    };
    if (this.csrfManager) {
      config.headers = this.csrfManager.attach(config.headers);
    }
    if (this.tokenProvider) {
      const token = await this.tokenProvider();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
    }
    for (const interceptor of this.requestInterceptors) {
      config = await interceptor(config) || config;
    }
    const response = await this.fetchImpl(`${this.baseUrl}${url}`, config);
    const normalized = {
      ok: response.ok,
      status: response.status,
      headers: response.headers,
      data: null,
      error: null,
      raw: response
    };
    try {
      normalized.data = await response.clone().json();
    } catch {
      normalized.data = await response.text();
    }
    if (!response.ok) {
      normalized.error = new SecurityError(SecurityErrorCode.INVALID_INPUT, "HTTP request failed", {
        status: response.status,
        body: normalized.data
      });
    }
    for (const interceptor of this.responseInterceptors) {
      await interceptor(normalized);
    }
    return normalized;
  }
};

// src/core/a08-data-integrity/types.js
var DATA_INTEGRITY_TYPES = {};

// src/core/a09-logging-monitoring/SecurityLogger.js
var DEFAULT_REDACT_KEYS = ["password", "token", "secret", "authorization", "cookie"];
var SecurityLogger = class {
  /**
   * @param {{sink?: (entry: object) => void, redactKeys?: string[]}} [options]
   */
  constructor(options = {}) {
    this.sink = options.sink || ((entry) => console.log(JSON.stringify(entry)));
    this.redactKeys = options.redactKeys || DEFAULT_REDACT_KEYS;
  }
  redact(value) {
    if (Array.isArray(value)) {
      return value.map((item) => this.redact(item));
    }
    if (value && typeof value === "object") {
      const next = {};
      for (const [key, val] of Object.entries(value)) {
        const shouldRedact = this.redactKeys.some((k) => key.toLowerCase().includes(k));
        next[key] = shouldRedact ? "[REDACTED]" : this.redact(val);
      }
      return next;
    }
    return value;
  }
  log(level, event, details = {}) {
    this.sink({
      ts: (/* @__PURE__ */ new Date()).toISOString(),
      level,
      event,
      details: this.redact(details)
    });
  }
  info(event, details = {}) {
    this.log("info", event, details);
  }
  warn(event, details = {}) {
    this.log("warn", event, details);
  }
  error(event, details = {}) {
    this.log("error", event, details);
  }
};

// src/core/a10-ssrf-defense/SSRFGuard.js
var PRIVATE_IP_RANGES = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^192\.168\./,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i
];
var SSRFGuard = class {
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
};

// src/core/a10-ssrf-defense/SafeFetcher.js
var SafeFetcher = class {
  /**
   * @param {{guard: import('./SSRFGuard.js').SSRFGuard, fetchImpl?: typeof fetch}} options
   */
  constructor(options) {
    this.guard = options.guard;
    this.fetchImpl = options.fetchImpl || fetch;
  }
  async fetch(url, options = {}) {
    this.guard.validateUrl(url);
    return this.fetchImpl(url, options);
  }
};
export {
  ACCESS_CONTROL_TYPES,
  ACLManager,
  AUTH_TYPES,
  AuthManager,
  CSRFTokenManager,
  ComponentPolicy,
  CryptoManager,
  DATA_INTEGRITY_TYPES,
  DependencyRiskScanner,
  DesignChecklist,
  EventEmitter,
  HTTPClient,
  HardeningReporter,
  INJECTION_DEFENSE_TYPES,
  InputSanitizer,
  InputValidator,
  PermissionChecker,
  RBACManager,
  SSRFGuard,
  SafeFetcher,
  SecretPolicy,
  SecurityConfigManager,
  SecurityError,
  SecurityErrorCode,
  SecurityLogger,
  ThreatModelGuard,
  TokenManager
};
