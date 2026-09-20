import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ACLManager,
  AuthManager,
  ComponentPolicy,
  CryptoManager,
  CSRFTokenManager,
  DependencyRiskScanner,
  DesignChecklist,
  EventEmitter,
  HardeningReporter,
  HTTPClient,
  InputSanitizer,
  InputValidator,
  PermissionChecker,
  RBACManager,
  SafeFetcher,
  SecretPolicy,
  SecurityConfigManager,
  SecurityError,
  SecurityErrorCode,
  SecurityLogger,
  SSRFGuard,
  TokenManager
} from "@owasp-core/owl";
import { NpmAuditProvider } from "./npm-audit-provider.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "../..");
const ROTATION_WINDOW_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const MASTER_PASSPHRASE = process.env.VAULT_MASTER_PASSPHRASE || "correct-horse-battery-staple-2026!";

export class SecretsVault {
  constructor() {
    // A01 — role -> permission set. Wildcard resources ("reveal:*") mean an
    // ACL entry scoped to one specific secret ("secret:AWS_KEY") can still
    // override the grant for just that secret, without needing a distinct
    // RBAC permission per secret name.
    this.rbacManager = new RBACManager();
    this.rbacManager.defineRole("viewer", ["read:*"]);
    this.rbacManager.defineRole("contributor", ["write:*"], ["viewer"]);
    this.rbacManager.defineRole("admin", ["reveal:*", "rotate:*", "delete:*", "manage:*"], ["contributor"]);

    this.aclManager = new ACLManager();
    this.permissionChecker = new PermissionChecker({ rbacManager: this.rbacManager, aclManager: this.aclManager });

    // A07 — session/token lifecycle.
    this.tokenManager = new TokenManager({ now: () => Date.now() });
    this.authManager = new AuthManager({ tokenManager: this.tokenManager });

    // A02 — one master key for the vault, derived once from a passphrase.
    this.cryptoManager = new CryptoManager();
    const { key, salt } = this.cryptoManager.deriveKey(MASTER_PASSPHRASE);
    this.masterKey = key;
    this.masterSalt = salt;

    // A03 — validation + sanitization for secret metadata.
    this.sanitizer = new InputSanitizer("strict");
    this.validator = new InputValidator();

    // A04 — a secret's lifecycle, plus abuse-case checks on its metadata.
    this.lifecycleGuard = {
      transitions: { active: ["rotating", "revoked"], rotating: ["active"], revoked: [] },
      abuseRules: [
        { id: "name_too_long", message: "Secret name must stay under 64 characters", check: (ctx) => ctx.name.length <= 64 },
        { id: "description_too_long", message: "Description must stay under 200 characters", check: (ctx) => ctx.description.length <= 200 }
      ]
    };
    this.designChecklist = new DesignChecklist([
      "role_based_access_control",
      "per_secret_deny_override",
      "aes_256_gcm_encryption_at_rest",
      "secret_strength_check",
      "csrf_protection",
      "ssrf_guard",
      "redacted_structured_logging",
      "dependency_risk_scanning"
    ]);

    // A05 — server-config hardening, checked once at boot.
    this.configManager = new SecurityConfigManager({
      debug: false,
      cors: { origin: "self" },
      cookies: { secure: true, sameSite: "Strict" }
    });
    this.hardeningReporter = new HardeningReporter(this.configManager);

    // A06 — a REAL npm-audit-backed scan of this repo, not a fixture.
    this.dependencyScanner = new DependencyRiskScanner(new NpmAuditProvider({ cwd: REPO_ROOT }));
    this.componentPolicy = new ComponentPolicy({ denylist: [], minVersions: {} });

    // A08 — CSRF token manager works for real here (Node has native crypto),
    // unlike the browser example, which has to mock it.
    this.csrfManager = new CSRFTokenManager();
    this.csrfManager.rotateToken();
    // `assertResolvedSafe()` does a real DNS lookup for non-literal hostnames
    // in Node (unlike the browser build, which skips it entirely). A custom
    // `resolveHost` keeps this demo deterministic and offline — "hooks.example.com"
    // resolves to a fixed, non-private TEST-NET-3 address (RFC 5737) instead of
    // depending on real DNS for a domain that doesn't actually have that record.
    this.ssrfGuard = new SSRFGuard({
      resolveHost: async (hostname) => (hostname === "hooks.example.com" ? ["203.0.113.10"] : [])
    });
    this.httpClient = new HTTPClient({
      baseUrl: "https://hooks.example.com",
      csrfManager: this.csrfManager,
      tokenProvider: () => this.tokenManager.getAccessToken(),
      outboundRequestPolicy: this.ssrfGuard,
      fetchImpl: mockFetch
    });

    // A10 — outbound URL validation for the "notify on reveal" webhook feature.
    this.safeFetcher = new SafeFetcher({ guard: this.ssrfGuard, fetchImpl: mockFetch });

    // A09 — redaction-first logging + an in-memory audit trail.
    this.events = new EventEmitter();
    this.auditLog = [];
    this.events.on("vault:event", (entry) => this.auditLog.push(entry));
    this.logger = new SecurityLogger({
      sink: (entry) => this.events.emit("vault:event", entry)
    });

    this.secrets = new Map();
  }

  requirePermission(role, action, resource) {
    const decision = this.permissionChecker.check({ role, action, resource });
    if (!decision.allowed) {
      this.logger.warn("permission.denied", { role, action, resource, reason: decision.reason });
      throw new SecurityError(SecurityErrorCode.ACCESS_DENIED, `${role} cannot ${action} ${resource}`, decision);
    }
    return decision;
  }

  createSecret({ role, name, value, description = "" }) {
    this.requirePermission(role, "write", "secret");

    const validation = this.validator.validateSchema(
      { name, value },
      { name: { required: true, type: "string", minLength: 2, maxLength: 64 }, value: { required: true, type: "string", minLength: 1 } }
    );
    if (!validation.valid) {
      throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "Secret metadata failed validation", validation);
    }

    const cleanName = this.sanitizer.sanitizeHTML(name);
    const cleanDescription = this.sanitizer.sanitizeHTML(description);
    const abuseCheck = this.evaluateAbuseCase({ name: cleanName, description: cleanDescription });
    if (!abuseCheck.valid) {
      throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "Secret metadata failed abuse-case checks", abuseCheck);
    }

    const entropyBits = SecretPolicy.minimumEntropyBits(value);
    const strengthWarning = SecretPolicy.isEntropySufficient(value, 40)
      ? null
      : `Stored value is weak (${entropyBits} bits of estimated entropy) — consider a stronger secret.`;

    const payload = this.cryptoManager.encrypt(value, this.masterKey);

    this.secrets.set(cleanName, {
      description: cleanDescription,
      payload,
      status: "active",
      issuedAt: Date.now()
    });

    this.logger.info("secret.created", { name: cleanName, entropyBits });
    this.events.emit("vault:event", { ts: new Date().toISOString(), type: "secret_created", actor: role, name: cleanName });

    return { name: cleanName, entropyBits, strengthWarning };
  }

  evaluateAbuseCase(context) {
    const violations = this.lifecycleGuard.abuseRules.filter((rule) => !rule.check(context)).map((r) => r.message);
    return { valid: violations.length === 0, violations };
  }

  validateTransition(from, to) {
    return (this.lifecycleGuard.transitions[from] || []).includes(to);
  }

  revealSecret({ role, name }) {
    // Permission is checked before confirming the secret exists, so an
    // unauthorized caller gets the same ACCESS_DENIED either way instead of
    // an error that leaks whether a given secret name exists in the vault.
    this.requirePermission(role, "reveal", `secret:${name}`);
    const record = this.getRecordOrThrow(name);

    const value = this.cryptoManager.decrypt(record.payload, this.masterKey);

    // Logged under `secretValue` deliberately — that key name matches
    // SecurityLogger's default redact-key list ("...secret..."), so the
    // plaintext is automatically replaced with "[REDACTED]" in the sink
    // output even though this call site never redacts it itself.
    this.logger.info("secret.revealed", { name, secretValue: value });
    this.events.emit("vault:event", { ts: new Date().toISOString(), type: "secret_revealed", actor: role, name });

    return value;
  }

  freezeSecret({ role, name, frozen }) {
    this.requirePermission(role, "manage", `secret:${name}`);
    this.getRecordOrThrow(name);
    // Per-secret ACL entry — overrides even an admin's RBAC "reveal:*" grant
    // for this one resource string, the same deny-override mechanism the
    // React example demonstrates at the resource-type level, just scoped
    // down to a single secret here.
    this.aclManager.setPolicy(`secret:${name}`, "reveal", frozen ? "deny" : "allow");
    this.logger.info(frozen ? "secret.frozen" : "secret.unfrozen", { name, actor: role });
    this.events.emit("vault:event", { ts: new Date().toISOString(), type: frozen ? "secret_frozen" : "secret_unfrozen", actor: role, name });
  }

  rotateSecret({ role, name, newValue }) {
    this.requirePermission(role, "rotate", `secret:${name}`);
    const record = this.getRecordOrThrow(name);

    if (!this.validateTransition("active", "rotating") || !this.validateTransition("rotating", "active")) {
      throw new SecurityError(SecurityErrorCode.MISCONFIGURATION, "Rotation lifecycle transition is not permitted");
    }

    const entropyBits = SecretPolicy.minimumEntropyBits(newValue);
    record.payload = this.cryptoManager.encrypt(newValue, this.masterKey);
    record.issuedAt = Date.now();
    record.status = "active";

    this.logger.info("secret.rotated", { name, entropyBits });
    this.events.emit("vault:event", { ts: new Date().toISOString(), type: "secret_rotated", actor: role, name });
    return { name, entropyBits };
  }

  deleteSecret({ role, name }) {
    this.requirePermission(role, "delete", `secret:${name}`);
    this.getRecordOrThrow(name);
    this.secrets.delete(name);
    this.logger.info("secret.deleted", { name });
    this.events.emit("vault:event", { ts: new Date().toISOString(), type: "secret_deleted", actor: role, name });
  }

  listSecrets({ role }) {
    this.requirePermission(role, "read", "secret");
    return Array.from(this.secrets.entries()).map(([name, record]) => ({
      name,
      description: record.description,
      status: record.status,
      ageMs: Date.now() - record.issuedAt,
      rotationOverdue: SecretPolicy.isRotationWindowExceeded(record.issuedAt, ROTATION_WINDOW_MS)
    }));
  }

  getRecordOrThrow(name) {
    const record = this.secrets.get(name);
    if (!record) {
      throw new SecurityError(SecurityErrorCode.INVALID_INPUT, `No such secret: ${name}`);
    }
    return record;
  }

  runHardeningCheck() {
    return this.hardeningReporter.generate();
  }

  runDesignChecklist(satisfiedControls) {
    return this.designChecklist.validate(satisfiedControls);
  }

  async runDependencyScan(threshold = "high") {
    return this.dependencyScanner.passesPolicy(threshold);
  }

  async notifyWebhook(url, payload) {
    const response = await this.safeFetcher.fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    return response.json();
  }
}

async function mockFetch(url, options = {}) {
  return {
    ok: true,
    status: 200,
    headers: new Map(),
    clone() {
      return this;
    },
    async json() {
      return { delivered: true, url, method: options.method || "GET" };
    },
    async text() {
      return "ok";
    }
  };
}
