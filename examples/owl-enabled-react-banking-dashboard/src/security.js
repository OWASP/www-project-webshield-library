// Plain root-package imports — safe now that both @owasp-webshield/core and
// @owasp-webshield/react ship a "browser" build where CryptoManager (the one
// piece with no browser equivalent) is a same-shaped throwing stub instead of
// a build-breaking import. See the FAQ: "Can I use OWL in a browser bundle?"
import {
  ComponentPolicy,
  createOwlClient,
  CryptoManager,
  CSRFTokenManager,
  DesignChecklist,
  HTTPClient,
  InputValidator,
  SecretPolicy,
  SSRFGuard
} from "@owasp-webshield/core";

// Demo session length — short enough that the token-refresh flow (A07) is
// actually observable while you use the app, instead of a 15-minute wait.
export const TOKEN_TTL_MS = 90 * 1000;

const owl = createOwlClient({
  roles: {
    // customer: manages their own accounts and can initiate transfers.
    customer: {
      permissions: ["read:accounts", "reveal:account-number", "create:transfer"]
    },
    // teller: everything a customer can do, plus approving ordinary transfers
    // and read-only visibility into audit history and vendor integrations.
    teller: {
      permissions: ["approve:transfer", "read:audit", "read:integrations"],
      inherits: ["customer"]
    },
    // admin: everything a teller can do, plus managing integrations/webhooks
    // and security settings. Note "approve:large-transfer" below — granted
    // here, but blocked for everyone by an ACL deny-override (see acl[]).
    admin: {
      permissions: ["approve:large-transfer", "manage:integrations", "manage:webhooks", "manage:security"],
      inherits: ["teller"]
    }
  },
  acl: [
    { resource: "transfer", action: "create", effect: "allow" },
    { resource: "transfer", action: "approve", effect: "allow" },
    // Deny-override demo: RBAC grants "approve:large-transfer" to admins,
    // but this ACL policy blocks it for every role, admin included. This
    // models real-world "maker-checker" dual control — a transfer above the
    // policy ceiling needs a second, out-of-band approval that no single
    // role can grant itself from inside this UI.
    { resource: "large-transfer", action: "approve", effect: "deny" },
    { resource: "security", action: "manage", effect: "allow" }
  ],
  token: {
    now: () => Date.now(),
    // Real refresh flow: TokenManager.refreshIfNeeded() calls this with the
    // stored refresh token whenever the access token has expired.
    onRefresh: async (refreshToken) => ({
      accessToken: `demo.refreshed.${Math.random().toString(36).slice(2, 10)}`,
      expiresAt: Date.now() + TOKEN_TTL_MS,
      refreshToken
    })
  },
  logger: { sink: (entry) => console.log("[owl-bank]", entry) }
});
const { tokenManager, authManager, rbacManager, aclManager, events, logger } = owl;

export const csrfManager = new CSRFTokenManager();
csrfManager.rotateToken();

export const ssrfGuard = new SSRFGuard();

function mockResponse(body, status = 200) {
  return {
    ok: status < 400,
    status,
    headers: {},
    clone: () => ({ json: async () => body }),
    text: async () => JSON.stringify(body)
  };
}

// Accounts the UI ever sees: masked identity + balance only. The real PAN
// (primary account number) never lives in frontend state — it's only ever
// returned, briefly, by a "vault" call the mock fetchImpl below answers.
export const ACCOUNTS = [
  { id: "ACC-1001", label: "Everyday Checking", type: "Checking", last4: "4821", balance: 8420.55 },
  { id: "ACC-1002", label: "High-Yield Savings", type: "Savings", last4: "7734", balance: 21890.1 },
  { id: "ACC-2001", label: "Business Operating", type: "Business Checking", last4: "1190", balance: 154302.77 }
];

// Simulates a Node-only vault microservice — the one place the full account
// number exists. The browser bundle never holds this map; it only receives
// one number at a time, on demand, over the CSRF/auth-protected apiClient.
const VAULT = {
  "ACC-1001": "4400 1234 5678 4821",
  "ACC-1002": "4400 8823 9012 7734",
  "ACC-2001": "4400 5561 0043 1190"
};

async function bankFetchImpl(url, options = {}) {
  await new Promise((resolve) => setTimeout(resolve, 180));
  if (url.includes("/vault/reveal")) {
    const body = JSON.parse(options.body || "{}");
    const fullNumber = VAULT[body.accountId];
    return fullNumber ? mockResponse({ fullNumber }) : mockResponse({ error: "not_found" }, 404);
  }
  if (url.includes("/transfers/execute")) {
    return mockResponse({ status: "completed", reference: `TXN-${Math.random().toString(36).slice(2, 8).toUpperCase()}` });
  }
  if (url.includes("/transfers/approve")) {
    return mockResponse({ status: "approved" });
  }
  if (url.includes("/webhooks/register")) {
    return mockResponse({ status: "registered" });
  }
  return mockResponse({ status: "ok", source: "owl-bank-mock-api" });
}

export const apiClient = new HTTPClient({
  baseUrl: "https://api.bank.example.com",
  csrfManager,
  tokenProvider: () => tokenManager.getAccessToken(),
  outboundRequestPolicy: ssrfGuard,
  fetchImpl: bankFetchImpl
});

export const inputValidator = new InputValidator();

export const designChecklist = new DesignChecklist([
  "role_based_access_control",
  "maker_checker_dual_control",
  "mfa_required_for_transfer",
  "csrf_protection",
  "input_sanitization",
  "ssrf_guarded_webhooks",
  "structured_audit_logging"
]);

export const componentPolicy = new ComponentPolicy({
  denylist: ["legacy-kyc-sdk"],
  minVersions: { "payment-gateway-sdk": "4.2.0" }
});

export const dependencyProvider = {
  async scan() {
    return [
      { name: "legacy-kyc-sdk", severity: "critical", currentVersion: "1.0.2", fixedVersion: "2.0.0" },
      { name: "payment-gateway-sdk", severity: "high", currentVersion: "4.1.3", fixedVersion: "4.2.0" },
      { name: "fx-rates-client", severity: "low", currentVersion: "2.3.0", fixedVersion: "2.3.1" }
    ];
  }
};

const DEMO_USERS = {
  customer: { userId: "jordan", roles: ["customer"] },
  teller: { userId: "morgan", roles: ["teller"] },
  admin: { userId: "hana", roles: ["admin"] }
};

// A persistent buffer, not just a pub/sub relay: EventEmitter has no replay,
// so a listener only added when the Audit Log tab mounts would miss every
// event emitted while some other tab was active. This listener is registered
// once, at module load, so nothing is ever lost regardless of which panel —
// or none — is currently mounted.
export const activityLog = [];
events.on("activity", (entry) => {
  activityLog.unshift(entry);
  if (activityLog.length > 200) activityLog.length = 200;
});

function emitActivity(type, actor, details = {}) {
  events.emit("activity", { ts: new Date().toISOString(), type, actor, details });
}

export function login(role) {
  const user = DEMO_USERS[role];
  if (!user) return;
  tokenManager.setTokens({
    accessToken: `demo.${role}.${csrfManager.generateToken().slice(0, 12)}`,
    refreshToken: `refresh.${role}.${csrfManager.generateToken().slice(0, 12)}`,
    expiresAt: Date.now() + TOKEN_TTL_MS
  });
  csrfManager.rotateToken();
  authManager.setSession(user);
  logger.info("auth.login", { userId: user.userId, role });
  emitActivity("login", user.userId);
}

export function logout() {
  const session = authManager.getSession();
  logger.info("auth.logout", { userId: session?.userId });
  emitActivity("logout", session?.userId || "unknown");
  authManager.clearSession();
}

export async function refreshSession() {
  const session = authManager.getSession();
  try {
    await tokenManager.refreshIfNeeded();
    logger.info("auth.token_refreshed", { userId: session?.userId });
    emitActivity("session_refreshed", session?.userId || "unknown");
    return true;
  } catch (error) {
    logger.warn("auth.token_refresh_failed", { userId: session?.userId, reason: error.message });
    emitActivity("session_refresh_failed", session?.userId || "unknown", { reason: error.message });
    return false;
  }
}

export const security = {
  tokenManager,
  authManager,
  rbacManager,
  aclManager,
  events,
  logger,
  apiClient,
  ssrfGuard,
  inputValidator,
  designChecklist,
  componentPolicy,
  dependencyProvider,
  login,
  logout,
  refreshSession,
  emitActivity
};

// CryptoManager itself is exported so the Accounts panel can demonstrate —
// live, in the browser — that this class intentionally refuses to run
// outside Node rather than silently falling back to weaker crypto.
export { CryptoManager, SecretPolicy };
