import { describe, expect, test } from "@jest/globals";
import { AuthManager, TokenManager } from "../../core/a07-auth-session/index.js";
import { SecurityErrorCode } from "../../core/error/index.js";

describe("A07 auth/session", () => {
  test("flags expired tokens", () => {
    const manager = new TokenManager({ now: () => 2000 });
    manager.setTokens({ accessToken: "a", expiresAt: 1000 });
    expect(manager.getAccessToken()).toBeNull();
  });

  test("refreshes through configured refresh hook", async () => {
    const manager = new TokenManager({
      now: () => 2000,
      onRefresh: async () => ({ accessToken: "new-token", refreshToken: "r2", expiresAt: 4000 })
    });
    manager.setTokens({ accessToken: "old", refreshToken: "r1", expiresAt: 1000 });
    const token = await manager.refreshIfNeeded();
    expect(token).toBe("new-token");
  });

  test("throws when an expired token cannot be refreshed", async () => {
    const manager = new TokenManager({ now: () => 2000 });
    manager.setTokens({ accessToken: "old", refreshToken: "r1", expiresAt: 1000 });

    await expect(manager.refreshIfNeeded()).rejects.toMatchObject({ code: SecurityErrorCode.TOKEN_EXPIRED });
  });

  test("auth manager tracks authenticated state", () => {
    const tokenManager = new TokenManager({ now: () => 1000 });
    tokenManager.setTokens({ accessToken: "live", expiresAt: 9999 });
    const auth = new AuthManager({ tokenManager });
    auth.setSession({ userId: "u1", roles: ["admin"] });
    expect(auth.isAuthenticated()).toBe(true);
    auth.clearSession();
    expect(auth.isAuthenticated()).toBe(false);
  });

  test("emits auth lifecycle events for set and clear session", () => {
    const tokenManager = new TokenManager({ now: () => 1000 });
    tokenManager.setTokens({ accessToken: "live", expiresAt: 9999 });
    const auth = new AuthManager({ tokenManager });
    const seen = [];

    auth.events.on("auth:changed", (session) => {
      seen.push(session);
    });

    auth.setSession({ userId: "u1", roles: ["admin"] });
    auth.clearSession();

    expect(seen).toEqual([
      { userId: "u1", roles: ["admin"], metadata: {} },
      null
    ]);
  });
});