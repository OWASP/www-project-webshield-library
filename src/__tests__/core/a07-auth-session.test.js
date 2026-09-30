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

  test("concurrent refreshIfNeeded calls share one refresh", async () => {
    let calls = 0;
    const manager = new TokenManager({
      now: () => 1000,
      onRefresh: async () => {
        calls++;
        await new Promise((resolve) => setTimeout(resolve, 10));
        return { accessToken: `access-${calls}`, refreshToken: `refresh-${calls}`, expiresAt: 5000 };
      }
    });
    manager.setTokens({ accessToken: "old", refreshToken: "r0", expiresAt: 500 });

    const tokens = await Promise.all([manager.refreshIfNeeded(), manager.refreshIfNeeded(), manager.refreshIfNeeded()]);
    expect(calls).toBe(1);
    expect(tokens).toEqual(["access-1", "access-1", "access-1"]);
  });

  test("a failed refresh can be retried", async () => {
    let attempt = 0;
    const manager = new TokenManager({
      now: () => 1000,
      onRefresh: async () => {
        attempt++;
        if (attempt === 1) throw new Error("network down");
        return { accessToken: "new", expiresAt: 5000 };
      }
    });
    manager.setTokens({ accessToken: "old", refreshToken: "r0", expiresAt: 500 });
    await expect(manager.refreshIfNeeded()).rejects.toThrow("network down");
    await expect(manager.refreshIfNeeded()).resolves.toBe("new");
  });

  test("keeps the current refresh token when the server does not rotate it", async () => {
    const manager = new TokenManager({ now: () => 1000, onRefresh: async () => ({ accessToken: "new", expiresAt: 5000 }) });
    manager.setTokens({ accessToken: "old", refreshToken: "long-lived", expiresAt: 500 });
    await manager.refreshIfNeeded();
    expect(manager.getTokens()).toEqual({ accessToken: "new", refreshToken: "long-lived", expiresAt: 5000 });
  });

  describe("a refresh in flight when the session changes", () => {
    const setup = () => {
      let release;
      const manager = new TokenManager({ now: () => 1000, onRefresh: () => new Promise((resolve) => (release = resolve)) });
      manager.setTokens({ accessToken: "old", refreshToken: "r0", expiresAt: 500 });
      return { manager, release: (value) => release(value) };
    };

    test("logout wins: the late refresh result is discarded", async () => {
      const { manager, release } = setup();
      const refreshing = manager.refreshIfNeeded();
      manager.clearTokens();
      release({ accessToken: "new", refreshToken: "r1", expiresAt: 9999 });
      await expect(refreshing).rejects.toMatchObject({ code: SecurityErrorCode.AUTH_REQUIRED });
      expect(manager.getTokens()).toBeNull();
    });

    test("a new login wins over a refresh of the previous session", async () => {
      const { manager, release } = setup();
      const refreshing = manager.refreshIfNeeded();
      manager.setTokens({ accessToken: "second-user", refreshToken: "r9", expiresAt: 9999 });
      release({ accessToken: "first-user-refreshed", refreshToken: "r1", expiresAt: 9999 });
      await expect(refreshing).rejects.toMatchObject({ code: SecurityErrorCode.AUTH_REQUIRED });
      expect(manager.getAccessToken()).toBe("second-user");
    });

    test("a refresh started after logout and login is not joined to the stale one", async () => {
      let calls = 0;
      const releases = [];
      const manager = new TokenManager({
        now: () => 1000,
        onRefresh: () => {
          calls++;
          return new Promise((resolve) => releases.push(resolve));
        }
      });
      manager.setTokens({ accessToken: "a", refreshToken: "r0", expiresAt: 500 });
      const stale = manager.refreshIfNeeded();
      manager.clearTokens();
      manager.setTokens({ accessToken: "b", refreshToken: "r1", expiresAt: 500 });
      const fresh = manager.refreshIfNeeded();
      expect(calls).toBe(2);
      releases[1]({ accessToken: "b2", expiresAt: 9999 });
      releases[0]({ accessToken: "a2", expiresAt: 9999 });
      await expect(fresh).resolves.toBe("b2");
      await expect(stale).rejects.toMatchObject({ code: SecurityErrorCode.AUTH_REQUIRED });
      expect(manager.getTokens()).toEqual({ accessToken: "b2", refreshToken: "r1", expiresAt: 9999 });
    });
  });
});
