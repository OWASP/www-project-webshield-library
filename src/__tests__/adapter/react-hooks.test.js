import React from "react";
import { describe, expect, jest, test } from "@jest/globals";
import { act, renderHook } from "@testing-library/react";
import {
  ACLProvider,
  AuthProvider,
  RBACProvider,
  useACL,
  useAuth,
  useAuthToken,
  usePermission
} from "../../adapters/react/index.js";
import { ACLManager, AuthManager, RBACManager, TokenManager } from "../../core/index.js";

function wrapperFactory({ authManager, aclManager, rbacManager }) {
  return function Wrapper({ children }) {
    return React.createElement(
      AuthProvider,
      { authManager },
      React.createElement(
        ACLProvider,
        { aclManager },
        React.createElement(RBACProvider, { rbacManager }, children)
      )
    );
  };
}

describe("React adapter hooks", () => {
  test("useAuth exposes authenticated state", () => {
    const tokenManager = new TokenManager({ now: () => 0 });
    tokenManager.setTokens({ accessToken: "token", expiresAt: 999999 });
    const authManager = new AuthManager({ tokenManager });
    authManager.setSession({ userId: "1", roles: ["admin"] });

    const aclManager = new ACLManager();
    const rbacManager = new RBACManager();
    rbacManager.defineRole("admin", ["read:reports"]);
    const wrapper = wrapperFactory({ authManager, aclManager, rbacManager });

    const { result } = renderHook(() => useAuth(), { wrapper });
    expect(result.current.isAuthenticated).toBe(true);
  });

  test("usePermission combines RBAC with ACL", () => {
    const tokenManager = new TokenManager({ now: () => 0 });
    tokenManager.setTokens({ accessToken: "token", expiresAt: 999999 });
    const authManager = new AuthManager({ tokenManager });
    authManager.setSession({ userId: "1", roles: ["admin"] });

    const aclManager = new ACLManager();
    aclManager.setPolicy("reports", "read", "deny");
    const rbacManager = new RBACManager();
    rbacManager.defineRole("admin", ["read:reports"]);

    const wrapper = wrapperFactory({ authManager, aclManager, rbacManager });
    const { result } = renderHook(() => usePermission("read", "reports"), { wrapper });
    expect(result.current.allowed).toBe(false);
    expect(result.current.reason).toBe("acl_deny_override");
  });

  test("useAuthToken returns current access token", () => {
    const tokenManager = new TokenManager({ now: () => 0 });
    tokenManager.setTokens({ accessToken: "token-123", expiresAt: 999999 });
    const authManager = new AuthManager({ tokenManager });
    authManager.setSession({ userId: "1", roles: ["admin"] });
    const aclManager = new ACLManager();
    const rbacManager = new RBACManager();
    const wrapper = wrapperFactory({ authManager, aclManager, rbacManager });

    const { result } = renderHook(() => useAuthToken(), { wrapper });
    expect(result.current).toBe("token-123");
  });

   test("useAuthToken clears when the session is cleared", () => {
    const tokenManager = new TokenManager({ now: () => 0 });
    tokenManager.setTokens({ accessToken: "token-123", expiresAt: 999999 });
    const authManager = new AuthManager({ tokenManager });
    authManager.setSession({ userId: "1", roles: ["admin"] });
    const aclManager = new ACLManager();
    const rbacManager = new RBACManager();
    const wrapper = wrapperFactory({ authManager, aclManager, rbacManager });

    const { result } = renderHook(() => useAuthToken(), { wrapper });
    expect(result.current).toBe("token-123");

    act(() => {
      authManager.clearSession();
    });

    expect(result.current).toBeNull();
  });

  test("useACL exposes ACL manager from provider", () => {
    const tokenManager = new TokenManager({ now: () => 0 });
    tokenManager.setTokens({ accessToken: "token", expiresAt: 999999 });
    const authManager = new AuthManager({ tokenManager });
    authManager.setSession({ userId: "1", roles: ["admin"] });
    const aclManager = new ACLManager();
    const rbacManager = new RBACManager();
    const wrapper = wrapperFactory({ authManager, aclManager, rbacManager });

    const { result } = renderHook(() => useACL(), { wrapper });
    expect(result.current).toBe(aclManager);
  });

  test("useAuth reacts when tokens are cleared outside clearSession", () => {
    const tokenManager = new TokenManager({ now: () => 0 });
    tokenManager.setTokens({ accessToken: "token", expiresAt: 999999 });
    const authManager = new AuthManager({ tokenManager });
    authManager.setSession({ userId: "1", roles: ["admin"] });
    const aclManager = new ACLManager();
    const rbacManager = new RBACManager();
    const wrapper = wrapperFactory({ authManager, aclManager, rbacManager });

    const { result } = renderHook(() => useAuth(), { wrapper });
    expect(result.current.isAuthenticated).toBe(true);

    act(() => {
      tokenManager.clearTokens();
    });

    expect(result.current.isAuthenticated).toBe(false);
  });

  test("useAuth marks the session unauthenticated when the access token expires", () => {
    jest.useFakeTimers();
    try {
      const tokenManager = new TokenManager();
      tokenManager.setTokens({ accessToken: "token", expiresAt: Date.now() + 20 });
      const authManager = new AuthManager({ tokenManager });
      authManager.setSession({ userId: "1", roles: ["admin"] });
      const aclManager = new ACLManager();
      const rbacManager = new RBACManager();
      const wrapper = wrapperFactory({ authManager, aclManager, rbacManager });

      const { result } = renderHook(() => useAuth(), { wrapper });
      expect(result.current.isAuthenticated).toBe(true);

      act(() => {
        jest.advanceTimersByTime(25);
      });

      expect(result.current.isAuthenticated).toBe(false);
    } finally {
      jest.useRealTimers();
    }
  });
});