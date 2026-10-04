/**
 * @jest-environment node
 */
import { afterEach, describe, expect, jest, test } from "@jest/globals";
import { createSSRApp, defineComponent, h } from "vue";
import { renderToString } from "vue/server-renderer";
import { createOwlClient } from "@owasp-webshield/core";
import { AuthGate, createOwl, PermissionGate, useAuth, vSafeHtml } from "@owasp-webshield/vue";

// Per-request app factory, as the docs recommend for server-side rendering.
function renderFor(user) {
  const client = createOwlClient({ roles: { editor: { permissions: ["write:reports"] }, viewer: { permissions: ["read:*"] } } });
  if (user) {
    client.tokenManager.setTokens({ accessToken: `tok-${user.id}`, expiresAt: Date.now() + 60_000 });
    client.authManager.setSession({ userId: user.id, roles: user.roles });
  }
  const Page = defineComponent({
    setup() {
      const { session } = useAuth();
      return () =>
        h("main", [
          h("span", { id: "user" }, session.value?.userId ?? "anon"),
          h(AuthGate, null, { default: () => "in", fallback: () => "out" }),
          h(PermissionGate, { action: "write", resource: "reports" }, { default: () => "writer", fallback: () => "reader" })
        ]);
    }
  });
  return renderToString(createSSRApp(Page).use(createOwl({ client })));
}

afterEach(() => {
  jest.useRealTimers();
});

describe("server-side rendering", () => {
  test("schedules no token-expiry timer on the server", () => {
    jest.useFakeTimers();
    const client = createOwlClient();
    client.tokenManager.setTokens({ accessToken: "t", expiresAt: Date.now() + 60_000 });
    client.authManager.setSession({ userId: "u", roles: [] });
    const owl = createOwl({ client });
    expect(jest.getTimerCount()).toBe(0);
    client.tokenManager.setTokens({ accessToken: "t2", expiresAt: Date.now() + 60_000 });
    expect(jest.getTimerCount()).toBe(0);
    expect(owl.context.auth.isAuthenticated.value).toBe(true);
  });

  test("concurrent renders keep each request's user", async () => {
    const users = [{ id: "alice", roles: ["editor"] }, { id: "bob", roles: ["viewer"] }, null];
    const html = await Promise.all(Array.from({ length: 30 }, (_, i) => renderFor(users[i % 3])));
    html.forEach((page, i) => {
      const user = users[i % 3];
      expect(page).toContain(`<span id="user">${user ? user.id : "anon"}</span>`);
      expect(page).toContain(user ? "in" : "out");
      expect(page).toContain(user?.roles.includes("editor") ? "writer" : "reader");
    });
  });

  // Template-based SSR of the directive is covered in vue.test.js; this checks the
  // SSR hook itself for each binding form.
  test("v-safe-html's SSR hook returns sanitized innerHTML", () => {
    const strict = vSafeHtml.getSSRProps({ value: '<b>x</b><img src=x onerror="alert(1)">' });
    const moderate = vSafeHtml.getSSRProps({ value: '<b>x</b><a href="javascript:alert(1)">y</a>', arg: "moderate" });
    const object = vSafeHtml.getSSRProps({ value: { html: '<i class="a b">i</i>', profile: "moderate", allowedClasses: ["a"] } });
    expect(strict.innerHTML).not.toMatch(/<b>|<img|onerror/);
    expect(moderate.innerHTML).toContain("<b>x</b>");
    expect(moderate.innerHTML).not.toContain("javascript:");
    expect(object.innerHTML).toBe('<i class="a">i</i>');
  });
});
