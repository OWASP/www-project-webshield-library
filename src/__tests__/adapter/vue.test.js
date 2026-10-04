/**
 * @jest-environment jsdom
 * @jest-environment-options {"customExportConditions": ["node", "node-addons"]}
 */
import { afterEach, describe, expect, jest, test } from "@jest/globals";
import { mount } from "@vue/test-utils";
import { createApp, createSSRApp, defineComponent, h, nextTick, ref } from "vue";
import { renderToString } from "vue/server-renderer";
import { createMemoryHistory, createRouter } from "vue-router";
import { createOwlClient, HTTPClient, SafeFetcher } from "@owasp-webshield/core";
import {
  AuthGate,
  createOwl,
  createOwlRouterGuard,
  PermissionGate,
  provideOwl,
  SanitizedText,
  SecurityAlert,
  useAuth,
  useAuthToken,
  useDependencyRiskScanner,
  useHardeningReport,
  useInputSanitizer,
  usePermission,
  useSafeFetcher,
  useSecureHttpClient,
  useSecurityMonitoring,
  useThreatModelGuard,
  vSafeHtml
} from "@owasp-webshield/vue";

function createClient() {
  return createOwlClient({
    roles: {
      viewer: { permissions: ["read:*"] },
      editor: { permissions: ["write:reports"], inherits: ["viewer"] }
    },
    acl: [{ resource: "report:locked", action: "read", effect: "deny" }]
  });
}

function signIn(client, roles = ["viewer"], ttlMs = 60_000) {
  client.tokenManager.setTokens({ accessToken: "t1", expiresAt: Date.now() + ttlMs });
  client.authManager.setSession({ userId: "u1", roles });
}

// Runs `setup` inside a component under an app with the OWL plugin installed.
function withSetup(setup, { client = createClient(), owl = createOwl({ client }) } = {}) {
  let result;
  const wrapper = mount(
    defineComponent({
      setup() {
        result = setup();
        return () => null;
      }
    }),
    { global: { plugins: [owl] } }
  );
  return { result, wrapper, client, owl };
}

afterEach(() => {
  jest.useRealTimers();
  document.cookie = "XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
});

describe("plugin", () => {
  test("composables fail clearly without the plugin", () => {
    const Comp = defineComponent({
      setup() {
        useAuth();
        return () => null;
      }
    });
    jest.spyOn(console, "warn").mockImplementation(() => {});
    expect(() => mount(Comp)).toThrow(/createOwl/);
    console.warn.mockRestore();
  });

  test("auth state follows login, logout and token refresh", async () => {
    const { result, client } = withSetup(() => ({ ...useAuth(), token: useAuthToken() }));
    expect(result.isAuthenticated.value).toBe(false);

    signIn(client, ["editor"]);
    expect(result.isAuthenticated.value).toBe(true);
    expect(result.session.value).toMatchObject({ userId: "u1", roles: ["editor"] });
    expect(result.token.value).toBe("t1");

    client.tokenManager.setTokens({ accessToken: "t2", expiresAt: Date.now() + 60_000 });
    expect(result.token.value).toBe("t2");

    client.authManager.clearSession();
    expect(result.isAuthenticated.value).toBe(false);
    expect(result.session.value).toBeNull();
  });

  test("isAuthenticated flips when the access token expires", () => {
    jest.useFakeTimers();
    const client = createClient();
    signIn(client, ["viewer"], 1_000);
    const { result } = withSetup(() => useAuth(), { client });
    expect(result.isAuthenticated.value).toBe(true);
    jest.advanceTimersByTime(1_001);
    expect(result.isAuthenticated.value).toBe(false);
  });

  test("session state is read-only", () => {
    const { result } = withSetup(() => useAuth());
    jest.spyOn(console, "warn").mockImplementation(() => {});
    result.session.value = { userId: "attacker", roles: ["admin"] };
    console.warn.mockRestore();
    expect(result.session.value).toBeNull();
  });

  test("unmounting the app ends the event subscriptions", () => {
    const client = createClient();
    const owl = createOwl({ client });
    const app = createApp({ render: () => null });
    app.use(owl);
    app.mount(document.createElement("div"));
    app.unmount();
    signIn(client);
    expect(owl.context.auth.isAuthenticated.value).toBe(false);
  });

  test("provideOwl gives a subtree its own managers and cleans up on unmount", async () => {
    const outer = createClient();
    const inner = createClient();
    signIn(inner, ["editor"]);
    let innerAuth;
    let provided;
    const Child = defineComponent({
      setup() {
        innerAuth = useAuth();
        return () => null;
      }
    });
    const Parent = defineComponent({
      setup() {
        provided = provideOwl({ client: inner });
        return () => h(Child);
      }
    });
    const wrapper = mount(Parent, { global: { plugins: [createOwl({ client: outer })] } });
    expect(innerAuth.authManager).toBe(inner.authManager);
    expect(innerAuth.isAuthenticated.value).toBe(true);

    wrapper.unmount();
    inner.authManager.clearSession();
    expect(provided.auth.isAuthenticated.value).toBe(true);
  });
});

describe("A01 access control", () => {
  test("usePermission recomputes for reactive resources and sessions", async () => {
    const resource = ref("reports");
    const { result, client } = withSetup(() => usePermission("read", resource));
    expect(result.value).toEqual({ allowed: false, reason: "no_role" });

    signIn(client, ["viewer"]);
    expect(result.value.allowed).toBe(true);

    resource.value = "report:locked";
    expect(result.value).toEqual({ allowed: false, reason: "acl_deny_override" });
  });

  test("any role can grant a permission", () => {
    const client = createClient();
    signIn(client, ["viewer", "editor"]);
    const { result } = withSetup(() => usePermission("write", () => "reports"), { client });
    expect(result.value.allowed).toBe(true);
  });

  test("PermissionGate and AuthGate render the matching slot", async () => {
    const client = createClient();
    const Page = defineComponent({
      render: () => [
        h(AuthGate, null, { default: () => "signed-in", fallback: () => "please-sign-in" }),
        h(PermissionGate, { action: "write", resource: "reports" }, { default: () => "editor-tools", fallback: () => "read-only" })
      ]
    });
    const wrapper = mount(Page, { global: { plugins: [createOwl({ client })] } });
    expect(wrapper.text()).toBe("please-sign-inread-only");

    signIn(client, ["editor"]);
    await nextTick();
    expect(wrapper.text()).toBe("signed-ineditor-tools");
  });
});

describe("A03 injection defense", () => {
  const payload = '<img src=x onerror="alert(1)"><b>bold</b><script>steal()</script>';

  test("v-safe-html sanitizes on mount and on update", async () => {
    const html = ref(payload);
    const Comp = defineComponent({
      directives: { safeHtml: vSafeHtml },
      setup: () => ({ html }),
      template: '<div v-safe-html="html"></div>'
    });
    const wrapper = mount(Comp);
    expect(wrapper.html()).not.toMatch(/<script|onerror|<img/);
    expect(wrapper.text()).toContain("bold");

    html.value = "<a href=\"javascript:alert(1)\">x</a>";
    await nextTick();
    expect(wrapper.html()).not.toContain("javascript:");
  });

  test("the moderate profile keeps formatting; the object form and null work", () => {
    const Comp = defineComponent({
      directives: { safeHtml: vSafeHtml },
      template: `<div>
        <p id="m" v-safe-html:moderate="'<b>bold</b><script>x()</script>'"></p>
        <p id="o" v-safe-html="{ html: '<i class=&quot;keep drop&quot;>i</i>', profile: 'moderate', allowedClasses: ['keep'] }"></p>
        <p id="n" v-safe-html="null"></p>
      </div>`
    });
    const wrapper = mount(Comp);
    expect(wrapper.find("#m").html()).toContain("<b>bold</b>");
    expect(wrapper.find("#m").html()).not.toContain("script");
    expect(wrapper.find("#o").html()).toContain('<i class="keep">i</i>');
    expect(wrapper.find("#n").text()).toBe("");
  });

  test("v-safe-html sanitizes in server-side rendering", async () => {
    const app = createSSRApp({
      directives: { safeHtml: vSafeHtml },
      template: `<div v-safe-html="'<b>ok</b><img src=x onerror=alert(1)>'"></div>`
    });
    const html = await renderToString(app);
    expect(html).toContain("ok");
    expect(html).not.toMatch(/onerror|<img/);
  });

  test("SanitizedText and useInputSanitizer use the requested profile", async () => {
    const wrapper = mount(SanitizedText, { props: { html: "<b>Tom & Jerry</b>", profile: "moderate" } });
    expect(wrapper.html()).toContain("<b>Tom &amp; Jerry</b>");

    const profile = ref("strict");
    const { result } = withSetup(() => useInputSanitizer(profile));
    expect(result.value.sanitizeHTML("<b>x</b>")).not.toContain("<b>");
    profile.value = "moderate";
    expect(result.value.sanitizeHTML("<b>x</b>")).toContain("<b>x</b>");
  });
});

describe("A05, A04, A06", () => {
  test("useHardeningReport recomputes when the config ref changes", () => {
    const config = ref({ debug: false });
    const { result } = withSetup(() => useHardeningReport(config));
    expect(result.value).toEqual([]);
    config.value = { debug: true };
    expect(result.value.map((f) => f.id)).toEqual(["debug_enabled"]);
  });

  test("useThreatModelGuard builds a guard from the config", () => {
    const { result } = withSetup(() => useThreatModelGuard({ transitions: { draft: ["published"] } }));
    expect(result.value.canTransition("draft", "published")).toBe(true);
    expect(result.value.canTransition("published", "draft")).toBe(false);
  });

  test("useDependencyRiskScanner keeps only the latest overlapping scan", async () => {
    const pending = [];
    const provider = { scan: () => new Promise((resolve) => pending.push(resolve)) };
    const { result } = withSetup(() => useDependencyRiskScanner(provider));

    const first = result.runScan();
    const second = result.runScan();
    expect(result.loading.value).toBe(true);
    pending[1]([{ name: "new", severity: "high" }]);
    await second;
    pending[0]([{ name: "stale", severity: "low" }]);
    await first;
    expect(result.loading.value).toBe(false);
    expect(result.results.value.map((r) => r.package)).toEqual(["new"]);
  });

  test("useDependencyRiskScanner exposes scan errors", async () => {
    const provider = { scan: async () => { throw new Error("registry down"); } };
    const { result } = withSetup(() => useDependencyRiskScanner(provider));
    await expect(result.runScan()).rejects.toThrow("registry down");
    expect(result.error.value.message).toBe("registry down");
    expect(result.loading.value).toBe(false);
  });
});

describe("A08 and A10 clients", () => {
  test("useSecureHttpClient sends the XSRF-TOKEN cookie as X-CSRF-Token", async () => {
    document.cookie = "XSRF-TOKEN=server-token";
    const response = {
      ok: true,
      status: 200,
      headers: new Headers(),
      clone: () => response,
      json: async () => ({}),
      text: async () => "{}"
    };
    const fetchImpl = jest.fn(async () => response);
    const { result } = withSetup(() => useSecureHttpClient({ fetchImpl }));
    expect(result.value).toBeInstanceOf(HTTPClient);
    await result.value.request("/api/reports", { method: "POST" });
    expect(fetchImpl.mock.calls[0][1].headers["X-CSRF-Token"]).toBe("server-token");
  });

  test("useSecureHttpClient rebuilds when the options ref changes", () => {
    const options = ref({ baseUrl: "/a" });
    const { result } = withSetup(() => useSecureHttpClient(options));
    const firstClient = result.value;
    options.value = { baseUrl: "/b", csrfCookieName: null };
    expect(result.value).not.toBe(firstClient);
    expect(result.value.csrfManager).toBeNull();
  });

  test("useSafeFetcher passes fetchImpl through without calling it", async () => {
    const fetchImpl = jest.fn(async () => ({ status: 200, headers: new Headers() }));
    const config = { resolveHost: async () => ["203.0.113.10"] };
    const { result } = withSetup(() => useSafeFetcher(config, fetchImpl));
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(result.value).toBeInstanceOf(SafeFetcher);
    await result.value.fetch("https://hooks.example.com/x");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    await expect(result.value.fetch("http://169.254.169.254/")).rejects.toMatchObject({ code: "SSRF_BLOCKED" });
  });
});

describe("A09 monitoring", () => {
  test("useSecurityMonitoring exposes the client's logger and events", () => {
    const client = createClient();
    const { result } = withSetup(() => useSecurityMonitoring(), { client });
    expect(result.logger).toBe(client.logger);
    expect(result.events).toBe(client.events);
  });

  test("SecurityAlert renders its message as text", () => {
    const wrapper = mount(SecurityAlert, { props: { message: "<b>x</b>", level: "error" } });
    expect(wrapper.attributes()).toMatchObject({ role: "alert", "data-level": "error" });
    expect(wrapper.html()).toContain("&lt;b&gt;x&lt;/b&gt;");
  });
});

describe("router guard", () => {
  const Page = { render: () => null };

  async function setup(roles) {
    const client = createClient();
    const warn = jest.fn();
    client.logger = { warn };
    if (roles) signIn(client, roles);
    const owl = createOwl({ client });
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: "/", component: Page },
        { path: "/login", component: Page },
        { path: "/403", component: Page },
        { path: "/account", component: Page, meta: { requiresAuth: true } },
        {
          path: "/reports",
          component: Page,
          meta: { permission: { action: "read", resource: "reports" } },
          children: [
            { path: ":id", component: Page, meta: { permission: { action: "read", resource: (to) => `report:${to.params.id}` } } }
          ]
        },
        { path: "/admin", component: Page, meta: { permission: { action: "write", resource: "reports" } } }
      ]
    });
    router.beforeEach(createOwlRouterGuard(owl, { forbiddenRoute: "/403" }));
    await router.push("/");
    return { router, warn };
  }

  test("signed-out users are sent to login with the requested path", async () => {
    const { router } = await setup(null);
    await router.push("/account?tab=keys");
    expect(router.currentRoute.value.path).toBe("/login");
    expect(router.currentRoute.value.query.redirect).toBe("/account?tab=keys");
    await router.push("/reports");
    expect(router.currentRoute.value.path).toBe("/login");
  });

  test("permissions are checked, including parent meta and ACL denies", async () => {
    const { router, warn } = await setup(["viewer"]);
    await router.push("/reports/42");
    expect(router.currentRoute.value.path).toBe("/reports/42");

    await router.push("/reports/locked");
    expect(router.currentRoute.value.path).toBe("/403");
    expect(warn).toHaveBeenCalledWith("navigation.denied", expect.objectContaining({ resource: "report:locked" }));

    await router.push("/admin");
    expect(router.currentRoute.value.path).toBe("/403");
  });

  test("without a forbidden route, a denied navigation is cancelled", async () => {
    const client = createClient();
    signIn(client, ["viewer"]);
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: "/", component: Page },
        { path: "/admin", component: Page, meta: { permission: { action: "write", resource: "reports" } } }
      ]
    });
    client.logger = { warn: jest.fn() };
    router.beforeEach(createOwlRouterGuard(createOwl({ client })));
    await router.push("/");
    await router.push("/admin");
    expect(router.currentRoute.value.path).toBe("/");
  });

  test("needs the createOwl() plugin", () => {
    expect(() => createOwlRouterGuard({})).toThrow(/createOwl/);
  });
});
