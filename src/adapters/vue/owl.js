import { computed, inject, onScopeDispose, provide, readonly, shallowRef } from "vue";

export const OWL_KEY = Symbol("owasp-webshield");

const TOKEN_EVENTS = ["token:changed", "token:cleared", "token:rotated"];

/**
 * Reactive view of an `AuthManager`: `session` and `accessToken` follow its
 * events, and a timer clears `accessToken` when it expires (no event fires for
 * that). Same behaviour as the React adapter's `AuthProvider`.
 */
function createAuthState(authManager) {
  const session = shallowRef(authManager?.getSession() || null);
  const accessToken = shallowRef(authManager?.tokenManager.getAccessToken() || null);
  const isAuthenticated = computed(() => Boolean(session.value && accessToken.value));

  if (!authManager) {
    return { session: readonly(session), accessToken: readonly(accessToken), isAuthenticated, stop: () => {} };
  }

  let expiryTimer = null;

  const sync = () => {
    session.value = authManager.getSession();
    accessToken.value = authManager.tokenManager.getAccessToken();
  };

  const clearExpiry = () => {
    if (expiryTimer) clearTimeout(expiryTimer);
    expiryTimer = null;
  };

  const scheduleExpiry = () => {
    clearExpiry();
    // No timers during server-side rendering: the app is never unmounted there,
    // so they would outlive the request.
    if (typeof window === "undefined") return;
    const expiresAt = authManager.tokenManager.getTokens()?.expiresAt;
    if (!expiresAt) return;
    const msUntilExpiry = expiresAt - Date.now();
    if (msUntilExpiry <= 0) {
      sync();
      return;
    }
    expiryTimer = setTimeout(sync, msUntilExpiry);
  };

  const onTokenChange = () => {
    sync();
    scheduleExpiry();
  };

  const unsubscribers = [
    authManager.events.on("auth:changed", sync),
    ...TOKEN_EVENTS.map((event) => authManager.tokenManager.events.on(event, onTokenChange))
  ];
  scheduleExpiry();

  const stop = () => {
    for (const unsubscribe of unsubscribers.splice(0)) unsubscribe();
    clearExpiry();
  };

  return { session: readonly(session), accessToken: readonly(accessToken), isAuthenticated, stop };
}

/**
 * Accepts the object `createOwlClient()` returns and/or individual managers,
 * like the React adapter's `<OwlProvider>`; individual managers win.
 */
function createContext({ client = {}, authManager, aclManager, rbacManager, logger, events } = {}) {
  const resolvedAuthManager = authManager ?? client.authManager ?? null;
  const auth = createAuthState(resolvedAuthManager);
  return {
    authManager: resolvedAuthManager,
    aclManager: aclManager ?? client.aclManager ?? null,
    rbacManager: rbacManager ?? client.rbacManager ?? null,
    logger: logger ?? client.logger ?? null,
    events: events ?? client.events ?? null,
    auth
  };
}

/**
 * Vue plugin that makes the OWL managers available to every component:
 *
 * ```js
 * const owl = createOwl({ client: createOwlClient({ roles: { ... } }) });
 * createApp(App).use(owl).mount("#app");
 * ```
 *
 * The returned plugin also carries the context, so code outside components (a
 * router guard, a Pinia store) can use the same reactive auth state. Event
 * subscriptions end when the app unmounts.
 *
 * With server-side rendering, call `createOwl()` inside the app factory so every
 * request gets its own managers; a module-level instance would share one user's
 * session with every other request.
 *
 * @param {{
 *   client?: {authManager?: object, aclManager?: object, rbacManager?: object, logger?: object, events?: object},
 *   authManager?: object, aclManager?: object, rbacManager?: object, logger?: object, events?: object
 * }} [options]
 */
export function createOwl(options) {
  const context = createContext(options);
  return {
    context,
    install(app) {
      app.provide(OWL_KEY, context);
      if (typeof app.onUnmount === "function") {
        app.onUnmount(context.auth.stop);
      } else {
        // Vue < 3.5 has no app.onUnmount.
        const unmount = app.unmount;
        app.unmount = function owlUnmount(...args) {
          context.auth.stop();
          return unmount.apply(this, args);
        };
      }
    }
  };
}

/**
 * Provides a separate set of managers to the calling component's subtree.
 * Call it in `setup()`; subscriptions end when the component unmounts.
 * @param {Parameters<typeof createOwl>[0]} options
 */
export function provideOwl(options) {
  const context = createContext(options);
  onScopeDispose(context.auth.stop);
  provide(OWL_KEY, context);
  return context;
}

/**
 * The OWL context provided by `createOwl()` or `provideOwl()`.
 */
export function useOwl() {
  const context = inject(OWL_KEY, null);
  if (!context) {
    throw new Error("OWL is not installed: call app.use(createOwl(...)) or provideOwl(...) first");
  }
  return context;
}
