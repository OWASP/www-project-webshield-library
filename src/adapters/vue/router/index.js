import { effectScope, watch } from "vue";
import { PermissionChecker } from "@owasp-webshield/core";

function routeRequirements(to) {
  const records = Array.isArray(to.matched) && to.matched.length ? to.matched : [to];
  const permissions = [];
  let requiresAuth = false;
  for (const record of records) {
    const meta = record.meta || {};
    if (meta.requiresAuth) requiresAuth = true;
    if (meta.permission) permissions.push(meta.permission);
  }
  return { requiresAuth: requiresAuth || permissions.length > 0, permissions };
}

function allowedByAnyRole(checker, roles, action, resource) {
  for (const role of roles) {
    const result = checker.check({ role, action, resource });
    if (result.allowed) return true;
    if (result.reason === "acl_deny_override") return false;
  }
  return false;
}

function contextOf(owl, caller) {
  const context = owl?.context;
  if (!context) throw new Error(`${caller} needs the plugin returned by createOwl()`);
  return context;
}

// Returns true (allow), a location to redirect to, or false (cancel).
function createEvaluator(context, { loginRoute = "/login", forbiddenRoute = null } = {}) {
  const { rbacManager, aclManager, logger, auth } = context;
  const checker = rbacManager && aclManager ? new PermissionChecker({ rbacManager, aclManager }) : null;

  return function evaluate(to) {
    if (to.path === loginRoute || (forbiddenRoute && to.path === forbiddenRoute)) return true;

    const { requiresAuth, permissions } = routeRequirements(to);
    if (!requiresAuth) return true;

    if (!auth.isAuthenticated.value) {
      return { path: loginRoute, query: { redirect: to.fullPath } };
    }

    const roles = Array.isArray(auth.session.value?.roles) ? auth.session.value.roles : [];
    for (const { action, resource } of permissions) {
      const target = typeof resource === "function" ? resource(to) : resource;
      if (!checker || !allowedByAnyRole(checker, roles, action, target)) {
        logger?.warn("navigation.denied", { path: to.path, action, resource: target });
        return forbiddenRoute ? { path: forbiddenRoute } : false;
      }
    }
    return true;
  };
}

/**
 * A Vue Router `beforeEach` guard driven by route meta:
 *
 * ```js
 * { path: "/reports/:id", component: Report,
 *   meta: { permission: { action: "read", resource: (to) => `report:${to.params.id}` } } }
 * { path: "/account", component: Account, meta: { requiresAuth: true } }
 *
 * router.beforeEach(createOwlRouterGuard(owl, { loginRoute: "/login", forbiddenRoute: "/403" }));
 * ```
 *
 * Meta on parent routes applies to their children. A route with a `permission`
 * also requires a session. Signed-out users go to `loginRoute`, with the
 * requested path in `?redirect=` (a path within the app; push it with the router
 * rather than assigning it to `location`). Denied navigations go to
 * `forbiddenRoute`, or are cancelled when it isn't set, and are logged through
 * the provided `SecurityLogger`.
 *
 * The guard only runs on navigation. Use `installOwlRouterGuard()` to also
 * leave a protected page when the session ends or loses the permission.
 *
 * Like `AuthGate`/`PermissionGate`, this only controls what the UI shows; the
 * server must still authorize every request.
 *
 * @param {{context: object}} owl the plugin returned by `createOwl()`
 * @param {{loginRoute?: string, forbiddenRoute?: string | null}} [options]
 */
export function createOwlRouterGuard(owl, options) {
  return createEvaluator(contextOf(owl, "createOwlRouterGuard"), options);
}

/**
 * Registers the `createOwlRouterGuard()` guard on `router`, and re-checks the
 * current route whenever the session changes. A logout or an expired token on a
 * protected page redirects to `loginRoute`; losing the permission (a role
 * change, a new user) redirects to `forbiddenRoute`, or to `/` when there is
 * none. Stops when the app unmounts, or when the returned function is called.
 *
 * @param {{replace: Function, beforeEach: Function, currentRoute: {value: object}}} router
 * @param {{context: object}} owl the plugin returned by `createOwl()`
 * @param {{loginRoute?: string, forbiddenRoute?: string | null}} [options]
 * @returns {() => void} uninstalls the guard and the watcher
 */
export function installOwlRouterGuard(router, owl, options = {}) {
  const context = contextOf(owl, "installOwlRouterGuard");
  const evaluate = createEvaluator(context, options);
  const removeGuard = router.beforeEach(evaluate);

  const scope = effectScope(true);
  scope.run(() => {
    watch([context.auth.isAuthenticated, context.auth.session], () => {
      const current = router.currentRoute.value;
      // Nothing to re-check before the initial navigation has resolved.
      if (!current?.matched?.length) return;
      const result = evaluate(current);
      if (result === true) return;
      router.replace(result === false ? "/" : result);
    });
  });

  let removeDisposer = () => {};
  const uninstall = () => {
    scope.stop();
    if (typeof removeGuard === "function") removeGuard();
    removeDisposer();
  };
  removeDisposer = context.auth.onStop(uninstall);
  return uninstall;
}
