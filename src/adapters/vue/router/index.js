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
 * Like `AuthGate`/`PermissionGate`, this only controls what the UI shows; the
 * server must still authorize every request.
 *
 * @param {{context: object}} owl the plugin returned by `createOwl()`
 * @param {{loginRoute?: string, forbiddenRoute?: string | null}} [options]
 */
export function createOwlRouterGuard(owl, { loginRoute = "/login", forbiddenRoute = null } = {}) {
  const context = owl?.context;
  if (!context) throw new Error("createOwlRouterGuard needs the plugin returned by createOwl()");
  const { rbacManager, aclManager, logger, auth } = context;
  const checker = rbacManager && aclManager ? new PermissionChecker({ rbacManager, aclManager }) : null;

  return function owlRouterGuard(to) {
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
