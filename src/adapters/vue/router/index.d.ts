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
export function createOwlRouterGuard(owl: {
    context: object;
}, options?: {
    loginRoute?: string;
    forbiddenRoute?: string | null;
}): (to: any) => boolean | {
    path: string;
    query: {
        redirect: any;
    };
} | {
    path: any;
    query?: undefined;
};
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
export function installOwlRouterGuard(router: {
    replace: Function;
    beforeEach: Function;
    currentRoute: {
        value: object;
    };
}, owl: {
    context: object;
}, options?: {
    loginRoute?: string;
    forbiddenRoute?: string | null;
}): () => void;
