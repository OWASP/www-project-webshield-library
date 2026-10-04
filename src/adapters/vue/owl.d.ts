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
export function createOwl(options?: {
    client?: {
        authManager?: object;
        aclManager?: object;
        rbacManager?: object;
        logger?: object;
        events?: object;
    };
    authManager?: object;
    aclManager?: object;
    rbacManager?: object;
    logger?: object;
    events?: object;
}): {
    context: {
        authManager: any;
        aclManager: any;
        rbacManager: any;
        logger: any;
        events: any;
        auth: any;
    };
    install(app: any): void;
};
/**
 * Provides a separate set of managers to the calling component's subtree.
 * Call it in `setup()`; subscriptions end when the component unmounts.
 * @param {Parameters<typeof createOwl>[0]} options
 */
export function provideOwl(options: Parameters<typeof createOwl>[0]): {
    authManager: any;
    aclManager: any;
    rbacManager: any;
    logger: any;
    events: any;
    auth: any;
};
/**
 * The OWL context provided by `createOwl()` or `provideOwl()`.
 */
export function useOwl(): any;
export const OWL_KEY: unique symbol;
