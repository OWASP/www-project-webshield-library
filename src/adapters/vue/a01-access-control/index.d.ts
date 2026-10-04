/**
 * The provided `ACLManager`.
 */
export function useACL(): any;
/**
 * Whether the current session may perform `action` on `resource`: allowed if
 * any of its roles grants it, and an ACL deny applies to every role (the same
 * rule as the React adapter's `usePermission`). Both arguments can be refs or
 * getters, e.g. `usePermission("read", () => \`report:${route.params.id}\`)`.
 *
 * Recomputes when the session or the arguments change. RBAC/ACL rules changed
 * at runtime (`aclManager.setPolicy()`) are picked up on the next change.
 *
 * @param {import("vue").MaybeRefOrGetter<string>} action
 * @param {import("vue").MaybeRefOrGetter<string>} resource
 * @returns {import("vue").ComputedRef<{allowed: boolean, reason: string}>}
 */
export function usePermission(action: import("vue").MaybeRefOrGetter<string>, resource: import("vue").MaybeRefOrGetter<string>): import("vue").ComputedRef<{
    allowed: boolean;
    reason: string;
}>;
/**
 * Renders the default slot when the session has the permission, otherwise the
 * `fallback` slot. Only controls what the UI shows; the server must still
 * authorize every request.
 */
export const PermissionGate: import("vue").DefineComponent<import("vue").ExtractPropTypes<{
    action: {
        type: StringConstructor;
        required: true;
    };
    resource: {
        type: StringConstructor;
        required: true;
    };
}>, () => import("vue").VNode<import("vue").RendererNode, import("vue").RendererElement, {
    [key: string]: any;
}>[], {}, {}, {}, import("vue").ComponentOptionsMixin, import("vue").ComponentOptionsMixin, {}, string, import("vue").PublicProps, Readonly<import("vue").ExtractPropTypes<{
    action: {
        type: StringConstructor;
        required: true;
    };
    resource: {
        type: StringConstructor;
        required: true;
    };
}>> & Readonly<{}>, {}, {}, {}, {}, string, import("vue").ComponentProvideOptions, true, {}, any>;
