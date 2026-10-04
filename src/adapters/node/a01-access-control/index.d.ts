/**
 * Accepts a `PermissionChecker`, or anything holding an `rbacManager` (and
 * optionally an `aclManager`), such as the object `createOwlClient()` returns.
 */
export function toPermissionChecker(source: any): any;
/**
 * Checks every role of the session, the same rule `usePermission()` applies in
 * the React adapter: allowed if any role grants the permission, and an ACL deny
 * applies to every role.
 * @param {{session: {roles?: string[]} | null | undefined, action: string, resource: string}} request
 * @param {object} checkerSource see `toPermissionChecker()`
 * @returns {{allowed: boolean, reason: string}}
 */
export function checkPermission({ session, action, resource }: {
    session: {
        roles?: string[];
    } | null | undefined;
    action: string;
    resource: string;
}, checkerSource: object): {
    allowed: boolean;
    reason: string;
};
/**
 * Like `checkPermission()`, but throws `AUTH_REQUIRED` without a session and
 * `ACCESS_DENIED` when no role grants the permission.
 */
export function assertPermission({ session, action, resource }: {
    session: any;
    action: any;
    resource: any;
}, checkerSource: any): {
    allowed: boolean;
    reason: string;
};
