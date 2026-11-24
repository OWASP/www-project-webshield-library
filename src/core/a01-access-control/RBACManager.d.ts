export class RBACManager {
    roles: Map<any, any>;
    defineRole(role: any, permissions?: any[], inherits?: any[]): void;
    _flattenPermissions(role: any, visited?: Set<any>): Set<any>;
    /**
     * @param {string | string[]} role One role or all roles assigned to the user.
     * @param {string} action
     * @param {string} resource
     * @returns {boolean}
     */
    can(role: string | string[], action: string, resource: string): boolean;
}
