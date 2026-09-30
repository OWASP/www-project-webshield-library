export class RBACManager {
    roles: Map<any, any>;
    defineRole(role: any, permissions?: any[], inherits?: any[]): void;
    _flattenPermissions(role: any, visited?: Set<any>): Set<any>;
    can(role: any, action: any, resource: any): boolean;
}
