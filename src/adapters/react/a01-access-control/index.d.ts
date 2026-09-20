export function ACLProvider({ aclManager, children }: {
    aclManager: any;
    children: any;
}): any;
export function RBACProvider({ rbacManager, children }: {
    rbacManager: any;
    children: any;
}): any;
export function useACL(): any;
export function usePermission(action: any, resource: any): any;
export function PermissionGate({ action, resource, fallback, children }: {
    action: any;
    resource: any;
    fallback?: any;
    children: any;
}): any;
export const ACLContext: any;
export const RBACContext: any;
