import { useACL } from "../context/ACLContext";

export function usePermission(
  roleId: string,
  action: string,
  resource: string,
  context?: Record<string, unknown>
) {
  const { checkPermission } = useACL();
  return checkPermission(roleId, action, resource, context);
}

export function useAttributeAccess(
  roleId: string,
  resource: string,
  attributes: string[]
) {
  const { checkAttributeAccess } = useACL();
  return checkAttributeAccess(roleId, resource, attributes);
}
