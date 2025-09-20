import React, { createContext, useContext } from "react";
import { ACL } from "@owasp-web-shield/core";

interface ACLContextValue {
  checkPermission: (
    roleId: string,
    action: string,
    resource: string,
    context?: Record<string, unknown>
  ) => Promise<boolean>;
  checkAttributeAccess: (
    roleId: string,
    resource: string,
    attributes: string[]
  ) => Promise<boolean>;
}

const ACLContext = createContext<ACLContextValue | undefined>(undefined);

interface ACLProviderProps {
  acl: ACL;
  children: React.ReactNode;
}

export function ACLProvider({ acl, children }: ACLProviderProps) {
  const value = React.useMemo(
    () => ({
      checkPermission: (
        roleId: string,
        action: string,
        resource: string,
        context?: Record<string, unknown>
      ) => {
        return acl.checkPermission(roleId, action, resource, context);
      },
      checkAttributeAccess: (
        roleId: string,
        resource: string,
        attributes: string[]
      ) => {
        return acl.checkAttributeAccess(roleId, resource, attributes);
      },
    }),
    [acl]
  );

  return <ACLContext.Provider value={value}>{children}</ACLContext.Provider>;
}

export function useACL() {
  const context = useContext(ACLContext);
  if (!context) {
    throw new Error("useACL must be used within an ACLProvider");
  }
  return context;
}
