import {
  IAccessControl,
  IUrlControl,
  IResourceControl,
  ISecurityContext,
  ISecurityProvider,
  SecurityContext,
  Principal,
  Resource,
  Permission,
  AccessRequest,
  AccessResponse,
  URLPattern,
} from "./api/interfaces";

import { RBAC } from "./core/rbac/rbac";
import { ACL } from "./core/acl/acl";
import { URLAccessControl } from "./core/url/url-access-control";

/**
 * Main security provider implementation for A01 Broken Access Control
 */
export class SecurityProvider implements ISecurityProvider {
  private rbac: RBAC;
  private acl: ACL;
  private urlControl: URLAccessControl;
  private context: SecurityContext;

  constructor() {
    this.rbac = new RBAC();
    this.acl = new ACL();
    this.urlControl = new URLAccessControl();
    this.context = {};
  }

  async initialize(options?: Record<string, any>): Promise<void> {
    // Initialize components with options
    if (options?.rbac) {
      // Initialize RBAC with options
    }
    if (options?.acl) {
      // Initialize ACL with options
    }
    if (options?.urlControl) {
      // Initialize URL control with options
    }
  }

  async dispose(): Promise<void> {
    // Clean up resources
    this.context = {};
  }

  // IAccessControl implementation
  async can(request: AccessRequest): Promise<AccessResponse> {
    const rbacAllowed = await this.rbac.can(request);
    if (!rbacAllowed) {
      return { allowed: false, reason: "RBAC: Access denied" };
    }

    const aclAllowed = await this.acl.isAllowed({
      principal: request.principal,
      resource: request.resource,
      permission: request.action,
    });

    return {
      allowed: aclAllowed,
      reason: aclAllowed ? "Access granted" : "ACL: Access denied",
      metadata: {
        rbacAllowed,
        aclAllowed,
      },
    };
  }

  async getPermissions(principal: Principal): Promise<Permission[]> {
    return this.rbac.getSubjectPermissions(principal);
  }

  async hasRoles(principal: Principal, roles: string[]): Promise<boolean> {
    return roles.every((role) => principal.roles?.includes(role));
  }

  async hasPermissions(
    principal: Principal,
    permissions: string[]
  ): Promise<boolean> {
    const userPermissions = await this.getPermissions(principal);
    return permissions.every((permission) =>
      userPermissions.some((p) => p.action === permission)
    );
  }

  // IUrlControl implementation
  async isUrlAllowed(
    url: string,
    context: SecurityContext
  ): Promise<AccessResponse> {
    const allowed = await this.urlControl.isAllowed({
      url,
      method: context?.metadata?.method || "GET",
      user: context.principal,
    });

    return {
      allowed,
      reason: allowed ? "URL access granted" : "URL access denied",
    };
  }

  addUrlPattern(pattern: URLPattern, permissions: Permission[]): void {
    this.urlControl.addRule({
      pattern,
      allow: true,
      permissions: permissions.map((p) => p.action),
    });
  }

  removeUrlPattern(pattern: URLPattern): void {
    this.urlControl.removeRule({ pattern });
  }

  // IResourceControl implementation
  async canAccessResource(
    principal: Principal,
    resource: Resource,
    action: string
  ): Promise<AccessResponse> {
    return this.can({
      principal,
      action,
      resource,
      context: this.context,
    });
  }

  async getAccessibleResources(
    principal: Principal,
    resourceType: string
  ): Promise<Resource[]> {
    // This would typically involve querying your resource store
    // and filtering based on permissions
    return [];
  }

  addResourcePermission(resource: Resource, permission: Permission): void {
    this.acl.addRule({
      allow: true,
      principal: { type: "*", id: "*" },
      resource: {
        type: resource.type,
        id: resource.id,
      },
      permissions: [permission.action],
    });
  }

  // ISecurityContext implementation
  getContext(): SecurityContext {
    return this.context;
  }

  updateContext(context: Partial<SecurityContext>): void {
    this.context = {
      ...this.context,
      ...context,
    };
  }

  clearContext(): void {
    this.context = {};
  }
}

// Export public API
export * from "./api/interfaces";
export * from "./api/types";
