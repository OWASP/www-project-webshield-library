import {
  Principal,
  Resource,
  Permission,
  AccessRequest,
  AccessResponse,
  URLPattern,
  SecurityContext,
} from "./types";

export {
  Principal,
  Resource,
  Permission,
  AccessRequest,
  AccessResponse,
  URLPattern,
  SecurityContext,
};

/**
 * Core access control interface that all implementations must follow
 */
export interface IAccessControl {
  /**
   * Check if a principal has permission to perform an action on a resource
   */
  can(request: AccessRequest): Promise<AccessResponse>;

  /**
   * Get all permissions for a principal
   */
  getPermissions(principal: Principal): Promise<Permission[]>;

  /**
   * Validate if a principal has specific roles
   */
  hasRoles(principal: Principal, roles: string[]): Promise<boolean>;

  /**
   * Validate if a principal has specific permissions
   */
  hasPermissions(principal: Principal, permissions: string[]): Promise<boolean>;
}

/**
 * URL-based access control interface
 */
export interface IUrlControl {
  /**
   * Check if a URL is accessible
   */
  isUrlAllowed(url: string, context: SecurityContext): Promise<AccessResponse>;

  /**
   * Add URL pattern rule
   */
  addUrlPattern(pattern: URLPattern, permissions: Permission[]): void;

  /**
   * Remove URL pattern rule
   */
  removeUrlPattern(pattern: URLPattern): void;
}

/**
 * Resource-level access control interface
 */
export interface IResourceControl {
  /**
   * Check if a principal can access a resource
   */
  canAccessResource(
    principal: Principal,
    resource: Resource,
    action: string
  ): Promise<AccessResponse>;

  /**
   * Get all accessible resources for a principal
   */
  getAccessibleResources(
    principal: Principal,
    resourceType: string
  ): Promise<Resource[]>;

  /**
   * Add resource-level permission
   */
  addResourcePermission(resource: Resource, permission: Permission): void;
}

/**
 * Security context management interface
 */
export interface ISecurityContext {
  /**
   * Get current security context
   */
  getContext(): SecurityContext;

  /**
   * Update security context
   */
  updateContext(context: Partial<SecurityContext>): void;

  /**
   * Clear security context
   */
  clearContext(): void;
}

/**
 * Combined security provider interface for framework adapters
 */
export interface ISecurityProvider
  extends IAccessControl,
    IUrlControl,
    IResourceControl,
    ISecurityContext {
  /**
   * Initialize the security provider
   */
  initialize(options?: Record<string, any>): Promise<void>;

  /**
   * Clean up and dispose of resources
   */
  dispose(): Promise<void>;
}
