/**
 * Represents the structure for access control lists (ACL) permissions.
 */
export interface ACLPermission {
  /**
   * The action being permitted (e.g., 'read', 'write', 'delete')
   */
  action: string;

  /**
   * The resource being accessed (e.g., 'users', 'posts', 'comments')
   */
  resource: string;

  /**
   * The attributes or fields that are accessible
   * For example: ['id', 'name'] for a user resource
   */
  attributes?: string[];

  /**
   * Any conditions that must be met for the permission to be granted
   * For example: { ownerId: '${userId}' } to only allow access to own resources
   */
  conditions?: Record<string, any>;
}

/**
 * Represents an ACL role with its associated permissions.
 */
export interface ACLRole {
  /**
   * Unique identifier for the role
   */
  roleId: string;

  /**
   * List of permissions granted to this role
   */
  permissions: ACLPermission[];

  /**
   * Parent roles from which this role inherits permissions
   */
  extends?: string[];
}

/**
 * Interface for ACL manager that handles role and permission management.
 */
export interface IACLManager {
  /**
   * Add a new role with specified permissions
   */
  addRole(role: ACLRole): void;

  /**
   * Remove a role and its permissions
   */
  removeRole(roleId: string): void;

  /**
   * Add permissions to an existing role
   */
  addPermissions(roleId: string, permissions: ACLPermission[]): void;

  /**
   * Remove permissions from a role
   */
  removePermissions(roleId: string, permissions: ACLPermission[]): void;

  /**
   * Check if a role has permission to perform an action on a resource
   */
  checkPermission(
    roleId: string,
    action: string,
    resource: string,
    context?: Record<string, any>
  ): boolean;

  /**
   * Get all permissions for a role, including inherited permissions
   */
  getRolePermissions(roleId: string): ACLPermission[];

  /**
   * Get all roles that have a specific permission
   */
  getRolesWithPermission(action: string, resource: string): string[];

  /**
   * Check if a role has access to specific attributes of a resource
   */
  checkAttributeAccess(
    roleId: string,
    resource: string,
    attributes: string[]
  ): boolean;

  /**
   * Evaluate conditions for a permission
   */
  evaluateConditions(
    conditions: Record<string, any>,
    context: Record<string, any>
  ): boolean;
}

/**
 * Configuration options for the ACL system
 */
export interface ACLConfig {
  /**
   * Default role assigned to users when no specific role is provided
   */
  defaultRole?: string;

  /**
   * Whether to allow access when no explicit permission is found
   */
  defaultAllow?: boolean;

  /**
   * Whether to enable permission inheritance through role extension
   */
  enableInheritance?: boolean;

  /**
   * Maximum depth for role inheritance to prevent circular dependencies
   */
  maxInheritanceDepth?: number;

  /**
   * Whether to cache permission checks for better performance
   */
  enableCaching?: boolean;

  /**
   * Time in milliseconds for how long to cache permission checks
   */
  cacheTTL?: number;
}

/**
 * Context passed to permission checks
 */
export interface ACLContext {
  /**
   * The user making the request
   */
  userId?: string;

  /**
   * The roles assigned to the user
   */
  userRoles?: string[];

  /**
   * Additional data needed for condition evaluation
   */
  attributes?: Record<string, any>;
}

/**
 * Result of a permission check
 */
export interface ACLPermissionResult {
  /**
   * Whether the permission is granted
   */
  granted: boolean;

  /**
   * The role that granted the permission (if any)
   */
  grantedBy?: string;

  /**
   * List of allowed attributes (if applicable)
   */
  allowedAttributes?: string[];

  /**
   * Any conditions that were evaluated
   */
  conditions?: Record<string, any>;
}
