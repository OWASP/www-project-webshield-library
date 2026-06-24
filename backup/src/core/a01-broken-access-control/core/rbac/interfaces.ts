export interface Permission {
  /**
   * The action being permitted (e.g., 'read', 'write', 'delete')
   */
  action: string;

  /**
   * The resource type being accessed (e.g., 'users', 'posts', 'comments')
   * Use '*' for wildcard access to all resources
   */
  resource: string;

  /**
   * Any conditions that must be met for the permission to be granted
   */
  conditions?: Record<string, any>;
}

export interface Role {
  /**
   * Unique identifier for the role
   */
  name: string;

  /**
   * Optional description of the role's purpose
   */
  description?: string;

  /**
   * List of permissions granted to this role
   */
  permissions: Permission[];

  /**
   * Parent roles from which this role inherits permissions
   */
  inheritFrom?: string[];
}

export interface Subject {
  /**
   * Unique identifier for the subject (user)
   */
  id: string;

  /**
   * List of roles assigned to the subject
   */
  roles: string[];

  /**
   * Additional attributes about the subject
   */
  attributes?: Record<string, any>;
}

export interface Resource {
  /**
   * The type of resource being accessed
   */
  type: string;

  /**
   * Unique identifier for the resource
   */
  id: string;

  /**
   * Additional attributes about the resource
   */
  attributes?: Record<string, any>;
}

export interface AccessRequest {
  /**
   * The subject requesting access
   */
  subject: Subject;

  /**
   * The action being requested
   */
  action: string;

  /**
   * The resource being accessed
   */
  resource: Resource;

  /**
   * Additional context for permission evaluation
   */
  context?: Record<string, any>;
}

/**
 * Custom permission verifier function type
 * Returns boolean indicating if access should be granted
 */
export type PermissionVerifier = (
  request: AccessRequest
) => boolean | Promise<boolean>;

export interface RBACOptions {
  /**
   * Whether role names are case sensitive
   * Default: false
   */
  caseSensitive?: boolean;

  /**
   * Whether to enable role inheritance
   * Default: true
   */
  hierarchical?: boolean;

  /**
   * Whether to enable dynamic permission evaluation through verifiers
   * Default: false
   */
  dynamicPermissions?: boolean;
}
