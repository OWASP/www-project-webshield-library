import {
  ACLPermission,
  ACLRole,
  IACLManager,
  ACLConfig,
  ACLContext,
  ACLPermissionResult,
} from "./interfaces";

/**
 * Implementation of the Access Control List (ACL) manager.
 * Handles role-based permissions with inheritance and condition evaluation.
 */
export class ACLManager implements IACLManager {
  private roles: Map<string, ACLRole>;
  private config: Required<ACLConfig>;
  private permissionCache: Map<string, { result: boolean; timestamp: number }>;

  constructor(config: ACLConfig = {}) {
    this.roles = new Map();
    this.permissionCache = new Map();
    this.config = {
      defaultRole: config.defaultRole || "guest",
      defaultAllow: config.defaultAllow || false,
      enableInheritance: config.enableInheritance ?? true,
      maxInheritanceDepth: config.maxInheritanceDepth || 5,
      enableCaching: config.enableCaching ?? true,
      cacheTTL: config.cacheTTL || 300000, // 5 minutes default
    };
  }

  /**
   * Add a new role with its permissions
   */
  public addRole(role: ACLRole): void {
    if (this.roles.has(role.roleId)) {
      throw new Error(`Role '${role.roleId}' already exists`);
    }
    this.roles.set(role.roleId, role);
    this.clearCache();
  }

  /**
   * Remove a role and its permissions
   */
  public removeRole(roleId: string): void {
    if (!this.roles.has(roleId)) {
      throw new Error(`Role '${roleId}' does not exist`);
    }
    this.roles.delete(roleId);
    this.clearCache();
  }

  /**
   * Add permissions to an existing role
   */
  public addPermissions(roleId: string, permissions: ACLPermission[]): void {
    const role = this.roles.get(roleId);
    if (!role) {
      throw new Error(`Role '${roleId}' does not exist`);
    }
    role.permissions = [...role.permissions, ...permissions];
    this.clearCache();
  }

  /**
   * Remove permissions from a role
   */
  public removePermissions(roleId: string, permissions: ACLPermission[]): void {
    const role = this.roles.get(roleId);
    if (!role) {
      throw new Error(`Role '${roleId}' does not exist`);
    }

    role.permissions = role.permissions.filter(
      (existing) =>
        !permissions.some(
          (toRemove) =>
            toRemove.action === existing.action &&
            toRemove.resource === existing.resource
        )
    );
    this.clearCache();
  }

  /**
   * Check if a role has permission to perform an action on a resource
   */
  public checkPermission(
    roleId: string,
    action: string,
    resource: string,
    context: ACLContext = {}
  ): boolean {
    const cacheKey = this.getCacheKey(roleId, action, resource, context);

    if (this.config.enableCaching) {
      const cached = this.getCachedResult(cacheKey);
      if (cached !== undefined) return cached;
    }

    const result = this.evaluatePermission(roleId, action, resource, context);

    if (this.config.enableCaching) {
      this.cacheResult(cacheKey, result);
    }

    return result;
  }

  /**
   * Get all permissions for a role, including inherited permissions
   */
  public getRolePermissions(roleId: string): ACLPermission[] {
    const role = this.roles.get(roleId);
    if (!role) {
      throw new Error(`Role '${roleId}' does not exist`);
    }

    if (!this.config.enableInheritance || !role.extends) {
      return role.permissions;
    }

    const allPermissions = new Set<ACLPermission>();
    this.collectInheritedPermissions(role, allPermissions, new Set(), 0);

    return Array.from(allPermissions);
  }

  /**
   * Get all roles that have a specific permission
   */
  public getRolesWithPermission(action: string, resource: string): string[] {
    const rolesWithPermission: string[] = [];

    for (const [roleId, role] of this.roles) {
      if (this.checkPermission(roleId, action, resource)) {
        rolesWithPermission.push(roleId);
      }
    }

    return rolesWithPermission;
  }

  /**
   * Check if a role has access to specific attributes of a resource
   */
  public checkAttributeAccess(
    roleId: string,
    resource: string,
    attributes: string[]
  ): boolean {
    const permissions = this.getRolePermissions(roleId);

    return permissions.some((permission) => {
      if (permission.resource !== resource) return false;
      if (!permission.attributes) return true;
      return attributes.every(
        (attr) => permission.attributes?.includes(attr) ?? false
      );
    });
  }

  /**
   * Evaluate conditions for a permission
   */
  public evaluateConditions(
    conditions: Record<string, any>,
    context: Record<string, any>
  ): boolean {
    if (!conditions || Object.keys(conditions).length === 0) return true;

    return Object.entries(conditions).every(([key, value]) => {
      // Handle template strings in conditions
      if (
        typeof value === "string" &&
        value.startsWith("${") &&
        value.endsWith("}")
      ) {
        const contextKey = value.slice(2, -1);
        return context[key] === context[contextKey];
      }
      return context[key] === value;
    });
  }

  /**
   * Clear the permission cache
   */
  private clearCache(): void {
    this.permissionCache.clear();
  }

  /**
   * Generate a cache key for permission checks
   */
  private getCacheKey(
    roleId: string,
    action: string,
    resource: string,
    context: ACLContext
  ): string {
    return `${roleId}:${action}:${resource}:${JSON.stringify(context)}`;
  }

  /**
   * Get a cached permission check result
   */
  private getCachedResult(cacheKey: string): boolean | undefined {
    const cached = this.permissionCache.get(cacheKey);
    if (!cached) return undefined;

    if (Date.now() - cached.timestamp > this.config.cacheTTL) {
      this.permissionCache.delete(cacheKey);
      return undefined;
    }

    return cached.result;
  }

  /**
   * Cache a permission check result
   */
  private cacheResult(cacheKey: string, result: boolean): void {
    this.permissionCache.set(cacheKey, {
      result,
      timestamp: Date.now(),
    });
  }

  /**
   * Recursively collect inherited permissions for a role
   */
  private collectInheritedPermissions(
    role: ACLRole,
    collected: Set<ACLPermission>,
    visited: Set<string>,
    depth: number
  ): void {
    if (depth > this.config.maxInheritanceDepth) {
      throw new Error("Maximum inheritance depth exceeded");
    }

    role.permissions.forEach((permission) => collected.add(permission));

    if (!role.extends) return;

    for (const parentRoleId of role.extends) {
      if (visited.has(parentRoleId)) {
        throw new Error(
          `Circular dependency detected in role inheritance: ${parentRoleId}`
        );
      }

      const parentRole = this.roles.get(parentRoleId);
      if (!parentRole) {
        throw new Error(`Parent role '${parentRoleId}' does not exist`);
      }

      visited.add(parentRoleId);
      this.collectInheritedPermissions(
        parentRole,
        collected,
        visited,
        depth + 1
      );
      visited.delete(parentRoleId);
    }
  }

  /**
   * Evaluate if a role has a specific permission
   */
  private evaluatePermission(
    roleId: string,
    action: string,
    resource: string,
    context: ACLContext
  ): boolean {
    const role = this.roles.get(roleId);
    if (!role) return this.config.defaultAllow;

    // Check direct permissions
    const hasDirectPermission = role.permissions.some(
      (permission) =>
        permission.action === action &&
        permission.resource === resource &&
        this.evaluateConditions(permission.conditions || {}, context)
    );

    if (hasDirectPermission) return true;

    // Check inherited permissions if enabled
    if (this.config.enableInheritance && role.extends) {
      return role.extends.some((parentRoleId) =>
        this.evaluatePermission(parentRoleId, action, resource, context)
      );
    }

    return this.config.defaultAllow;
  }
}
