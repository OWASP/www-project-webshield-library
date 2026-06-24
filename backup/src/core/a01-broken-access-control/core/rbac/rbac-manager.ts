import {
  Role,
  Permission,
  Subject,
  Resource,
  AccessRequest,
  RBACOptions,
  PermissionVerifier,
} from "./interfaces";
import {
  RBACError,
  RoleNotFoundError,
  DuplicateRoleError,
  InheritedRoleError,
  InvalidParentRoleError,
  InvalidPermissionError,
  ConditionEvaluationError,
} from "./errors";

export class RBAC {
  private roles: Map<string, Role>;
  private permissionVerifiers: Map<string, PermissionVerifier>;
  private options: Required<RBACOptions>;

  constructor(options: RBACOptions = {}) {
    this.roles = new Map();
    this.permissionVerifiers = new Map();
    this.options = {
      caseSensitive: false,
      hierarchical: true,
      dynamicPermissions: false,
      ...options,
    };
  }

  /**
   * Add a new role to the RBAC system
   */
  public addRole(role: Role): void {
    const roleName = this.normalizeRoleName(role.name);

    if (this.roles.has(roleName)) {
      throw new DuplicateRoleError(roleName);
    }

    // Validate inheritance
    if (role.inheritFrom) {
      for (const parentRole of role.inheritFrom) {
        const normalizedParentRole = this.normalizeRoleName(parentRole);
        if (!this.roles.has(normalizedParentRole)) {
          throw new InvalidParentRoleError(parentRole);
        }
      }
    }

    this.roles.set(roleName, {
      ...role,
      name: roleName,
    });
  }

  /**
   * Remove a role from the RBAC system
   */
  public removeRole(roleName: string): void {
    const normalizedName = this.normalizeRoleName(roleName);

    if (!this.roles.has(normalizedName)) {
      throw new RoleNotFoundError(roleName);
    }

    // Check if any other roles inherit from this one
    for (const [name, role] of this.roles.entries()) {
      if (role.inheritFrom?.includes(normalizedName)) {
        throw new InheritedRoleError(roleName, name);
      }
    }

    this.roles.delete(normalizedName);
  }

  /**
   * Check if a subject has permission to perform an action on a resource
   */
  public async can(request: AccessRequest): Promise<boolean> {
    const { subject, action, resource } = request;

    // Get all roles including inherited ones
    const effectiveRoles = this.getEffectiveRoles(subject.roles);

    // Check each role's permissions
    for (const roleName of effectiveRoles) {
      const role = this.roles.get(roleName);
      if (!role) continue;

      const hasPermission = await this.checkRolePermission(
        role,
        action,
        resource,
        request
      );
      if (hasPermission) return true;
    }

    return false;
  }

  /**
   * Register a custom permission verifier
   */
  public registerPermissionVerifier(
    action: string,
    verifier: PermissionVerifier
  ): void {
    this.permissionVerifiers.set(action, verifier);
  }

  /**
   * Get all permissions for a subject
   */
  public getSubjectPermissions(subject: Subject): Permission[] {
    const permissions: Permission[] = [];
    const effectiveRoles = this.getEffectiveRoles(subject.roles);

    for (const roleName of effectiveRoles) {
      const role = this.roles.get(roleName);
      if (role) {
        permissions.push(...role.permissions);
      }
    }

    return permissions;
  }

  private normalizeRoleName(name: string): string {
    return this.options.caseSensitive ? name : name.toLowerCase();
  }

  private getEffectiveRoles(roleNames: string[]): Set<string> {
    const effectiveRoles = new Set<string>();

    const addRole = (roleName: string) => {
      const normalizedName = this.normalizeRoleName(roleName);
      if (effectiveRoles.has(normalizedName)) return;

      effectiveRoles.add(normalizedName);

      if (this.options.hierarchical) {
        const role = this.roles.get(normalizedName);
        if (role?.inheritFrom) {
          role.inheritFrom.forEach((parentRole: string) => addRole(parentRole));
        }
      }
    };

    roleNames.forEach((roleName) => addRole(roleName));
    return effectiveRoles;
  }

  private async checkRolePermission(
    role: Role,
    action: string,
    resource: Resource,
    request: AccessRequest
  ): Promise<boolean> {
    for (const permission of role.permissions) {
      if (this.matchesPermission(permission, action, resource)) {
        // Check custom verifier if exists
        const verifier = this.permissionVerifiers.get(action);
        if (verifier) {
          const isAllowed = await verifier(request);
          if (!isAllowed) continue;
        }

        // Check conditions if they exist
        if (permission.conditions) {
          const conditionsMet = this.evaluateConditions(
            permission.conditions,
            request
          );
          if (!conditionsMet) continue;
        }

        return true;
      }
    }

    return false;
  }

  private matchesPermission(
    permission: Permission,
    action: string,
    resource: Resource
  ): boolean {
    return (
      permission.action === action &&
      (permission.resource === "*" || permission.resource === resource.type)
    );
  }

  private evaluateConditions(
    conditions: Record<string, any>,
    request: AccessRequest
  ): boolean {
    // Simple condition evaluation - can be extended for more complex conditions
    for (const [key, value] of Object.entries(conditions)) {
      const contextValue = request.context?.[key];
      if (contextValue !== value) return false;
    }
    return true;
  }
}
