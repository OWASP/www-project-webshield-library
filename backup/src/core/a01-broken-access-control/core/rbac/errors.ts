/**
 * Base error class for RBAC-related errors
 */
export class RBACError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RBACError";
  }
}

/**
 * Error thrown when a role is not found
 */
export class RoleNotFoundError extends RBACError {
  constructor(roleName: string) {
    super(`Role '${roleName}' does not exist`);
    this.name = "RoleNotFoundError";
  }
}

/**
 * Error thrown when attempting to create a duplicate role
 */
export class DuplicateRoleError extends RBACError {
  constructor(roleName: string) {
    super(`Role '${roleName}' already exists`);
    this.name = "DuplicateRoleError";
  }
}

/**
 * Error thrown when attempting to remove a role that is inherited by others
 */
export class InheritedRoleError extends RBACError {
  constructor(roleName: string, inheritingRole: string) {
    super(
      `Cannot remove role '${roleName}' as it is inherited by '${inheritingRole}'`
    );
    this.name = "InheritedRoleError";
  }
}

/**
 * Error thrown when a parent role does not exist
 */
export class InvalidParentRoleError extends RBACError {
  constructor(parentRole: string) {
    super(`Parent role '${parentRole}' does not exist`);
    this.name = "InvalidParentRoleError";
  }
}

/**
 * Error thrown when there are permission validation issues
 */
export class InvalidPermissionError extends RBACError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidPermissionError";
  }
}

/**
 * Error thrown when there are condition evaluation issues
 */
export class ConditionEvaluationError extends RBACError {
  constructor(message: string) {
    super(message);
    this.name = "ConditionEvaluationError";
  }
}
