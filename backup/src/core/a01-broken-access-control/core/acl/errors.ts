/**
 * Error thrown when there are issues with ACL operations
 */
export class ACLError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ACLError";
  }
}

/**
 * Error thrown when a role is not found
 */
export class RoleNotFoundError extends ACLError {
  constructor(roleId: string) {
    super(`Role '${roleId}' does not exist`);
    this.name = "RoleNotFoundError";
  }
}

/**
 * Error thrown when there is a circular dependency in role inheritance
 */
export class CircularDependencyError extends ACLError {
  constructor(roleId: string) {
    super(`Circular dependency detected in role inheritance: ${roleId}`);
    this.name = "CircularDependencyError";
  }
}

/**
 * Error thrown when maximum inheritance depth is exceeded
 */
export class MaxInheritanceDepthError extends ACLError {
  constructor() {
    super("Maximum inheritance depth exceeded");
    this.name = "MaxInheritanceDepthError";
  }
}

/**
 * Error thrown when a role already exists
 */
export class DuplicateRoleError extends ACLError {
  constructor(roleId: string) {
    super(`Role '${roleId}' already exists`);
    this.name = "DuplicateRoleError";
  }
}

/**
 * Error thrown when an invalid permission is provided
 */
export class InvalidPermissionError extends ACLError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidPermissionError";
  }
}

/**
 * Error thrown when there are condition evaluation issues
 */
export class ConditionEvaluationError extends ACLError {
  constructor(message: string) {
    super(message);
    this.name = "ConditionEvaluationError";
  }
}
