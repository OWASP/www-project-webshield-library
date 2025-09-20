import { ACLManager } from "./acl-manager";
import {
  ACLPermission,
  ACLRole,
  ACLConfig,
  ACLContext,
  IACLManager,
} from "./interfaces";
import {
  ACLError,
  RoleNotFoundError,
  CircularDependencyError,
  MaxInheritanceDepthError,
  DuplicateRoleError,
  InvalidPermissionError,
  ConditionEvaluationError,
} from "./errors";

export {
  // Main Implementation
  ACLManager,

  // Interfaces
  ACLPermission,
  ACLRole,
  ACLConfig,
  ACLContext,
  IACLManager,

  // Errors
  ACLError,
  RoleNotFoundError,
  CircularDependencyError,
  MaxInheritanceDepthError,
  DuplicateRoleError,
  InvalidPermissionError,
  ConditionEvaluationError,
};
