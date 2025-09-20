import { RBAC } from "./rbac-manager";
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

export {
  // Main implementation
  RBAC,

  // Core interfaces
  Role,
  Permission,
  Subject,
  Resource,
  AccessRequest,
  RBACOptions,
  PermissionVerifier,

  // Error classes
  RBACError,
  RoleNotFoundError,
  DuplicateRoleError,
  InheritedRoleError,
  InvalidParentRoleError,
  InvalidPermissionError,
  ConditionEvaluationError,
};
