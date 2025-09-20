import { URLControlManager } from "./url-control-manager";
import {
  URLPattern,
  URLRequestContext,
  URLAccessResult,
  URLControlOptions,
  URLCondition,
  CustomConditionValidator,
  RoleConditionConfig,
  IPConditionConfig,
  TimeConditionConfig,
  RateConditionConfig,
  HeaderConditionConfig,
  QueryConditionConfig,
  CustomConditionConfig,
} from "./interfaces";
import { HttpMethod, ConditionType } from "./types";
import {
  URLControlError,
  InvalidPatternError,
  InvalidConditionError,
  ValidatorNotFoundError,
  PatternConflictError,
  InvalidContextError,
  RateLimitExceededError,
  MissingHeaderError,
  MissingQueryParamError,
  IPRestrictedError,
  TimeRestrictedError,
} from "./errors";

export {
  // Core Manager
  URLControlManager,

  // Interfaces
  URLPattern,
  URLRequestContext,
  URLAccessResult,
  URLControlOptions,
  URLCondition,
  CustomConditionValidator,

  // Condition Configs
  RoleConditionConfig,
  IPConditionConfig,
  TimeConditionConfig,
  RateConditionConfig,
  HeaderConditionConfig,
  QueryConditionConfig,
  CustomConditionConfig,

  // Types
  HttpMethod,
  ConditionType,

  // Errors
  URLControlError,
  InvalidPatternError,
  InvalidConditionError,
  ValidatorNotFoundError,
  PatternConflictError,
  InvalidContextError,
  RateLimitExceededError,
  MissingHeaderError,
  MissingQueryParamError,
  IPRestrictedError,
  TimeRestrictedError,
};
