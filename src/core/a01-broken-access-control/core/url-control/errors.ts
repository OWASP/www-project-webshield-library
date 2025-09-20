/**
 * Base error class for URL access control
 */
export class URLControlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "URLControlError";
  }
}

/**
 * Error thrown when a pattern is invalid
 */
export class InvalidPatternError extends URLControlError {
  constructor(pattern: string, reason: string) {
    super(`Invalid URL pattern '${pattern}': ${reason}`);
    this.name = "InvalidPatternError";
  }
}

/**
 * Error thrown when there are condition configuration issues
 */
export class InvalidConditionError extends URLControlError {
  constructor(type: string, reason: string) {
    super(`Invalid condition configuration for type '${type}': ${reason}`);
    this.name = "InvalidConditionError";
  }
}

/**
 * Error thrown when a custom validator is not found
 */
export class ValidatorNotFoundError extends URLControlError {
  constructor(validator: string) {
    super(`Custom validator '${validator}' not found`);
    this.name = "ValidatorNotFoundError";
  }
}

/**
 * Error thrown when pattern priority conflicts occur
 */
export class PatternConflictError extends URLControlError {
  constructor(pattern1: string, pattern2: string) {
    super(`Pattern conflict between '${pattern1}' and '${pattern2}'`);
    this.name = "PatternConflictError";
  }
}

/**
 * Error thrown for invalid condition evaluation contexts
 */
export class InvalidContextError extends URLControlError {
  constructor(message: string) {
    super(`Invalid context: ${message}`);
    this.name = "InvalidContextError";
  }
}

/**
 * Error thrown for rate limit exceeded conditions
 */
export class RateLimitExceededError extends URLControlError {
  constructor(limit: number, window: number) {
    super(`Rate limit of ${limit} requests per ${window} seconds exceeded`);
    this.name = "RateLimitExceededError";
  }
}

/**
 * Error thrown when required headers are missing
 */
export class MissingHeaderError extends URLControlError {
  constructor(headers: string[]) {
    super(`Missing required headers: ${headers.join(", ")}`);
    this.name = "MissingHeaderError";
  }
}

/**
 * Error thrown when required query parameters are missing
 */
export class MissingQueryParamError extends URLControlError {
  constructor(params: string[]) {
    super(`Missing required query parameters: ${params.join(", ")}`);
    this.name = "MissingQueryParamError";
  }
}

/**
 * Error thrown for IP address restriction violations
 */
export class IPRestrictedError extends URLControlError {
  constructor(ip: string) {
    super(`Access denied for IP address: ${ip}`);
    this.name = "IPRestrictedError";
  }
}

/**
 * Error thrown for time-based access restrictions
 */
export class TimeRestrictedError extends URLControlError {
  constructor(message: string) {
    super(message);
    this.name = "TimeRestrictedError";
  }
}
