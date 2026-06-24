/**
 * SecurityError - Custom error class for security-related errors
 * Provides structured error handling and context
 */

export enum SecurityErrorCode {
  AUTH_FAILED = 'AUTH_FAILED',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  PERMISSION_DENIED = 'PERMISSION_DENIED',
  VALIDATION_FAILED = 'VALIDATION_FAILED',
  CSRF_TOKEN_INVALID = 'CSRF_TOKEN_INVALID',
  INPUT_MALICIOUS = 'INPUT_MALICIOUS',
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  HTTP_ERROR = 'HTTP_ERROR',
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
}

export class SecurityError extends Error {
  public code: SecurityErrorCode;
  public context?: Record<string, any>;
  public timestamp: number;

  constructor(message: string, code: SecurityErrorCode, context?: Record<string, any>) {
    super(message);
    this.name = 'SecurityError';
    this.code = code;
    this.context = context;
    this.timestamp = Date.now();

    // Maintain proper prototype chain
    Object.setPrototypeOf(this, SecurityError.prototype);
  }

  /**
   * Convert error to plain object for logging/serialization
   */
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      context: this.context,
      timestamp: this.timestamp,
      stack: this.stack,
    };
  }
}

/**
 * Check if error is a SecurityError
 */
export function isSecurityError(error: any): error is SecurityError {
  return error instanceof SecurityError;
}
