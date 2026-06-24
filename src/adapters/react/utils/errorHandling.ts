export type SecurityErrorCode =
  | 'AUTH_FAILED'
  | 'TOKEN_EXPIRED'
  | 'PERMISSION_DENIED'
  | 'VALIDATION_FAILED'
  | 'CSRF_TOKEN_INVALID'
  | 'INPUT_MALICIOUS'
  | 'HTTP_ERROR'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN';

export class SecurityError extends Error {
  readonly code: SecurityErrorCode;
  readonly context: Record<string, unknown>;
  readonly timestamp: Date;

  constructor(
    message: string,
    code: SecurityErrorCode,
    context: Record<string, unknown> = {}
  ) {
    super(message);
    this.name = 'SecurityError';
    this.code = code;
    this.context = context;
    this.timestamp = new Date();
    Object.setPrototypeOf(this, SecurityError.prototype);
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      context: this.context,
      timestamp: this.timestamp.toISOString(),
    };
  }
}

export function isSecurityError(err: unknown): err is SecurityError {
  return err instanceof SecurityError;
}
