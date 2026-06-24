import { useState, useCallback } from 'react';
import { ValidationRule, ValidationResult } from '../types';

export interface UseSafeInputOptions {
  rules?: ValidationRule[];
  sanitize?: boolean;
  initialValue?: string;
}

export interface UseSafeInputResult {
  value: string;
  errors: string[];
  isValid: boolean;
  isDirty: boolean;
  handleChange(value: string): void;
  reset(): void;
}

function defaultSanitize(input: string): string {
  // Strip script tags
  let out = input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  // Remove event handlers
  out = out.replace(/\bon\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)/gi, '');
  return out;
}

export function useSafeInput(opts: UseSafeInputOptions = {}): UseSafeInputResult {
  const { rules = [], sanitize = true, initialValue = '' } = opts;

  const [value, setValue] = useState(initialValue);
  const [errors, setErrors] = useState<string[]>([]);
  const [isDirty, setIsDirty] = useState(false);

  const validate = useCallback(
    (val: string): ValidationResult => {
      const errs = rules
        .filter((r) => !r.validate(val))
        .map((r) => r.message);
      return { isValid: errs.length === 0, errors: errs };
    },
    [rules]
  );

  const handleChange = useCallback(
    (raw: string) => {
      const sanitized = sanitize ? defaultSanitize(raw) : raw;
      const result = validate(sanitized);
      setValue(sanitized);
      setErrors(result.errors);
      setIsDirty(true);
    },
    [sanitize, validate]
  );

  const reset = useCallback(() => {
    setValue(initialValue);
    setErrors([]);
    setIsDirty(false);
  }, [initialValue]);

  return {
    value,
    errors,
    isValid: errors.length === 0,
    isDirty,
    handleChange,
    reset,
  };
}
