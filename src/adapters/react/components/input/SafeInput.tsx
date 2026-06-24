import React, { useState, useCallback, forwardRef } from 'react';
import { ValidationRule } from '../../types';

export interface SafeInputProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'onChange'> {
  value: string;
  onChange(value: string): void;
  rules?: ValidationRule[];
  /** Sanitize on each keystroke (default: true) */
  sanitize?: boolean;
  showErrors?: boolean;
  onValidationChange?(isValid: boolean, errors: string[]): void;
}

function sanitize(input: string): string {
  let out = input.replace(
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    ''
  );
  out = out.replace(/\bon\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)/gi, '');
  return out;
}

export const SafeInput = forwardRef<HTMLInputElement, SafeInputProps>(
  (
    {
      value,
      onChange,
      rules = [],
      sanitize: shouldSanitize = true,
      showErrors = false,
      onValidationChange,
      className,
      ...rest
    },
    ref
  ) => {
    const [errors, setErrors] = useState<string[]>([]);

    const handleChange = useCallback(
      (e: React.ChangeEvent<HTMLInputElement>) => {
        let next = e.target.value;
        if (shouldSanitize) next = sanitize(next);

        const errs = rules.filter((r) => !r.validate(next)).map((r) => r.message);
        setErrors(errs);
        onValidationChange?.(errs.length === 0, errs);
        onChange(next);
      },
      [shouldSanitize, rules, onChange, onValidationChange]
    );

    return (
      <div>
        <input
          ref={ref}
          value={value}
          onChange={handleChange}
          className={`${className ?? ''} ${errors.length > 0 ? 'error' : ''}`.trim()}
          aria-invalid={errors.length > 0}
          {...rest}
        />
        {showErrors && errors.length > 0 && (
          <ul role="alert" aria-live="polite">
            {errors.map((err, i) => (
              <li key={i}>{err}</li>
            ))}
          </ul>
        )}
      </div>
    );
  }
);

SafeInput.displayName = 'SafeInput';
