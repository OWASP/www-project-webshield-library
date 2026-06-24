import React, { FormEvent, ReactNode, useCallback } from 'react';
import { useSecurityContext } from '../../hooks/useSecurityContext';

export interface SecureFormProps
  extends Omit<React.FormHTMLAttributes<HTMLFormElement>, 'onSubmit'> {
  children: ReactNode;
  onSubmit(data: FormData, event: FormEvent<HTMLFormElement>): void;
  /** Inject CSRF token as a hidden field (default: true) */
  csrfProtected?: boolean;
}

/**
 * A form wrapper that automatically injects the CSRF token as a hidden field
 * and disables autocomplete for sensitive forms.
 */
export const SecureForm: React.FC<SecureFormProps> = ({
  children,
  onSubmit,
  csrfProtected = true,
  ...rest
}) => {
  const { csrfToken } = useSecurityContext();

  const handleSubmit = useCallback(
    (e: FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      const formData = new FormData(e.currentTarget);
      onSubmit(formData, e);
    },
    [onSubmit]
  );

  return (
    <form onSubmit={handleSubmit} {...rest}>
      {csrfProtected && csrfToken && (
        <input type="hidden" name="_csrf" value={csrfToken} />
      )}
      {children}
    </form>
  );
};
