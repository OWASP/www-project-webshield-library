import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { SafeInput } from '../../components/input/SafeInput';
import { SecurityErrorBoundary } from '../../components/security/SecurityErrorBoundary';

describe('SafeInput', () => {
  it('renders an input element', () => {
    const onChange = jest.fn();
    render(<SafeInput value="" onChange={onChange} />);
    expect(screen.getByRole('textbox')).toBeTruthy();
  });

  it('calls onChange with sanitized value', () => {
    const onChange = jest.fn();
    render(<SafeInput value="" onChange={onChange} sanitize />);
    fireEvent.change(screen.getByRole('textbox'), {
      target: { value: '<script>alert(1)</script>Hello' },
    });
    expect(onChange).toHaveBeenCalledWith('Hello');
  });

  it('displays validation errors when showErrors=true', () => {
    const onChange = jest.fn();
    const rules = [
      {
        validate: (v: string) => v.length >= 5,
        message: 'Too short',
      },
    ];
    render(
      <SafeInput value="" onChange={onChange} rules={rules} showErrors />
    );
    fireEvent.change(screen.getByRole('textbox'), {
      target: { value: 'ab' },
    });
    expect(screen.getByText('Too short')).toBeTruthy();
  });

  it('passes validation when value satisfies all rules', () => {
    const onValidationChange = jest.fn();
    const onChange = jest.fn();
    const rules = [
      { validate: (v: string) => v.length >= 3, message: 'Too short' },
    ];
    render(
      <SafeInput
        value=""
        onChange={onChange}
        rules={rules}
        showErrors
        onValidationChange={onValidationChange}
      />
    );
    fireEvent.change(screen.getByRole('textbox'), {
      target: { value: 'hello' },
    });
    expect(onValidationChange).toHaveBeenCalledWith(true, []);
  });

  it('marks input as aria-invalid when there are errors', () => {
    const onChange = jest.fn();
    const rules = [{ validate: () => false, message: 'Always fails' }];
    render(<SafeInput value="" onChange={onChange} rules={rules} showErrors />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'x' } });
    expect(screen.getByRole('textbox')).toHaveAttribute('aria-invalid', 'true');
  });
});

describe('SecurityErrorBoundary', () => {
  const ThrowingComponent: React.FC = () => {
    throw new Error('Test error');
  };

  beforeEach(() => {
    // Suppress console.error for expected errors
    jest.spyOn(console, 'error').mockImplementation(() => {/* noop */});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('renders children when no error', () => {
    render(
      <SecurityErrorBoundary>
        <div>Safe Content</div>
      </SecurityErrorBoundary>
    );
    expect(screen.getByText('Safe Content')).toBeTruthy();
  });

  it('renders fallback on error', () => {
    render(
      <SecurityErrorBoundary fallback={<div>Something went wrong</div>}>
        <ThrowingComponent />
      </SecurityErrorBoundary>
    );
    expect(screen.getByText('Something went wrong')).toBeTruthy();
  });

  it('renders default fallback when no fallback prop', () => {
    render(
      <SecurityErrorBoundary>
        <ThrowingComponent />
      </SecurityErrorBoundary>
    );
    expect(screen.getByRole('alert')).toBeTruthy();
  });

  it('calls onError when an error occurs', () => {
    const onError = jest.fn();
    render(
      <SecurityErrorBoundary onError={onError}>
        <ThrowingComponent />
      </SecurityErrorBoundary>
    );
    expect(onError).toHaveBeenCalledWith(
      expect.any(Error),
      expect.any(Object)
    );
  });
});
