import React, { Component, ErrorInfo, ReactNode } from 'react';

export interface SecurityErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, info: ErrorInfo) => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class SecurityErrorBoundary extends Component<
  SecurityErrorBoundaryProps,
  State
> {
  constructor(props: SecurityErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Avoid exposing stack traces in production logs
    console.error('[WebShield] Caught security error:', error.message);
    this.props.onError?.(error, info);
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        this.props.fallback ?? (
          <div role="alert">
            <h2>An error occurred</h2>
            <p>Something went wrong. Please refresh the page or try again later.</p>
          </div>
        )
      );
    }
    return this.props.children;
  }
}
