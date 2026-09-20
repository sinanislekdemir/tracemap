import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import CrashScreen from './CrashScreen';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
  componentStack: string;
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null, componentStack: '' };

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('render error', error, info);
    this.setState({ componentStack: info.componentStack ?? '' });
  }

  render() {
    if (this.state.error) {
      return (
        <CrashScreen
          title="RENDER ERROR"
          error={this.state.error}
          componentStack={this.state.componentStack}
          onRetry={() => this.setState({ error: null, componentStack: '' })}
        />
      );
    }
    return this.props.children;
  }
}

export default ErrorBoundary;
