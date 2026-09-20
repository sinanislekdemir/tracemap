import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';

// GlobalErrorBridge turns uncaught exceptions and unhandled promise rejections
// into a render error, so the enclosing ErrorBoundary shows the same crash
// screen (with the full stack) as a normal render failure.
const GlobalErrorBridge = ({ children }: { children: ReactNode }) => {
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    const onError = (event: ErrorEvent) => {
      // Resource-load failures have no error object; ignore them.
      if (!event.error) {
        return;
      }
      setError(event.error);
    };
    const onRejection = (event: PromiseRejectionEvent) => {
      setError(event.reason ?? new Error('unhandled promise rejection'));
    };
    window.addEventListener('error', onError);
    window.addEventListener('unhandledrejection', onRejection);
    return () => {
      window.removeEventListener('error', onError);
      window.removeEventListener('unhandledrejection', onRejection);
    };
  }, []);

  if (error) {
    throw error;
  }
  return <>{children}</>;
};

export default GlobalErrorBridge;
