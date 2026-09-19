import { useEffect, useRef } from 'react';

/**
 * useEscape calls onEscape when the user presses Escape while active. The
 * callback is held in a ref so the listener is installed once per activation
 * instead of on every render, and it never captures a stale closure.
 */
export function useEscape(active: boolean, onEscape: () => void) {
  const handler = useRef(onEscape);

  useEffect(() => {
    handler.current = onEscape;
  });

  useEffect(() => {
    if (!active) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        handler.current();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [active]);
}
