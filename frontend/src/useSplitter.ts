import { useCallback } from 'react';
import type { PointerEvent as ReactPointerEvent } from 'react';

interface SplitterOptions {
  /** Width of the pane when the drag starts. */
  startWidth: number;
  /** Whether the pane is currently open; closed panes do not resize. */
  open: boolean;
  min: number;
  max: number;
  /**
   * When true the pane sits to the right of the handle, so dragging left makes
   * it wider (the delta is subtracted).
   */
  invert?: boolean;
  onWidth: (width: number) => void;
  onToggle: () => void;
}

/**
 * useSplitter returns a pointer-down handler for a pane handle: dragging
 * resizes the pane between min and max, and a click without movement toggles
 * it open or closed.
 */
export function useSplitter({
  startWidth,
  open,
  min,
  max,
  invert,
  onWidth,
  onToggle,
}: SplitterOptions) {
  return useCallback(
    (event: ReactPointerEvent<HTMLDivElement>) => {
      event.preventDefault();
      const startX = event.clientX;
      let moved = false;

      const onMove = (moveEvent: PointerEvent) => {
        if (!open) {
          return;
        }
        if (Math.abs(moveEvent.clientX - startX) > 3) {
          moved = true;
        }
        const delta = moveEvent.clientX - startX;
        const raw = invert ? startWidth - delta : startWidth + delta;
        onWidth(Math.min(max, Math.max(min, raw)));
      };

      const onUp = () => {
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
        if (!moved) {
          onToggle();
        }
      };

      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
    },
    [startWidth, open, min, max, invert, onWidth, onToggle],
  );
}
