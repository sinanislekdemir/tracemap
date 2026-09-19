import { useCallback, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import type { PointerEvent as ReactPointerEvent, ReactNode } from 'react';
import { nextZ } from '../zorder';

interface ModalProps {
  title: string;
  subtitle?: ReactNode;
  ariaLabel: string;
  /** Extra class names appended after the shared "modal modal--scan". */
  variant?: string;
  onClose: () => void;
  footer?: ReactNode;
  children: ReactNode;
}

const MIN_WIDTH = 320;
const MIN_HEIGHT = 200;
const DEFAULT_WIDTH = 760;
const DEFAULT_HEIGHT = 640;

// Initial widths per dialog, matching the old centered-modal sizes.
const VARIANT_WIDTHS: Record<string, number> = {
  'modal--scan': 620,
  'modal--ports': 680,
  'modal--domain': 760,
  'modal--tool': 540,
};

// Modal dialogs behave like the floating terminal windows: draggable,
// resizable and non-blocking, so they never hide the rest of the app. They are
// portaled into the shared window layer and draw their stacking order from the
// same counter, so focusing a window or a dialog raises it above the other.

interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

const initialRect = (variant?: string): Rect => {
  const width = Math.min(
    VARIANT_WIDTHS[variant ?? ''] ?? DEFAULT_WIDTH,
    Math.max(MIN_WIDTH, window.innerWidth - 48),
  );
  const height = Math.min(DEFAULT_HEIGHT, Math.max(MIN_HEIGHT, window.innerHeight - 80));
  return {
    x: Math.max(8, (window.innerWidth - width) / 2),
    y: Math.max(8, (window.innerHeight - height) / 2),
    width,
    height,
  };
};

/**
 * Modal is the shared shell for the app's tool dialogs. Unlike a classic
 * modal it renders as a movable window with no backdrop, so the map and any
 * floating terminal windows stay visible and interactive behind it.
 */
const Modal = ({
  title,
  subtitle,
  ariaLabel,
  variant,
  onClose,
  footer,
  children,
}: ModalProps) => {
  const [rect, setRect] = useState<Rect>(() => initialRect(variant));
  const [z, setZ] = useState(nextZ);
  const rectRef = useRef(rect);
  rectRef.current = rect;

  const focusSelf = useCallback(() => setZ(nextZ()), []);

  const startDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest('button')) {
      return;
    }
    event.preventDefault();
    focusSelf();
    const startX = event.clientX;
    const startY = event.clientY;
    const orig = rectRef.current;
    const onPointerMove = (moveEvent: PointerEvent) => {
      const nextX = Math.min(
        window.innerWidth - 80,
        Math.max(80 - orig.width, orig.x + moveEvent.clientX - startX),
      );
      const nextY = Math.min(
        window.innerHeight - 40,
        Math.max(0, orig.y + moveEvent.clientY - startY),
      );
      setRect((current) => ({ ...current, x: nextX, y: nextY }));
    };
    const onPointerUp = () => {
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);
    };
    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', onPointerUp);
  };

  const startResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    focusSelf();
    const startX = event.clientX;
    const startY = event.clientY;
    const orig = rectRef.current;
    const onPointerMove = (moveEvent: PointerEvent) => {
      setRect((current) => ({
        ...current,
        width: Math.max(MIN_WIDTH, orig.width + moveEvent.clientX - startX),
        height: Math.max(MIN_HEIGHT, orig.height + moveEvent.clientY - startY),
      }));
    };
    const onPointerUp = () => {
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);
    };
    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', onPointerUp);
  };

  const dialog = (
    <div
      className={`modal modal--scan modal--float${variant ? ` ${variant}` : ''}`}
      role="dialog"
      aria-label={ariaLabel}
      style={{ left: rect.x, top: rect.y, width: rect.width, height: rect.height, zIndex: z }}
      onPointerDown={focusSelf}
    >
      <div className="modal-head" onPointerDown={startDrag}>
        <div>
          <div className="modal-title">{title}</div>
          {subtitle != null && <div className="modal-sub selectable">{subtitle}</div>}
        </div>
        <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
          ×
        </button>
      </div>

      <div className="modal-body">{children}</div>

      {footer != null && <div className="modal-foot">{footer}</div>}

      <div className="fw-resize" onPointerDown={startResize} title="Resize" />
    </div>
  );

  // Portal into the shared window layer so dialogs and terminal windows share
  // one stacking context (and therefore one z-order).
  const layer = document.getElementById('window-layer');
  return layer ? createPortal(dialog, layer) : dialog;
};

export default Modal;
