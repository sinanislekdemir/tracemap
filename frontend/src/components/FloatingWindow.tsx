import type { PointerEvent as ReactPointerEvent, ReactNode } from 'react';
import type { FloatingWindowState } from '../types';

interface FloatingWindowProps {
  win: FloatingWindowState;
  active: boolean;
  onFocus: (id: string) => void;
  onClose: (id: string) => void;
  onMove: (id: string, x: number, y: number) => void;
  onResize: (id: string, width: number, height: number) => void;
  headerExtra?: ReactNode;
  children: ReactNode;
}

const FloatingWindow = ({
  win,
  active,
  onFocus,
  onClose,
  onMove,
  onResize,
  headerExtra,
  children,
}: FloatingWindowProps) => {
  const startDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest('button')) {
      return;
    }
    event.preventDefault();
    onFocus(win.id);
    const startX = event.clientX;
    const startY = event.clientY;
    const origX = win.x;
    const origY = win.y;
    const onPointerMove = (moveEvent: PointerEvent) => {
      const nextX = Math.min(
        window.innerWidth - 80,
        Math.max(80 - win.width, origX + moveEvent.clientX - startX),
      );
      const nextY = Math.min(
        window.innerHeight - 40,
        Math.max(0, origY + moveEvent.clientY - startY),
      );
      onMove(win.id, nextX, nextY);
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
    onFocus(win.id);
    const startX = event.clientX;
    const startY = event.clientY;
    const origWidth = win.width;
    const origHeight = win.height;
    const onPointerMove = (moveEvent: PointerEvent) => {
      onResize(win.id, origWidth + moveEvent.clientX - startX, origHeight + moveEvent.clientY - startY);
    };
    const onPointerUp = () => {
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);
    };
    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', onPointerUp);
  };

  return (
    <section
      className={`fw${active ? ' is-active' : ''}`}
      style={{ left: win.x, top: win.y, width: win.width, height: win.height, zIndex: win.z }}
      onPointerDown={() => onFocus(win.id)}
    >
      <header className="fw-head" onPointerDown={startDrag}>
        <span className="fw-dot" data-kind={win.kind} />
        <span className="fw-title">{win.title}</span>
        <span className="fw-spacer" />
        {headerExtra}
        <button type="button" className="fw-btn" onClick={() => onClose(win.id)} aria-label="Close window">
          ×
        </button>
      </header>
      <div className="fw-body">{children}</div>
      <div className="fw-resize" onPointerDown={startResize} title="Resize" />
    </section>
  );
};

export default FloatingWindow;
