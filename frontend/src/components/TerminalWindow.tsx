import ConsoleBody from './ConsoleBody';
import FloatingWindow from './FloatingWindow';
import type { FloatingWindowState, LogLine, TerminalKind } from '../types';

interface TerminalWindowProps {
  win: FloatingWindowState;
  active: boolean;
  lines: LogLine[];
  onFocus: (id: string) => void;
  onClose: (id: string) => void;
  onMove: (id: string, x: number, y: number) => void;
  onResize: (id: string, width: number, height: number) => void;
  onClear: (kind: TerminalKind) => void;
}

const TerminalWindow = ({
  win,
  active,
  lines,
  onFocus,
  onClose,
  onMove,
  onResize,
  onClear,
}: TerminalWindowProps) => (
  <FloatingWindow
    win={win}
    active={active}
    onFocus={onFocus}
    onClose={onClose}
    onMove={onMove}
    onResize={onResize}
    headerExtra={
      <>
        <span className="fw-count">{lines.length}</span>
        <button
          type="button"
          className="fw-btn fw-btn--text"
          onClick={() => onClear(win.kind)}
          disabled={lines.length === 0}
        >
          CLR
        </button>
      </>
    }
  >
    <ConsoleBody lines={lines} />
  </FloatingWindow>
);

export default TerminalWindow;
