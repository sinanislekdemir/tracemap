import { useEffect, useLayoutEffect, useRef } from 'react';
import type { PointerEvent as ReactPointerEvent } from 'react';
import type { LogLine } from '../types';

interface ConsoleProps {
  lines: LogLine[];
  open: boolean;
  height: number;
  state: 'ready' | 'tracing' | 'done' | 'error';
  onToggle: () => void;
  onClear: () => void;
  onResizeStart: (event: ReactPointerEvent<HTMLDivElement>) => void;
}

function formatTime(ms: number): string {
  const date = new Date(ms);
  const pad = (value: number, size = 2) => String(value).padStart(size, '0');
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`;
}

const Console = ({ lines, open, height, state, onToggle, onClear, onResizeStart }: ConsoleProps) => {
  const bodyRef = useRef<HTMLDivElement>(null);
  const pinnedRef = useRef(true);

  useLayoutEffect(() => {
    if (!open || !pinnedRef.current) {
      return;
    }
    const body = bodyRef.current;
    if (body) {
      body.scrollTop = body.scrollHeight;
    }
  }, [lines, open]);

  useEffect(() => {
    pinnedRef.current = true;
  }, [open]);

  const onScroll = () => {
    const body = bodyRef.current;
    if (!body) {
      return;
    }
    pinnedRef.current = body.scrollHeight - body.scrollTop - body.clientHeight < 24;
  };

  return (
    <section className={`console${open ? '' : ' is-collapsed'}`} style={open ? { height } : undefined}>
      <div
        className="console-splitter"
        onPointerDown={onResizeStart}
        role="separator"
        aria-orientation="horizontal"
      />
      <header className="console-head">
        <button type="button" className="console-toggle" onClick={onToggle} aria-expanded={open}>
          {open ? '▾' : '▸'}
        </button>
        <span className="console-title">CONSOLE</span>
        <span className="console-state" data-state={state}>
          {state}
        </span>
        <span className="console-count">{lines.length} lines</span>
        <span className="console-spacer" />
        <button type="button" className="console-clear" onClick={onClear} disabled={lines.length === 0}>
          CLEAR
        </button>
      </header>
      {open && (
        <div className="console-body" ref={bodyRef} onScroll={onScroll}>
          {lines.length === 0 ? (
            <div className="console-empty">waiting for activity…</div>
          ) : (
            lines.map((line) => (
              <div className="console-line" key={line.id} data-level={line.level}>
                <span className="console-time">{formatTime(line.time)}</span>
                <span className="console-text selectable">{line.text}</span>
              </div>
            ))
          )}
        </div>
      )}
    </section>
  );
};

export default Console;
