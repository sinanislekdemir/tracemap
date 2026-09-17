import { useLayoutEffect, useRef } from 'react';
import type { LogLine } from '../types';

interface ConsoleBodyProps {
  lines: LogLine[];
}

function formatTime(ms: number): string {
  const date = new Date(ms);
  const pad = (value: number, size = 2) => String(value).padStart(size, '0');
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`;
}

const ConsoleBody = ({ lines }: ConsoleBodyProps) => {
  const bodyRef = useRef<HTMLDivElement>(null);
  const pinnedRef = useRef(true);

  useLayoutEffect(() => {
    if (!pinnedRef.current) {
      return;
    }
    const body = bodyRef.current;
    if (body) {
      body.scrollTop = body.scrollHeight;
    }
  }, [lines]);

  const onScroll = () => {
    const body = bodyRef.current;
    if (!body) {
      return;
    }
    pinnedRef.current = body.scrollHeight - body.scrollTop - body.clientHeight < 24;
  };

  return (
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
  );
};

export default ConsoleBody;
