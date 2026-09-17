import type { PointerEvent as ReactPointerEvent } from 'react';
import ConsoleBody from './ConsoleBody';
import NetcatPanel from './NetcatPanel';
import type { LogLevel, LogLine } from '../types';

export type BottomTab = 'console' | 'netcat';

interface BottomDockProps {
  open: boolean;
  height: number;
  tab: BottomTab;
  onTabChange: (tab: BottomTab) => void;
  onToggle: () => void;
  onResizeStart: (event: ReactPointerEvent<HTMLDivElement>) => void;
  logLines: LogLine[];
  logState: 'ready' | 'tracing' | 'done' | 'error';
  onClearLog: () => void;
  netRequest: { host: string; nonce: number } | null;
  onLog: (level: LogLevel, text: string) => void;
}

const BottomDock = ({
  open,
  height,
  tab,
  onTabChange,
  onToggle,
  onResizeStart,
  logLines,
  logState,
  onClearLog,
  netRequest,
  onLog,
}: BottomDockProps) => {
  const selectTab = (next: BottomTab) => {
    onTabChange(next);
    if (!open) {
      onToggle();
    }
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
        <div className="dock-tabs" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'console'}
            className={`dock-tab${tab === 'console' ? ' is-active' : ''}`}
            onClick={() => selectTab('console')}
          >
            CONSOLE
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'netcat'}
            className={`dock-tab${tab === 'netcat' ? ' is-active' : ''}`}
            onClick={() => selectTab('netcat')}
          >
            NETCAT
          </button>
        </div>

        {tab === 'console' ? (
          <>
            <span className="console-state" data-state={logState}>
              {logState}
            </span>
            <span className="console-count">{logLines.length} lines</span>
            <span className="console-spacer" />
            <button
              type="button"
              className="console-clear"
              onClick={onClearLog}
              disabled={logLines.length === 0}
            >
              CLEAR
            </button>
          </>
        ) : (
          <span className="console-spacer" />
        )}
      </header>

      {open && tab === 'console' && <ConsoleBody lines={logLines} />}

      <div className="netcat-mount" data-hidden={!open || tab !== 'netcat'}>
        <NetcatPanel request={netRequest} onLog={onLog} />
      </div>
    </section>
  );
};

export default BottomDock;
