interface StatusBarProps {
  state: 'ready' | 'tracing' | 'done' | 'error';
  message: string;
  targets: number;
  hops: number;
  located: number;
  elapsedMs: number;
}

function formatElapsed(ms: number): string {
  if (ms < 1000) {
    return `${ms} ms`;
  }
  const seconds = ms / 1000;
  if (seconds < 60) {
    return `${seconds.toFixed(1)} s`;
  }
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.floor(seconds % 60)}s`;
}

const LABELS: Record<StatusBarProps['state'], string> = {
  ready: 'READY',
  tracing: 'TRACING',
  done: 'COMPLETE',
  error: 'ERROR',
};

const StatusBar = ({ state, message, targets, hops, located, elapsedMs }: StatusBarProps) => (
  <footer className="statusbar">
    <div className="status-left">
      <span className="status-text" data-state={state}>
        {LABELS[state]}
      </span>
      {message && <span className="status-text selectable">{message}</span>}
    </div>
    <div className="status-right">
      <span className="stat">
        TARGETS <b>{targets}</b>
      </span>
      <span className="stat">
        HOPS <b>{hops}</b>
      </span>
      <span className="stat">
        GEO <b>{located}</b>
      </span>
      <span className="stat">
        TIME <b>{formatElapsed(elapsedMs)}</b>
      </span>
    </div>
  </footer>
);

export default StatusBar;
