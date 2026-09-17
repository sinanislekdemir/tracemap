import type { KeyboardEvent } from 'react';

interface ToolbarProps {
  target: string;
  onTargetChange: (value: string) => void;
  maxHops: number;
  onMaxHopsChange: (value: number) => void;
  isLoading: boolean;
  onTrace: () => void;
  onScan: () => void;
  onPortScan: () => void;
  onNet: () => void;
  onCancel: () => void;
  onHistory: () => void;
  onAddToHistory: () => void;
  canAddToHistory: boolean;
}

const Toolbar = ({
  target,
  onTargetChange,
  maxHops,
  onMaxHopsChange,
  isLoading,
  onTrace,
  onScan,
  onPortScan,
  onNet,
  onCancel,
  onHistory,
  onAddToHistory,
  canAddToHistory,
}: ToolbarProps) => {
  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter' && !isLoading) {
      onTrace();
    }
  };

  return (
    <div className="toolbar">
      <div className="field field--target">
        <label className="field-label" htmlFor="target">
          TARGET / DOMAIN
        </label>
        <div className="input-wrap">
          <span className="input-prompt">›</span>
          <input
            id="target"
            className="input selectable"
            type="text"
            value={target}
            spellCheck={false}
            autoComplete="off"
            placeholder="hostname or IP address"
            onChange={(event) => onTargetChange(event.target.value)}
            onKeyDown={onKeyDown}
          />
        </div>
      </div>

      <div className="field">
        <label className="field-label" htmlFor="max-hops">
          MAX HOPS
        </label>
        <input
          id="max-hops"
          className="input input--num selectable"
          type="number"
          min={1}
          max={64}
          value={maxHops}
          onChange={(event) => onMaxHopsChange(Number(event.target.value) || 30)}
        />
      </div>

      <button className="btn btn--primary" onClick={onTrace} disabled={isLoading}>
        {isLoading ? 'Tracing' : 'Trace'}
      </button>

      <button className="btn btn--scan" onClick={onScan} disabled={isLoading} title="Resolve all DNS records and trace each address">
        Scan
      </button>

      <button
        className="btn"
        onClick={onPortScan}
        disabled={isLoading}
        title="Scan the target for open ports (TCP/UDP). You can also right-click a hop or marker."
      >
        Ports
      </button>

      <button
        className="btn"
        onClick={onNet}
        title="Open an interactive TCP session to the target (netcat). You can also right-click a hop or marker."
      >
        Net
      </button>

      <button className="btn" onClick={onCancel} disabled={!isLoading}>
        Cancel
      </button>

      <button
        className="btn btn--ghost"
        onClick={onAddToHistory}
        disabled={!canAddToHistory}
        title="Save the current traces to history"
      >
        + History
      </button>

      <button className="btn" onClick={onHistory} title="Browse saved traces and compare them on the map">
        History
      </button>
    </div>
  );
};

export default Toolbar;
