import { useRef, useState } from 'react';
import type { KeyboardEvent } from 'react';
import ContextMenu from './ContextMenu';

interface ToolbarProps {
  target: string;
  onTargetChange: (value: string) => void;
  maxHops: number;
  onMaxHopsChange: (value: number) => void;
  isLoading: boolean;
  onTrace: () => void;
  onScan: () => void;
  onDomainAnalysis: () => void;
  onUnmask: () => void;
  canUnmask: boolean;
  onPortScan: () => void;
  onNet: () => void;
  onConsole: () => void;
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
  onDomainAnalysis,
  onUnmask,
  canUnmask,
  onPortScan,
  onNet,
  onConsole,
  onCancel,
  onHistory,
  onAddToHistory,
  canAddToHistory,
}: ToolbarProps) => {
  const [toolsOpen, setToolsOpen] = useState(false);
  const [toolsPos, setToolsPos] = useState({ x: 0, y: 0 });
  const toolsRef = useRef<HTMLButtonElement>(null);

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter' && !isLoading) {
      onTrace();
    }
  };

  const openTools = () => {
    const rect = toolsRef.current?.getBoundingClientRect();
    if (rect) {
      setToolsPos({ x: rect.left, y: rect.bottom + 6 });
    }
    setToolsOpen(true);
  };

  const runTool = (action: () => void) => () => {
    setToolsOpen(false);
    action();
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
          max={100}
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
        ref={toolsRef}
        className={`btn btn--tools${toolsOpen ? ' is-open' : ''}`}
        onClick={() => (toolsOpen ? setToolsOpen(false) : openTools())}
        title="Additional tools: domain analysis, unmask target, port scan, netcat and console"
        aria-haspopup="menu"
        aria-expanded={toolsOpen}
      >
        Tools <span className="btn-caret">▾</span>
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

      {toolsOpen && (
        <ContextMenu
          x={toolsPos.x}
          y={toolsPos.y}
          title="TOOLS"
          items={[
            {
              label: 'Domain analysis',
              hint: 'WHOIS · DNS · TLS',
              onSelect: runTool(onDomainAnalysis),
            },
            {
              label: 'Unmask target',
              hint: canUnmask ? 'find origin IP' : 'scanning must complete to use this tool',
              disabled: !canUnmask,
              onSelect: runTool(onUnmask),
            },
            {
              label: 'Port scan',
              hint: 'open ports',
              onSelect: runTool(onPortScan),
            },
            {
              label: 'Netcat',
              hint: 'interactive TCP',
              onSelect: runTool(onNet),
            },
            {
              label: 'Console',
              hint: 'activity log',
              onSelect: runTool(onConsole),
            },
          ]}
          onClose={() => setToolsOpen(false)}
        />
      )}
    </div>
  );
};

export default Toolbar;
