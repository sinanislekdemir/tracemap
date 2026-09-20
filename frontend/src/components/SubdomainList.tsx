import type { SubdomainResult } from '../types';

interface SubdomainListProps {
  subdomains: SubdomainResult[];
  selected: Set<string>;
  tracing: boolean;
  onToggle: (name: string) => void;
  onSelectAll: () => void;
  onClear: () => void;
  onTrace: () => void;
}

const SubdomainList = ({
  subdomains,
  selected,
  tracing,
  onToggle,
  onSelectAll,
  onClear,
  onTrace,
}: SubdomainListProps) => (
  <div className="sub-pane">
    <div className="sub-toolbar">
      <button type="button" className="history-toggle" onClick={onSelectAll}>
        Select all
      </button>
      <button type="button" className="history-toggle" onClick={onClear}>
        Clear
      </button>
      <button
        type="button"
        className="btn btn--primary btn--small"
        disabled={selected.size === 0 || tracing}
        onClick={onTrace}
      >
        {tracing ? 'Tracing' : `Trace ${selected.size || ''}`.trim()}
      </button>
    </div>
    <div className="sub-list">
      {subdomains.map((subdomain) => {
        const ips = Array.isArray(subdomain.ips) ? subdomain.ips : [];
        return (
        <button
          key={subdomain.name}
          type="button"
          className={`sub-row${selected.has(subdomain.name) ? ' is-selected' : ''}`}
          onClick={() => onToggle(subdomain.name)}
        >
          <span className="sub-check">{selected.has(subdomain.name) ? '✓' : ''}</span>
          <span className="sub-main">
            <span className="sub-name selectable">{subdomain.name}</span>
            <span className="sub-meta">
              {ips.length} {ips.length === 1 ? 'IP' : 'IPs'}
              {ips[0] ? ` · ${ips[0]}` : ''}
            </span>
          </span>
          <span className={`sub-source sub-source--${subdomain.source}`}>{subdomain.source}</span>
        </button>
        );
      })}
    </div>
  </div>
);

export default SubdomainList;
