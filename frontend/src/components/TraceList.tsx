import type { TraceState } from '../types';

interface TraceListProps {
  traces: TraceState[];
  selected: number | null;
  onSelect: (id: number) => void;
}

const TraceList = ({ traces, selected, onSelect }: TraceListProps) => (
  <>
    {traces.map((trace) => {
      const classes = ['trace-row'];
      if (trace.id === selected) {
        classes.push('is-selected');
      }
      if (trace.error) {
        classes.push('is-error');
      }

      return (
        <button
          key={trace.id}
          type="button"
          className={classes.join(' ')}
          onClick={() => onSelect(trace.id)}
        >
          <span className="trace-swatch" style={{ background: trace.color }} />
          <span className="trace-main">
            <span className="trace-label">{trace.label}</span>
            <span className="trace-ip selectable">{trace.ip || '—'}</span>
          </span>
          <span className="trace-meta">
            {trace.kind && <span className="trace-kind">{trace.kind}</span>}
            <span className="trace-count">{trace.hops.length}</span>
          </span>
        </button>
      );
    })}
  </>
);

export default TraceList;
