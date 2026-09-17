import type { TraceState } from '../types';

interface TraceListProps {
  traces: TraceState[];
  selected: Set<number>;
  onToggle: (id: number) => void;
}

const TraceList = ({ traces, selected, onToggle }: TraceListProps) => (
  <>
    {traces.map((trace) => {
      const isSelected = selected.has(trace.id);
      const classes = ['trace-row'];
      if (isSelected) {
        classes.push('is-selected');
      }
      if (trace.error) {
        classes.push('is-error');
      }

      return (
        <div key={trace.id} className={classes.join(' ')}>
          <label className="trace-check">
            <input
              type="checkbox"
              checked={isSelected}
              onChange={() => onToggle(trace.id)}
            />
          </label>
          <button
            type="button"
            className="trace-body"
            onClick={() => onToggle(trace.id)}
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
        </div>
      );
    })}
  </>
);

export default TraceList;
