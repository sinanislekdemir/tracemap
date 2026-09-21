import { useEffect, useMemo, useState } from 'react';
import Modal from './Modal';
import type { HistorySummary } from '../types';

interface HistoryModalProps {
  open: boolean;
  entries: HistorySummary[];
  loading: boolean;
  disabled: boolean;
  onClose: () => void;
  onLoad: (ids: number[]) => void;
  onCorrelate: (ids: number[]) => void;
  onDelete: (id: number) => void;
  onClear: () => void;
}

function formatDate(ms: number): string {
  if (!ms) {
    return '—';
  }
  const date = new Date(ms);
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

const HistoryModal = ({
  open,
  entries,
  loading,
  disabled,
  onClose,
  onLoad,
  onCorrelate,
  onDelete,
  onClear,
}: HistoryModalProps) => {
  const [selected, setSelected] = useState<Set<number>>(new Set());

  useEffect(() => {
    if (open) {
      setSelected(new Set());
    }
  }, [open]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  const selectedIds = useMemo(() => [...selected], [selected]);
  const allSelected = entries.length > 0 && selected.size === entries.length;

  if (!open) {
    return null;
  }

  const toggle = (id: number) => {
    setSelected((previous) => {
      const next = new Set(previous);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const toggleAll = () => {
    setSelected(allSelected ? new Set() : new Set(entries.map((entry) => entry.id)));
  };

  return (
    <Modal
      title="HISTORY"
      subtitle={`${entries.length} saved ${entries.length === 1 ? 'entry' : 'entries'}`}
      ariaLabel="Trace history"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn--primary"
            disabled={selected.size === 0}
            onClick={() => onLoad(selectedIds)}
          >
            Show {selected.size > 0 ? `${selected.size} ` : ''}on map
          </button>
          <button
            type="button"
            className="btn"
            disabled={selected.size === 0}
            title="Aggregate the selected paths and draw each hop once"
            onClick={() => onCorrelate(selectedIds)}
          >
            Correlate
          </button>
        </>
      }
    >
      {disabled && <div className="modal-note">History storage is disabled.</div>}
      {!disabled && loading && <div className="modal-note">Loading…</div>}
      {!disabled && !loading && entries.length === 0 && (
        <div className="modal-note">
          No saved traces yet. Run a trace or scan, then choose “Add to history”.
        </div>
      )}

      {entries.length > 0 && (
        <>
          <div className="history-head">
            <button type="button" className="history-toggle" onClick={toggleAll}>
              {allSelected ? 'Clear selection' : 'Select all'}
            </button>
            <button type="button" className="history-toggle history-toggle--danger" onClick={onClear}>
              Clear all
            </button>
          </div>
          <ul className="history-list">
            {entries.map((entry) => (
              <li key={entry.id} className={`history-row${selected.has(entry.id) ? ' is-selected' : ''}`}>
                <label className="history-check">
                  <input
                    type="checkbox"
                    checked={selected.has(entry.id)}
                    onChange={() => toggle(entry.id)}
                  />
                </label>
                <button
                  type="button"
                  className="history-main"
                  onClick={() => toggle(entry.id)}
                >
                  <span className={`history-kind history-kind--${entry.kind}`}>{entry.kind}</span>
                  <span className="history-label selectable">{entry.label}</span>
                  <span className="history-meta">
                    {entry.traceCount} {entry.traceCount === 1 ? 'path' : 'paths'} · {entry.hopCount} hops
                  </span>
                  <span className="history-date">{formatDate(entry.createdAt)}</span>
                </button>
                <button
                  type="button"
                  className="history-delete"
                  title="Delete entry"
                  onClick={() => onDelete(entry.id)}
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </Modal>
  );
};

export default HistoryModal;
