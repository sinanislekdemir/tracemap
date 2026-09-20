import { useEffect, useMemo, useState } from 'react';
import Modal from './Modal';
import type { GeoCacheEntry, GeoCacheInfo } from '../types';

interface GeoCacheModalProps {
  open: boolean;
  entries: GeoCacheEntry[];
  info: GeoCacheInfo | null;
  loading: boolean;
  onClose: () => void;
  onRefresh: () => void;
  onDelete: (ip: string) => void;
  onClear: () => void;
}

function formatAge(ms: number): string {
  if (!ms) {
    return '—';
  }
  const seconds = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (seconds < 60) {
    return `${seconds}s ago`;
  }
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  const hours = Math.round(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }
  const days = Math.round(hours / 24);
  if (days < 30) {
    return `${days}d ago`;
  }
  return `${Math.round(days / 30)}mo ago`;
}

function formatCoords(lat: number, lon: number): string {
  if (lat === 0 && lon === 0) {
    return '—';
  }
  return `${lat.toFixed(3)}, ${lon.toFixed(3)}`;
}

const GeoCacheModal = ({
  open,
  entries,
  info,
  loading,
  onClose,
  onRefresh,
  onDelete,
  onClear,
}: GeoCacheModalProps) => {
  const [query, setQuery] = useState('');

  useEffect(() => {
    if (open) {
      setQuery('');
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

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) {
      return entries;
    }
    return entries.filter((entry) =>
      [entry.ip, entry.city, entry.country, entry.asn].some((value) =>
        value.toLowerCase().includes(needle),
      ),
    );
  }, [entries, query]);

  if (!open) {
    return null;
  }

  const disabled = info != null && !info.enabled;
  const expired = entries.filter((entry) => entry.expired).length;

  return (
    <Modal
      title="GEOIP CACHE"
      subtitle={
        disabled
          ? 'persistence disabled'
          : `${entries.length} cached ${entries.length === 1 ? 'IP' : 'IPs'}${
              expired > 0 ? ` · ${expired} expired` : ''
            }`
      }
      ariaLabel="GeoIP cache"
      variant="modal--geocache"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onRefresh} disabled={disabled || loading}>
            Refresh
          </button>
          <button type="button" className="btn btn--primary" onClick={onClose}>
            Close
          </button>
        </>
      }
    >
      {disabled && (
        <div className="modal-note">
          The GeoIP cache is disabled. Set <code>TRACEROUTE_DB</code> to a file path to enable it.
        </div>
      )}
      {!disabled && loading && <div className="modal-note">Loading…</div>}
      {!disabled && !loading && entries.length === 0 && (
        <div className="modal-note">No cached addresses yet. Run a trace to populate the cache.</div>
      )}

      {!disabled && entries.length > 0 && (
        <>
          <div className="geo-cache-toolbar">
            <input
              className="input selectable"
              type="text"
              value={query}
              spellCheck={false}
              autoComplete="off"
              placeholder="filter by IP, city, country or ASN"
              onChange={(event) => setQuery(event.target.value)}
            />
            <button
              type="button"
              className="history-toggle history-toggle--danger"
              onClick={onClear}
            >
              Clear all
            </button>
          </div>

          {info?.path && <div className="geo-cache-path selectable">{info.path}</div>}

          {filtered.length === 0 ? (
            <div className="modal-note">No cached addresses match “{query.trim()}”.</div>
          ) : (
            <ul className="geo-cache-list">
              {filtered.map((entry) => (
                <li key={entry.ip} className="geo-cache-row">
                  <div className="geo-cache-main">
                    <span className="geo-cache-ip selectable">{entry.ip}</span>
                    <span className="geo-cache-loc selectable">
                      {[entry.city, entry.country].filter(Boolean).join(', ') || 'unknown'}
                      {entry.expired && <span className="geo-cache-badge">expired</span>}
                    </span>
                    <span className="geo-cache-asn selectable" title={entry.asn}>
                      {entry.asn || '—'}
                    </span>
                    <span className="geo-cache-coords selectable">
                      {formatCoords(entry.lat, entry.lon)}
                    </span>
                    <span className="geo-cache-age">{formatAge(entry.fetchedAt)}</span>
                  </div>
                  <button
                    type="button"
                    className="history-delete"
                    title={`Delete ${entry.ip} from cache`}
                    onClick={() => onDelete(entry.ip)}
                  >
                    ×
                  </button>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Modal>
  );
};

export default GeoCacheModal;
