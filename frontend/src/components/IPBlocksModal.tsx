import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ExportCountryBlocks,
  IPBlocksInfo as fetchIPBlocksInfo,
  ListCountryBlocks,
  QueryCountryBlocks,
  ReleaseCountryBlocks,
} from '../../wailsjs/go/main/App';
import { main } from '../../wailsjs/go/models';
import { EventsOn } from '../../wailsjs/runtime/runtime';
import Modal from './Modal';
import { useEscape } from '../useEscape';
import { EVENT_IPBLOCKS_PROGRESS } from '../events';
import type {
  CountryBlockSummary,
  CountryBlocksResult,
  IPBlocksInfo,
  IPBlocksProgressEvent,
} from '../types';

/** How many block lines the modal renders at once; exports are never paged. */
const PAGE_SIZE = 2000;

const FILTER_DEBOUNCE_MS = 250;

type Family = '' | 'ipv4' | 'ipv6';

interface IPBlocksModalProps {
  open: boolean;
  onClose: () => void;
}

const IPBlocksModal = ({ open, onClose }: IPBlocksModalProps) => {
  const [info, setInfo] = useState<IPBlocksInfo | null>(null);
  const [countries, setCountries] = useState<CountryBlockSummary[]>([]);
  const [loadingCountries, setLoadingCountries] = useState(false);
  const [countryQuery, setCountryQuery] = useState('');

  const [selected, setSelected] = useState<CountryBlockSummary | null>(null);
  const [family, setFamily] = useState<Family>('');
  const [filter, setFilter] = useState('');
  const [result, setResult] = useState<CountryBlocksResult | null>(null);
  const [loadingBlocks, setLoadingBlocks] = useState(false);

  const [progress, setProgress] = useState<IPBlocksProgressEvent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const requestRef = useRef(0);

  // loadCountries reads the database summary once per modal opening. The full
  // walk takes a few seconds and streams progress events.
  const loadCountries = useCallback(() => {
    setLoadingCountries(true);
    setError(null);
    setProgress(null);
    Promise.all([fetchIPBlocksInfo(), ListCountryBlocks()])
      .then(([nextInfo, list]) => {
        setInfo(nextInfo);
        setCountries(list as CountryBlockSummary[]);
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => {
        setLoadingCountries(false);
        setProgress(null);
      });
  }, []);

  useEffect(() => {
    if (!open) {
      return;
    }
    setCountryQuery('');
    setSelected(null);
    setFamily('');
    setFilter('');
    setResult(null);
    setError(null);
    setNotice(null);
    loadCountries();
  }, [open, loadCountries]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const off = EventsOn(EVENT_IPBLOCKS_PROGRESS, (event: IPBlocksProgressEvent) => {
      setProgress(event);
    });
    return () => off();
  }, [open]);

  // loadBlocks requests one page for the selected country. Every request gets a
  // sequence number so a slow response cannot overwrite a newer one.
  const loadBlocks = useCallback((country: string, nextFamily: Family, nextFilter: string) => {
    const id = ++requestRef.current;
    setLoadingBlocks(true);
    setError(null);
    setNotice(null);
    QueryCountryBlocks(
      main.CountryBlocksRequest.createFrom({
        country,
        family: nextFamily,
        filter: nextFilter,
        limit: PAGE_SIZE,
      }),
    )
      .then((page) => {
        if (id !== requestRef.current) {
          return;
        }
        setResult(page as CountryBlocksResult);
      })
      .catch((err: unknown) => {
        if (id !== requestRef.current) {
          return;
        }
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (id === requestRef.current) {
          setLoadingBlocks(false);
        }
      });
  }, []);

  const selectCountry = (country: CountryBlockSummary) => {
    setSelected(country);
    setFamily('');
    setFilter('');
    setResult(null);
  };

  // Re-query on selection and whenever the family changes; debounce the text
  // filter so typing does not fire a request per keystroke.
  useEffect(() => {
    if (!selected) {
      return;
    }
    const timer = window.setTimeout(() => loadBlocks(selected.code, family, filter), FILTER_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [selected, family, filter, loadBlocks]);

  const handleClose = () => {
    requestRef.current += 1;
    void ReleaseCountryBlocks();
    onClose();
  };

  useEscape(open, handleClose);

  const filteredCountries = useMemo(() => {
    const needle = countryQuery.trim().toLowerCase();
    if (!needle) {
      return countries;
    }
    return countries.filter((country) =>
      [country.code, country.name].some((value) => (value ?? '').toLowerCase().includes(needle)),
    );
  }, [countries, countryQuery]);

  if (!open) {
    return null;
  }

  const unavailable = info != null && !info.available;
  const percent = progress && progress.total > 0 ? (progress.done / progress.total) * 100 : 0;

  const handleExport = () => {
    if (!selected || loadingBlocks) {
      return;
    }
    ExportCountryBlocks(
      main.CountryBlocksRequest.createFrom({ country: selected.code, family, filter, limit: 0 }),
    )
      .then((path) => {
        if (path) {
          setNotice(`Report saved to ${path}`);
        }
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)));
  };

  return (
    <Modal
      title="COUNTRY IP BLOCKS"
      subtitle={
        selected
          ? `${selected.code || '??'} · ${selected.name || 'Unknown'}`
          : info?.path
            ? `${info.database ?? 'GeoLite2'} · built ${info.build ?? 'unknown'}`
            : 'local GeoIP database'
      }
      ariaLabel="Country IP blocks"
      variant="modal--ipblocks"
      onClose={handleClose}
      footer={
        <>
          {selected && (
            <button type="button" className="btn" onClick={handleExport} disabled={loadingBlocks}>
              Export blocks
            </button>
          )}
          <button type="button" className="btn btn--primary" onClick={handleClose}>
            Close
          </button>
        </>
      }
    >
      {unavailable && (
        <div className="modal-note">
          {info?.message || 'No local GeoLite2 Country or City database was found.'}
          <br />
          Install one (for example <code>geolite2-country</code>) or point{' '}
          <code>TRACEROUTE_GEOIP_DIR</code> at a directory containing it.
        </div>
      )}

      {!unavailable && error && <div className="ipb-error">{error}</div>}

      {!unavailable && !selected && (
        <>
          {loadingCountries ? (
            <div className="ipb-loading">
              <div className="modal-note">Walking the local GeoIP database…</div>
              {progress && (
                <>
                  <div className="ipb-progress-bar">
                    <i style={{ width: `${percent}%` }} />
                  </div>
                  <div className="ipb-progress-text">
                    {progress.done.toLocaleString()} / {progress.total.toLocaleString()} nodes
                  </div>
                </>
              )}
            </div>
          ) : (
            <>
              <div className="ipb-toolbar">
                <input
                  className="input selectable"
                  type="text"
                  value={countryQuery}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder="filter countries by code or name"
                  onChange={(event) => setCountryQuery(event.target.value)}
                />
                <span className="ipb-count">
                  {countries.length} {countries.length === 1 ? 'country' : 'countries'}
                </span>
              </div>

              {filteredCountries.length === 0 ? (
                <div className="modal-note">No countries match “{countryQuery.trim()}”.</div>
              ) : (
                <ul className="ipb-country-list">
                  {filteredCountries.map((country) => (
                    <li key={country.code || 'unknown'}>
                      <button
                        type="button"
                        className="ipb-country-row"
                        onClick={() => selectCountry(country)}
                      >
                        <span className="ipb-code">{country.code || '??'}</span>
                        <span className="ipb-name">{country.name || 'Unknown'}</span>
                        <span className="ipb-blocks">{country.blocks.toLocaleString()} blocks</span>
                        <span className="ipb-addrs">{country.addresses} addrs</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </>
      )}

      {!unavailable && selected && (
        <>
          <div className="ipb-blocks-head">
            <button
              type="button"
              className="btn btn--ghost ipb-back"
              onClick={() => {
                requestRef.current += 1;
                setSelected(null);
                setResult(null);
                setNotice(null);
              }}
            >
              ← All countries
            </button>
            <span className="ipb-selected-name selectable">
              {selected.code || '??'} · {selected.name || 'Unknown'}
            </span>
          </div>

          <div className="ipb-toolbar">
            <div className="port-toggle ipb-family">
              {(['', 'ipv4', 'ipv6'] as Family[]).map((value) => (
                <button
                  key={value || 'all'}
                  type="button"
                  className={`port-toggle-btn${family === value ? ' is-active' : ''}`}
                  onClick={() => setFamily(value)}
                >
                  {value === '' ? 'All' : value === 'ipv4' ? 'IPv4' : 'IPv6'}
                </button>
              ))}
            </div>
            <input
              className="input selectable"
              type="text"
              value={filter}
              spellCheck={false}
              autoComplete="off"
              placeholder="filter blocks (e.g. 1.2 or :/32)"
              onChange={(event) => setFilter(event.target.value)}
            />
          </div>

          {result && (
            <div className="ipb-summary">
              <b>{result.matched.toLocaleString()}</b> {result.matched === 1 ? 'block' : 'blocks'}
              {result.addresses ? ` · ${result.addresses} addresses` : ''}
              {result.truncated ? ` · showing first ${result.blocks.length.toLocaleString()}` : ''}
            </div>
          )}

          {!result && <div className="modal-note">Loading blocks…</div>}

          {result && result.blocks.length === 0 && !loadingBlocks && (
            <div className="modal-note">No blocks match this filter.</div>
          )}

          {result && result.blocks.length > 0 && (
            <div className="ipb-list">
              {result.blocks.map((block) => (
                <div className="ipb-line selectable" key={block}>
                  {block}
                </div>
              ))}
            </div>
          )}

          {notice && <div className="ipb-notice">{notice}</div>}
        </>
      )}
    </Modal>
  );
};

export default IPBlocksModal;
