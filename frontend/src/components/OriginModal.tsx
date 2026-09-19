import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  CancelUnmaskTarget,
  CreateUnmaskRules,
  ExportOriginReport,
  UnmaskRulesPath,
  UnmaskTarget,
} from '../../wailsjs/go/main/App';
import { origin } from '../../wailsjs/go/models';
import { EventsOn } from '../../wailsjs/runtime/runtime';
import ConsoleBody from './ConsoleBody';
import type {
  LogLevel,
  LogLine,
  OriginLogEvent,
  OriginMarker,
  OriginProgressEvent,
  UnmaskRulesInfo,
} from '../types';

const EVENT_ORIGIN_PROGRESS = 'origin:progress';
const EVENT_ORIGIN_LOG = 'origin:log';
const MAX_MODAL_LOG_LINES = 500;

type Phase = 'options' | 'running' | 'done';
type RulesMode = 'default' | 'custom';

const VERDICT_ORDER: Record<string, number> = { confirmed: 0, likely: 1, proxy: 2, dead: 3 };

const VERDICT_LABELS: Record<string, string> = {
  confirmed: 'CONFIRMED',
  likely: 'LIKELY',
  proxy: 'PROXY',
  dead: 'DEAD',
};

const join = (values?: string[]): string => (values && values.length > 0 ? values.join(', ') : '—');

const formatMs = (ms?: number): string => {
  if (!ms) {
    return '—';
  }
  return new Date(ms).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
};

const shortHash = (value?: string): string => (value ? value.slice(0, 16) : '—');

const markerLabel = (result: origin.Origin): string => {
  const city = result.geo?.city;
  const country = result.geo?.country;
  const place = [city, country].filter(Boolean).join(', ');
  return place ? `${result.ip} · ${place}` : result.ip;
};

const markersFor = (report: origin.Report): OriginMarker[] =>
  report.origins
    .filter((entry) => (entry.verdict === 'confirmed' || entry.verdict === 'likely') && entry.geo?.resolved)
    .map((entry) => ({
      ip: entry.ip,
      lat: entry.geo.lat,
      lon: entry.geo.lon,
      verdict: entry.verdict,
      label: markerLabel(entry),
    }));

interface OriginModalProps {
  open: boolean;
  domain: string;
  onDomainChange: (value: string) => void;
  onClose: () => void;
  onLog: (level: LogLevel, text: string) => void;
  onOrigins: (markers: OriginMarker[]) => void;
}

const OriginModal = ({ open, domain, onDomainChange, onClose, onLog, onOrigins }: OriginModalProps) => {
  const [phase, setPhase] = useState<Phase>('options');
  const [report, setReport] = useState<origin.Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<OriginProgressEvent | null>(null);
  const [exportPath, setExportPath] = useState<string | null>(null);
  const [rulesMode, setRulesMode] = useState<RulesMode>('default');
  const [rulesInfo, setRulesInfo] = useState<UnmaskRulesInfo | null>(null);
  const [rulesBusy, setRulesBusy] = useState(false);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const logIdRef = useRef(0);

  // pushLog mirrors a line into the modal's inline terminal and the shared
  // origin log channel.
  const pushLog = useCallback(
    (level: LogLevel, text: string) => {
      logIdRef.current += 1;
      const line: LogLine = { id: logIdRef.current, time: Date.now(), level, text, channel: 'origin' };
      setLogs((previous) => {
        const next = [...previous, line];
        return next.length > MAX_MODAL_LOG_LINES ? next.slice(next.length - MAX_MODAL_LOG_LINES) : next;
      });
      onLog(level, text);
    },
    [onLog],
  );

  useEffect(() => {
    if (!open) {
      return;
    }
    setPhase('options');
    setReport(null);
    setError(null);
    setProgress(null);
    setExportPath(null);
    setLogs([]);
    UnmaskRulesPath()
      .then((info) => setRulesInfo(info))
      .catch(() => setRulesInfo(null));
  }, [open]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const off = EventsOn(EVENT_ORIGIN_PROGRESS, (event: OriginProgressEvent) => {
      setProgress(event);
    });
    return () => off();
  }, [open]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const off = EventsOn(EVENT_ORIGIN_LOG, (event: OriginLogEvent) => {
      pushLog(event.level, event.message);
    });
    return () => off();
  }, [open, pushLog]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        handleClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  });

  const handleClose = () => {
    if (phase === 'running') {
      void CancelUnmaskTarget();
    }
    onClose();
  };

  const start = () => {
    const trimmed = domain.trim();
    if (!trimmed) {
      return;
    }
    setPhase('running');
    setReport(null);
    setError(null);
    setProgress(null);
    setExportPath(null);
    setLogs([]);
    pushLog('info', `▶ unmask target ${trimmed}`);
    UnmaskTarget(trimmed, rulesMode === 'custom')
      .then((result) => {
        setReport(result);
        setPhase('done');
        onOrigins(markersFor(result));
        const confirmed = result.origins.filter((entry) => entry.verdict === 'confirmed').length;
        pushLog('ok', `unmask complete · ${result.candidates.length} candidates · ${confirmed} confirmed origin(s)`);
      })
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
        setPhase('done');
        pushLog('error', `unmask failed: ${message}`);
      });
  };

  const handleExport = () => {
    if (!report) {
      return;
    }
    ExportOriginReport(report)
      .then((path) => {
        if (path) {
          setExportPath(path);
          pushLog('ok', `origin report saved to ${path}`);
        }
      })
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        pushLog('error', `export failed: ${message}`);
      });
  };

  const handleCreateRules = () => {
    setRulesBusy(true);
    CreateUnmaskRules()
      .then((path) => {
        if (path) {
          pushLog('ok', `unmask rules written to ${path}`);
        } else {
          pushLog('info', 'unmask rules creation cancelled');
        }
        return UnmaskRulesPath();
      })
      .then((info) => setRulesInfo(info))
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        pushLog('error', `could not write unmask rules: ${message}`);
      })
      .finally(() => setRulesBusy(false));
  };

  const sortedOrigins = useMemo(() => {
    const list = [...(report?.origins ?? [])];
    list.sort((a, b) => {
      const order = (VERDICT_ORDER[a.verdict] ?? 9) - (VERDICT_ORDER[b.verdict] ?? 9);
      return order !== 0 ? order : b.score - a.score;
    });
    return list;
  }, [report]);

  if (!open) {
    return null;
  }

  return (
    <div className="modal-backdrop" onClick={handleClose}>
      <div
        className="modal modal--scan modal--origin"
        role="dialog"
        aria-modal="true"
        aria-label="Unmask target"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-head">
          <div>
            <div className="modal-title">UNMASK TARGET</div>
            <div className="modal-sub selectable">origin discovery · DNS footprint + direct fingerprint</div>
          </div>
          <button type="button" className="modal-close" onClick={handleClose} aria-label="Close">
            ×
          </button>
        </div>

        <div className="modal-body">
          <div className="scan-fields">
            <div className="field field--target">
              <label className="field-label" htmlFor="origin-target">
                TARGET / DOMAIN
              </label>
              <div className="input-wrap">
                <span className="input-prompt">›</span>
                <input
                  id="origin-target"
                  className="input selectable"
                  type="text"
                  value={domain}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder="domain to unmask"
                  onChange={(event) => onDomainChange(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' && phase !== 'running') {
                      start();
                    }
                  }}
                />
              </div>
            </div>
          </div>

          {phase === 'options' && (
            <>
              <div className="modal-note">
                Mines the target's own DNS footprint (reusing the last scan's subdomains, plus MX, SPF and
                certificate SANs) and then connects directly to each candidate to compare its certificate,
                favicon and response body against the proxied baseline. No third-party services are used.
                <div className="origin-warning">
                  Direct probes send traffic to addresses the target's DNS already points to. Only run this
                  against targets you are authorised to test.
                </div>
              </div>

              <div className="domain-group">
                <div className="domain-group-title">INTERMEDIARY MARKER RULES</div>
                <div className="origin-rules">
                  <button
                    type="button"
                    className={`origin-rule-option${rulesMode === 'default' ? ' is-selected' : ''}`}
                    onClick={() => setRulesMode('default')}
                  >
                    <span className="origin-rule-title">Use default rules</span>
                    <span className="origin-rule-desc">built-in marker headers</span>
                  </button>
                  <button
                    type="button"
                    className={`origin-rule-option${rulesMode === 'custom' ? ' is-selected' : ''}`}
                    onClick={() => setRulesMode('custom')}
                  >
                    <span className="origin-rule-title">Load rules file</span>
                    <span className="origin-rule-desc selectable">
                      {rulesInfo?.path || 'no configuration directory'}
                      {rulesInfo && rulesInfo.path && !rulesInfo.exists
                        ? ' (missing — defaults will be used)'
                        : ''}
                    </span>
                  </button>
                </div>
                <div className="origin-rules-actions">
                  <button
                    type="button"
                    className="btn btn--ghost"
                    onClick={handleCreateRules}
                    disabled={rulesBusy}
                  >
                    {rulesBusy ? 'Writing…' : 'Create rules config'}
                  </button>
                  <span className="origin-rules-hint">
                    Copies the built-in markers to a JSON file you can edit.
                  </span>
                </div>
              </div>
            </>
          )}

          {phase === 'running' && (
            <div className="domain-progress">
              <div className="domain-progress-spinner" />
              <span>{progress ? `${progress.phase} · ${progress.message}` : 'starting…'}</span>
            </div>
          )}

          {logs.length > 0 && (
            <div className="domain-group">
              <div className="domain-group-title">LIVE LOG · {logs.length}</div>
              <div className="origin-log">
                <ConsoleBody lines={logs} />
              </div>
            </div>
          )}

          {error && <div className="port-error">{error}</div>}

          {report && (
            <>
              <div className="domain-group">
                <div className="domain-group-title">BASELINE (THROUGH PROXY)</div>
                <div className="domain-table">
                  <div className="domain-row">
                    <span>Proxied IPs</span>
                    <span className="selectable">
                      {join(report.baseline.proxiedIps)}
                      {report.baseline.proxied ? ' · intermediary detected' : ' · no intermediary detected'}
                    </span>
                  </div>
                  <div className="domain-row">
                    <span>Certificate</span>
                    <span className="selectable">
                      {shortHash(report.baseline.cert?.sha256)} · issuer {report.baseline.cert?.issuer || '—'} ·
                      expires {formatMs(report.baseline.cert?.notAfter)}
                    </span>
                  </div>
                  <div className="domain-row">
                    <span>Status</span>
                    <span className="selectable">{report.baseline.status || '—'}</span>
                  </div>
                </div>
              </div>

              <div className="domain-group">
                <div className="domain-group-title">
                  CANDIDATES · {report.candidates.length}
                </div>
                <div className="origin-list">
                  {sortedOrigins.map((entry) => (
                    <div className="origin-row" key={entry.ip}>
                      <span className={`origin-verdict origin-verdict--${entry.verdict}`}>
                        {VERDICT_LABELS[entry.verdict] ?? entry.verdict}
                      </span>
                      <span className="origin-main">
                        <span className="origin-ip selectable">{entry.ip}</span>
                        <span className="origin-evidence">
                          {entry.evidence.certMatch && <span className="origin-chip">cert</span>}
                          {entry.evidence.faviconMatch && <span className="origin-chip">favicon</span>}
                          {entry.evidence.bodyMatch && <span className="origin-chip">body</span>}
                          {entry.evidence.statusMatch && <span className="origin-chip">status</span>}
                          {entry.evidence.fanIn > 1 && (
                            <span className="origin-chip origin-chip--muted">×{entry.evidence.fanIn} names</span>
                          )}
                          {entry.evidence.proxyHeaders && entry.evidence.proxyHeaders.length > 0 && (
                            <span className="origin-chip origin-chip--bad">
                              proxy: {entry.evidence.proxyHeaders.join(', ')}
                            </span>
                          )}
                          {entry.evidence.sniVariance && (
                            <span className="origin-chip origin-chip--bad">shared edge</span>
                          )}
                        </span>
                        <span className="origin-meta selectable">
                          score {entry.score}
                          {entry.ports && entry.ports.length > 0 ? ` · ports ${entry.ports.join(', ')}` : ''}
                          {entry.cert?.issuer ? ` · issuer ${entry.cert.issuer}` : ''}
                          {entry.geo?.resolved
                            ? ` · ${[entry.geo.city, entry.geo.country].filter(Boolean).join(', ') || entry.ip}`
                            : ''}
                        </span>
                        {entry.note && <span className="origin-note-inline selectable">{entry.note}</span>}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {report.notes && report.notes.length > 0 && (
                <div className="domain-group">
                  <div className="domain-group-title">NOTES</div>
                  <div className="origin-notes">
                    {report.notes.map((note) => (
                      <div className="origin-note selectable" key={note}>
                        {note}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {exportPath && <div className="domain-export-path selectable">Saved to {exportPath}</div>}
        </div>

        <div className="modal-foot">
          {phase === 'running' ? (
            <button type="button" className="btn" onClick={() => void CancelUnmaskTarget()}>
              Stop
            </button>
          ) : (
            <>
              <button type="button" className="btn" onClick={handleClose}>
                Close
              </button>
              {report && (
                <button type="button" className="btn" onClick={handleExport}>
                  Export
                </button>
              )}
              <button
                type="button"
                className="btn btn--primary"
                disabled={domain.trim() === ''}
                onClick={start}
              >
                {report ? 'Re-run' : 'Unmask'}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default OriginModal;
