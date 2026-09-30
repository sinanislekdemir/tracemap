import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AnalyzeEndpoints, CancelEndpointAnalysis, ExportHTTPReport } from '../../wailsjs/go/main/App';
import { main } from '../../wailsjs/go/models';
import type { httpcheck } from '../../wailsjs/go/models';
import { EventsOn } from '../../wailsjs/runtime/runtime';
import ConsoleBody from './ConsoleBody';
import Modal from './Modal';
import { useEscape } from '../useEscape';
import { joinList } from '../format';
import { EVENT_HTTP_LOG, EVENT_HTTP_PROGRESS, EVENT_HTTP_RESULT } from '../events';
import type {
  CheckStatus,
  HttpEndpointTarget,
  HttpLogEvent,
  HttpProgressEvent,
  HttpReport,
  LogLevel,
  LogLine,
} from '../types';

type Phase = 'options' | 'running' | 'done';

const MAX_MODAL_LOG_LINES = 2000;

const STATIC_ENDPOINTS: HttpEndpointTarget[] = [];
const CATEGORY_ORDER = ['headers', 'cookies', 'caching', 'tech', 'tls'];
const CATEGORY_LABELS: Record<string, string> = {
  headers: 'RESPONSE HEADERS',
  cookies: 'COOKIES',
  caching: 'CACHING',
  tech: 'TECHNOLOGY',
  tls: 'TLS',
};
const STATUS_LABELS: Record<CheckStatus, string> = {
  pass: 'PASS',
  warn: 'WARN',
  fail: 'FAIL',
  info: 'INFO',
};

const SOURCE_LABELS: Record<string, string> = {
  target: 'target',
  subdomain: 'subdomain',
  crawl: 'crawl',
  ports: 'ports',
  manual: 'manual',
};

// gradeStatus maps a score to a check-chip colour.
function gradeStatus(score: number): CheckStatus {
  if (score >= 90) return 'pass';
  if (score >= 70) return 'warn';
  return 'fail';
}

// normalizeEndpoint fills in a scheme so the input is a usable URL.
function normalizeEndpoint(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    return '';
  }
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

interface EndpointAnalysisModalProps {
  open: boolean;
  seed: HttpEndpointTarget[];
  onClose: () => void;
  onLog: (level: LogLevel, text: string) => void;
}

const EndpointAnalysisModal = ({ open, seed, onClose, onLog }: EndpointAnalysisModalProps) => {
  const [targets, setTargets] = useState<HttpEndpointTarget[]>(STATIC_ENDPOINTS);
  const [input, setInput] = useState('');
  const [phase, setPhase] = useState<Phase>('options');
  const [reports, setReports] = useState<HttpReport[]>([]);
  const [progress, setProgress] = useState<HttpProgressEvent | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [showActivity, setShowActivity] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exportPath, setExportPath] = useState<string | null>(null);
  const logIdRef = useRef(0);
  const seedRef = useRef(seed);
  seedRef.current = seed;

  const pushLog = useCallback(
    (level: LogLevel, text: string) => {
      logIdRef.current += 1;
      const line: LogLine = { id: logIdRef.current, time: Date.now(), level, text, channel: 'http' };
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
    const discovered = seedRef.current.filter((target) => target.url.trim() !== '');
    setTargets(discovered);
    setInput('');
    setPhase('options');
    setReports([]);
    setProgress(null);
    setSelected(null);
    setLogs([]);
    setShowActivity(false);
    setError(null);
    setExportPath(null);
  }, [open]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const offLog = EventsOn(EVENT_HTTP_LOG, (event: HttpLogEvent) => {
      const level: LogLevel =
        event.level === 'ok' || event.level === 'warn' || event.level === 'error' ? event.level : 'info';
      pushLog(level, `${event.label ? `${event.label} · ` : ''}${event.message}`);
    });
    const offProgress = EventsOn(EVENT_HTTP_PROGRESS, (event: HttpProgressEvent) => {
      setProgress(event);
    });
    const offResult = EventsOn(EVENT_HTTP_RESULT, (event: HttpReport) => {
      setReports((previous) => {
        if (previous.some((report) => report.url === event.url)) {
          return previous;
        }
        return [...previous, event];
      });
      setSelected((current) => current ?? event.url);
    });
    return () => {
      offLog();
      offProgress();
      offResult();
    };
  }, [open, pushLog]);

  const handleClose = () => {
    if (phase === 'running') {
      void CancelEndpointAnalysis();
    }
    onClose();
  };

  useEscape(open, handleClose);

  const addTarget = () => {
    const url = normalizeEndpoint(input);
    if (!url) {
      return;
    }
    setTargets((previous) => {
      if (previous.some((target) => target.url === url)) {
        return previous;
      }
      return [...previous, { url, source: 'manual' }];
    });
    setInput('');
  };

  const removeTarget = (url: string) => {
    setTargets((previous) => previous.filter((target) => target.url !== url));
  };

  const start = () => {
    if (targets.length === 0) {
      return;
    }
    setPhase('running');
    setReports([]);
    setProgress(null);
    setSelected(null);
    setError(null);
    setExportPath(null);
    pushLog('info', `▶ analyzing ${targets.length} endpoint(s)`);

    const request = main.EndpointAnalysisRequest.createFrom({
      targets: targets.map((target) => ({ url: target.url, label: target.label, source: target.source })),
    });
    AnalyzeEndpoints(request)
      .then((result) => {
        const list = (result ?? []) as unknown as HttpReport[];
        setReports(list);
        setSelected(list[0]?.url ?? null);
        setPhase('done');
        pushLog('ok', `analysis complete · ${list.length} endpoint(s)`);
      })
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
        setPhase('done');
        pushLog('error', `analysis failed: ${message}`);
      });
  };

  const handleExport = () => {
    if (reports.length === 0) {
      return;
    }
    ExportHTTPReport(reports as unknown as httpcheck.Report[])
      .then((path) => {
        if (path) {
          setExportPath(path);
          pushLog('ok', `report saved to ${path}`);
        }
      })
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        pushLog('error', `export failed: ${message}`);
      });
  };

  // The live result stream can arrive out of order; keep reports newest-first
  // and aligned with the editable target order.
  const ordered = useMemo(() => {
    const byUrl = new Map(reports.map((report) => [report.url, report]));
    const source = targets.map((target) => byUrl.get(target.url)).filter(Boolean) as HttpReport[];
    for (const report of reports) {
      if (!source.some((entry) => entry.url === report.url)) {
        source.push(report);
      }
    }
    return source;
  }, [reports, targets]);

  const current = ordered.find((report) => report.url === selected) ?? ordered[0] ?? null;

  const doneCount = ordered.filter((report) => !report.error).length;
  const avgScore =
    doneCount > 0 ? Math.round(ordered.reduce((sum, report) => sum + report.score, 0) / doneCount) : 0;

  if (!open) {
    return null;
  }

  return (
    <Modal
      title="HTTP ENDPOINT ANALYSIS"
      subtitle={<>response headers · cookies · caching · technology</>}
      ariaLabel="HTTP endpoint analysis"
      variant="modal--http"
      onClose={handleClose}
      footer={
        <>
          {phase === 'running' ? (
            <button type="button" className="btn" onClick={() => void CancelEndpointAnalysis()}>
              Stop
            </button>
          ) : (
            <>
              <button type="button" className="btn" onClick={handleClose}>
                Close
              </button>
              {ordered.length > 0 && (
                <button type="button" className="btn" onClick={handleExport}>
                  Export
                </button>
              )}
              <button
                type="button"
                className="btn"
                onClick={() => setShowActivity((value) => !value)}
                disabled={logs.length === 0}
              >
                {showActivity ? 'Hide activity' : 'Activity'}
              </button>
              <button
                type="button"
                className="btn btn--primary"
                disabled={targets.length === 0}
                onClick={start}
              >
                {ordered.length > 0 ? 'Re-analyze' : 'Analyze'}
              </button>
            </>
          )}
        </>
      }
    >
      <div className="http-targets">
        <div className="http-add">
          <input
            className="input selectable"
            type="text"
            value={input}
            spellCheck={false}
            autoComplete="off"
            placeholder="https://host:port/path"
            onChange={(event) => setInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                addTarget();
              }
            }}
          />
          <button type="button" className="btn" onClick={addTarget} disabled={!input.trim()}>
            Add
          </button>
        </div>

        {targets.length === 0 ? (
          <div className="modal-note">
            No endpoints discovered yet. Run a scan to collect subdomains, or a port scan, or add an endpoint above.
          </div>
        ) : (
          <div className="http-target-list">
            {targets.map((target) => (
              <span className="http-target-chip" key={target.url}>
                <span className="http-target-url selectable">{target.url}</span>
                {target.source && (
                  <span className="http-target-source">{SOURCE_LABELS[target.source] ?? target.source}</span>
                )}
                <button
                  type="button"
                  className="http-target-remove"
                  onClick={() => removeTarget(target.url)}
                  disabled={phase === 'running'}
                  aria-label={`Remove ${target.url}`}
                >
                  ×
                </button>
              </span>
            ))}
          </div>
        )}
      </div>

      {phase === 'running' && (
        <div className="domain-progress">
          <div className="domain-progress-spinner" />
          <span>
            {progress ? `analyzing ${progress.done}/${progress.total} · ${progress.url}` : 'starting…'}
          </span>
        </div>
      )}

      {error && <div className="port-error">{error}</div>}

      {(showActivity || phase === 'running') && logs.length > 0 && (
        <div className="http-activity">
          <ConsoleBody lines={logs} />
        </div>
      )}

      {ordered.length > 0 && (
        <>
          <div className="domain-score">
            <div className={`domain-grade domain-grade--${(current?.grade ?? 'F').toLowerCase()}`}>
              {current?.grade ?? 'F'}
            </div>
            <div className="domain-score-meta">
              <span className="domain-score-value selectable">{avgScore}/100 avg</span>
              <span className="domain-score-domain selectable">
                {doneCount} analyzed · {ordered.length} endpoint(s)
              </span>
            </div>
          </div>

          <div className="http-results">
            {ordered.map((report) => (
              <button
                type="button"
                key={report.url}
                className={`http-result-row${report.url === current?.url ? ' is-active' : ''}`}
                onClick={() => setSelected(report.url)}
              >
                <span className={`check-chip check-chip--${report.error ? 'fail' : gradeStatus(report.score)}`}>
                  {report.error ? 'ERR' : `${report.score}`}
                </span>
                <span className="http-result-url selectable">{report.url}</span>
                <span className="http-result-meta">
                  {report.error
                    ? report.error
                    : `${report.status} · ${report.tech?.length ?? 0} tech · ${report.cookies?.length ?? 0} cookies`}
                </span>
              </button>
            ))}
          </div>

          {current && !current.error && <ReportDetail report={current} />}
        </>
      )}

      {exportPath && <div className="domain-export-path selectable">Saved to {exportPath}</div>}
    </Modal>
  );
};

// ReportDetail renders one endpoint's findings.
const ReportDetail = ({ report }: { report: HttpReport }) => {
  const grouped = useMemo(() => {
    const groups = new Map<string, HttpReport['checks']>();
    for (const check of report.checks ?? []) {
      const list = groups.get(check.category) ?? [];
      list.push(check);
      groups.set(check.category, list);
    }
    return CATEGORY_ORDER.filter((category) => groups.has(category)).map((category) => ({
      category,
      checks: groups.get(category) ?? [],
    }));
  }, [report]);

  return (
    <Fragment>
      <div className="domain-group">
        <div className="domain-group-title">SUMMARY</div>
        <div className="domain-table">
          <div className="domain-row">
            <span>Final URL</span>
            <span className="selectable">{report.finalUrl || report.url}</span>
          </div>
          <div className="domain-row">
            <span>Status</span>
            <span className="selectable">
              HTTP {report.status} · {report.https ? 'HTTPS' : 'HTTP'}
            </span>
          </div>
          {report.server && (
            <div className="domain-row">
              <span>Server</span>
              <span className="selectable">{report.server}</span>
            </div>
          )}
          {report.contentType && (
            <div className="domain-row">
              <span>Content-Type</span>
              <span className="selectable">{report.contentType}</span>
            </div>
          )}
          <div className="domain-row">
            <span>Score</span>
            <span className="selectable">
              {report.score}/100 (grade {report.grade})
            </span>
          </div>
          {report.redirects && report.redirects.length > 0 && (
            <div className="domain-row">
              <span>Redirects</span>
              <span className="selectable">
                {report.redirects.map((hop) => `${hop.status} ${hop.to}`).join(' → ')}
              </span>
            </div>
          )}
        </div>
      </div>

      {grouped.map((group) => (
        <div className="domain-group" key={group.category}>
          <div className="domain-group-title">{CATEGORY_LABELS[group.category] ?? group.category}</div>
          <div className="check-list">
            {group.checks.map((check) => (
              <div className="check-row" key={check.id}>
                <span className={`check-chip check-chip--${check.status}`}>{STATUS_LABELS[check.status]}</span>
                <span className="check-main">
                  <span className="check-title">{check.title}</span>
                  <span className="check-detail selectable">{check.detail}</span>
                </span>
              </div>
            ))}
          </div>
        </div>
      ))}

      {report.cookies && report.cookies.length > 0 && (
        <div className="domain-group">
          <div className="domain-group-title">COOKIE DETAIL</div>
          <div className="http-cookie-table">
            {report.cookies.map((cookie) => (
              <div className="http-cookie-row" key={cookie.name}>
                <span className="http-cookie-name selectable">{cookie.name}</span>
                <span className="http-cookie-flags">
                  {cookie.secure ? 'Secure' : '—'} · {cookie.httpOnly ? 'HttpOnly' : '—'} ·{' '}
                  {cookie.sameSite || '—'}
                  {cookie.session ? ' · session' : ''}
                  {cookie.tech ? ` · ${cookie.tech}` : ''}
                </span>
                {cookie.flags && cookie.flags.length > 0 && (
                  <span className="http-cookie-issues">{cookie.flags.join(', ')}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="domain-group">
        <div className="domain-group-title">CACHING DETAIL</div>
        <div className="domain-table">
          <div className="domain-row">
            <span>Cache-Control</span>
            <span className="selectable">{report.caching.cacheControl || '—'}</span>
          </div>
          <div className="domain-row">
            <span>Cacheable</span>
            <span className="selectable">
              {report.caching.cacheable ? 'yes' : 'no'} · {report.caching.shared ? 'shared' : 'private'}
            </span>
          </div>
          {report.caching.cdn && (
            <div className="domain-row">
              <span>CDN</span>
              <span className="selectable">{report.caching.cdn}</span>
            </div>
          )}
          {report.caching.age > 0 && (
            <div className="domain-row">
              <span>Age</span>
              <span className="selectable">{report.caching.age}s</span>
            </div>
          )}
          {report.caching.vary && report.caching.vary.length > 0 && (
            <div className="domain-row">
              <span>Vary</span>
              <span className="selectable">{joinList(report.caching.vary)}</span>
            </div>
          )}
        </div>
      </div>

      {report.tls && (
        <div className="domain-group">
          <div className="domain-group-title">TLS DETAIL</div>
          <div className="domain-table">
            <div className="domain-row">
              <span>Version</span>
              <span className="selectable">
                {report.tls.version || '—'} · {report.tls.alpn || 'no ALPN'}
              </span>
            </div>
            <div className="domain-row">
              <span>Issuer</span>
              <span className="selectable">{report.tls.issuer || '—'}</span>
            </div>
            <div className="domain-row">
              <span>Subject</span>
              <span className="selectable">{report.tls.subject || '—'}</span>
            </div>
            <div className="domain-row">
              <span>Expires</span>
              <span className="selectable">{report.tls.daysLeft} day(s)</span>
            </div>
          </div>
        </div>
      )}

      {report.headers && report.headers.length > 0 && (
        <div className="domain-group">
          <div className="domain-group-title">ALL RESPONSE HEADERS</div>
          <div className="domain-table">
            {report.headers.map((header) => (
              <div className="domain-row" key={header.name}>
                <span>
                  {header.name}
                  {header.kind !== 'other' ? ` (${header.kind})` : ''}
                </span>
                <span className="selectable">{header.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Fragment>
  );
};

export default EndpointAnalysisModal;
