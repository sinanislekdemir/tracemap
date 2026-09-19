import { useEffect, useMemo, useState } from 'react';
import { AnalyzeDomain, CancelDomainAnalysis, ExportDomainReport } from '../../wailsjs/go/main/App';
import { domaincheck } from '../../wailsjs/go/models';
import { EventsOn } from '../../wailsjs/runtime/runtime';
import type { CheckStatus, DomainProgressEvent, LogLevel } from '../types';

const EVENT_DOMAIN_PROGRESS = 'domain:progress';

type Phase = 'options' | 'running' | 'done';

const CATEGORY_ORDER = ['registration', 'dns', 'email', 'web'];
const CATEGORY_LABELS: Record<string, string> = {
  registration: 'REGISTRATION',
  dns: 'DNS',
  email: 'EMAIL AUTHENTICATION',
  web: 'WEB / TLS',
};

const STATUS_LABELS: Record<CheckStatus, string> = {
  pass: 'PASS',
  warn: 'WARN',
  fail: 'FAIL',
  info: 'INFO',
};

const formatMs = (ms?: number): string => {
  if (!ms) {
    return '—';
  }
  return new Date(ms).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
};

const join = (values?: string[]): string => (values && values.length > 0 ? values.join(', ') : '—');

interface DomainAnalysisModalProps {
  open: boolean;
  domain: string;
  onDomainChange: (value: string) => void;
  onClose: () => void;
  onLog: (level: LogLevel, text: string) => void;
}

const DomainAnalysisModal = ({
  open,
  domain,
  onDomainChange,
  onClose,
  onLog,
}: DomainAnalysisModalProps) => {
  const [phase, setPhase] = useState<Phase>('options');
  const [report, setReport] = useState<domaincheck.Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<DomainProgressEvent | null>(null);
  const [exportPath, setExportPath] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      return;
    }
    setPhase('options');
    setReport(null);
    setError(null);
    setProgress(null);
    setExportPath(null);
  }, [open]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const off = EventsOn(EVENT_DOMAIN_PROGRESS, (event: DomainProgressEvent) => {
      setProgress(event);
      onLog('info', `domain · ${event.phase} · ${event.message}`);
    });
    return () => off();
  }, [open, onLog]);

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
      void CancelDomainAnalysis();
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
    onLog('info', `▶ domain analysis ${trimmed}`);
    AnalyzeDomain(trimmed)
      .then((result) => {
        setReport(result);
        setPhase('done');
        onLog('ok', `domain analysis complete · score ${result.score}/100 (${result.grade})`);
      })
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
        setPhase('done');
        onLog('error', `domain analysis failed: ${message}`);
      });
  };

  const handleExport = () => {
    if (!report) {
      return;
    }
    ExportDomainReport(report)
      .then((path) => {
        if (path) {
          setExportPath(path);
          onLog('ok', `report saved to ${path}`);
        }
      })
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        onLog('error', `export failed: ${message}`);
      });
  };

  const grouped = useMemo(() => {
    const groups = new Map<string, domaincheck.Check[]>();
    for (const check of report?.checks ?? []) {
      const list = groups.get(check.category) ?? [];
      list.push(check);
      groups.set(check.category, list);
    }
    return CATEGORY_ORDER.filter((category) => groups.has(category)).map((category) => ({
      category,
      checks: groups.get(category) ?? [],
    }));
  }, [report]);

  if (!open) {
    return null;
  }

  const counts = report?.checks.reduce(
    (acc, check) => {
      const status = check.status as CheckStatus;
      acc[status] = (acc[status] ?? 0) + 1;
      return acc;
    },
    {} as Partial<Record<CheckStatus, number>>,
  );

  return (
    <div className="modal-backdrop" onClick={handleClose}>
      <div
        className="modal modal--scan modal--domain"
        role="dialog"
        aria-modal="true"
        aria-label="Domain analysis"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-head">
          <div>
            <div className="modal-title">DOMAIN ANALYSIS</div>
            <div className="modal-sub selectable">
              WHOIS / RDAP · DNS · email auth · TLS &amp; headers
            </div>
          </div>
          <button type="button" className="modal-close" onClick={handleClose} aria-label="Close">
            ×
          </button>
        </div>

        <div className="modal-body">
          <div className="scan-fields">
            <div className="field field--target">
              <label className="field-label" htmlFor="domain-analysis-target">
                DOMAIN
              </label>
              <div className="input-wrap">
                <span className="input-prompt">›</span>
                <input
                  id="domain-analysis-target"
                  className="input selectable"
                  type="text"
                  value={domain}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder="domain to analyze"
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
            <div className="modal-note">
              Collects registration data (RDAP via IANA, WHOIS fallback), DNS and email-authentication
              records, DNSSEC/CAA and the web/TLS configuration, then scores them on a checklist.
            </div>
          )}

          {phase === 'running' && (
            <div className="domain-progress">
              <div className="domain-progress-spinner" />
              <span>{progress ? `${progress.phase} · ${progress.message}` : 'starting…'}</span>
            </div>
          )}

          {error && <div className="port-error">{error}</div>}

          {report && (
            <>
              <div className="domain-score">
                <div className={`domain-grade domain-grade--${report.grade.toLowerCase()}`}>
                  {report.grade}
                </div>
                <div className="domain-score-meta">
                  <span className="domain-score-value selectable">{report.score}/100</span>
                  <span className="domain-score-domain selectable">{report.domain}</span>
                  <span className="domain-score-date">analyzed {formatMs(report.analyzedAt)}</span>
                </div>
                <div className="domain-tally">
                  <span className="check-chip check-chip--pass">{counts?.pass ?? 0} pass</span>
                  <span className="check-chip check-chip--warn">{counts?.warn ?? 0} warn</span>
                  <span className="check-chip check-chip--fail">{counts?.fail ?? 0} fail</span>
                </div>
              </div>

              {grouped.map((group) => (
                <div className="domain-group" key={group.category}>
                  <div className="domain-group-title">{CATEGORY_LABELS[group.category] ?? group.category}</div>
                  <div className="check-list">
                    {group.checks.map((check) => (
                      <div className="check-row" key={check.id}>
                        <span className={`check-chip check-chip--${check.status}`}>
                          {STATUS_LABELS[check.status as CheckStatus]}
                        </span>
                        <span className="check-main">
                          <span className="check-title">{check.title}</span>
                          <span className="check-detail selectable">{check.detail}</span>
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}

              {report.registration && (
                <div className="domain-group">
                  <div className="domain-group-title">REGISTRATION DETAILS</div>
                  <div className="domain-table">
                    <div className="domain-row">
                      <span>Source</span>
                      <span className="selectable">{report.registration.source || '—'}</span>
                    </div>
                    <div className="domain-row">
                      <span>Registrar</span>
                      <span className="selectable">{report.registration.registrar || '—'}</span>
                    </div>
                    <div className="domain-row">
                      <span>Created</span>
                      <span className="selectable">{formatMs(report.registration.createdAt)}</span>
                    </div>
                    <div className="domain-row">
                      <span>Updated</span>
                      <span className="selectable">{formatMs(report.registration.updatedAt)}</span>
                    </div>
                    <div className="domain-row">
                      <span>Expires</span>
                      <span className="selectable">{formatMs(report.registration.expiresAt)}</span>
                    </div>
                    <div className="domain-row">
                      <span>Registrant</span>
                      <span className="selectable">
                        {report.registration.registrant || '—'}
                        {report.registration.country ? ` (${report.registration.country})` : ''}
                      </span>
                    </div>
                    <div className="domain-row">
                      <span>Nameservers</span>
                      <span className="selectable">{join(report.registration.nameservers)}</span>
                    </div>
                    <div className="domain-row">
                      <span>Status</span>
                      <span className="selectable">{join(report.registration.statuses)}</span>
                    </div>
                  </div>
                </div>
              )}

              <div className="domain-group">
                <div className="domain-group-title">DNS &amp; EMAIL RECORDS</div>
                <div className="domain-table">
                  <div className="domain-row">
                    <span>Addresses</span>
                    <span className="selectable">{join(report.dns.addresses)}</span>
                  </div>
                  <div className="domain-row">
                    <span>Nameservers</span>
                    <span className="selectable">{join(report.dns.nameservers)}</span>
                  </div>
                  <div className="domain-row">
                    <span>MX</span>
                    <span className="selectable">{join(report.dns.mx)}</span>
                  </div>
                  <div className="domain-row">
                    <span>SPF</span>
                    <span className="selectable">
                      {join(report.dns.spf)}
                      {report.dns.spf?.length ? ` · policy ${report.dns.spfPolicy ?? 'none'} · ${report.dns.spfLookups} lookups` : ''}
                    </span>
                  </div>
                  <div className="domain-row">
                    <span>DMARC</span>
                    <span className="selectable">
                      {join(report.dns.dmarc)}
                      {report.dns.dmarc?.length ? ` · p=${report.dns.dmarcPolicy ?? 'none'}` : ''}
                    </span>
                  </div>
                  <div className="domain-row">
                    <span>DKIM</span>
                    <span className="selectable">{join(report.dns.dkim)}</span>
                  </div>
                  <div className="domain-row">
                    <span>CAA</span>
                    <span className="selectable">{join(report.dns.caa)}</span>
                  </div>
                  <div className="domain-row">
                    <span>MTA-STS</span>
                    <span className="selectable">{join(report.dns.mtaSts)}</span>
                  </div>
                  <div className="domain-row">
                    <span>TLS-RPT</span>
                    <span className="selectable">{join(report.dns.tlsRpt)}</span>
                  </div>
                </div>
              </div>

              <div className="domain-group">
                <div className="domain-group-title">WEB / TLS</div>
                <div className="domain-table">
                  <div className="domain-row">
                    <span>URL</span>
                    <span className="selectable">{report.web.url || '—'}</span>
                  </div>
                  <div className="domain-row">
                    <span>HTTPS</span>
                    <span className="selectable">
                      {report.web.https ? `yes (HTTP ${report.web.httpStatus ?? '?'})` : 'no'}
                      {report.web.redirectsHttps ? ' · redirects from HTTP' : ''}
                    </span>
                  </div>
                  <div className="domain-row">
                    <span>Certificate</span>
                    <span className="selectable">
                      {report.web.certSubject || '—'} · issuer {report.web.certIssuer || '—'} · expires{' '}
                      {formatMs(report.web.certNotAfter)}
                      {report.web.certNotAfter ? ` (${report.web.certDaysLeft}d)` : ''}
                    </span>
                  </div>
                  <div className="domain-row">
                    <span>TLS version</span>
                    <span className="selectable">{report.web.tlsVersion || '—'}</span>
                  </div>
                  {report.web.headers &&
                    Object.entries(report.web.headers).map(([name, value]) => (
                      <div className="domain-row" key={name}>
                        <span>{name}</span>
                        <span className="selectable">{value}</span>
                      </div>
                    ))}
                </div>
                {report.web.error && <div className="port-error">{report.web.error}</div>}
              </div>
            </>
          )}

          {exportPath && <div className="domain-export-path selectable">Saved to {exportPath}</div>}
        </div>

        <div className="modal-foot">
          {phase === 'running' ? (
            <button type="button" className="btn" onClick={() => void CancelDomainAnalysis()}>
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
                {report ? 'Re-analyze' : 'Analyze'}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default DomainAnalysisModal;
