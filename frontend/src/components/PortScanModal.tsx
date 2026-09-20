import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CancelPortScan, ExportPortScanReport, ScanPorts } from '../../wailsjs/go/main/App';
import { main } from '../../wailsjs/go/models';
import { EventsOn } from '../../wailsjs/runtime/runtime';
import ConsoleBody from './ConsoleBody';
import Modal from './Modal';
import { useEscape } from '../useEscape';
import {
  EVENT_PORT_DONE,
  EVENT_PORT_ERROR,
  EVENT_PORT_OPEN,
  EVENT_PORT_PROGRESS,
} from '../events';
import type {
  LogLevel,
  LogLine,
  PortOpenEvent,
  PortScanDone,
  PortScanOptions,
  PortScanProgress,
  PortScanTarget,
} from '../types';

type Phase = 'options' | 'scanning' | 'done';
type SortKey = 'port' | 'service';

const MAX_MODAL_LOG_LINES = 2000;

const PRESETS: { id: PortScanOptions['preset']; label: string; hint: string }[] = [
  { id: 'top20', label: 'Top 20', hint: 'Most commonly open ports' },
  { id: 'top100', label: 'Top 100', hint: 'Popular services' },
  { id: 'top1000', label: 'Top 1000', hint: 'Well-known 1–1024 plus common high ports' },
];

const DEFAULT_OPTIONS: PortScanOptions = {
  protocol: 'tcp',
  preset: 'top100',
  portRange: '1-1024',
  concurrency: 64,
  timeoutMs: 500,
  probe: true,
  scope: 'single',
};

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

// validateRange mirrors the backend grammar: comma-separated ports and ranges.
function validateRange(spec: string): string | null {
  const trimmed = spec.trim();
  if (!trimmed) {
    return 'Enter a port or range, e.g. 22,80,443 or 1-1024';
  }
  for (const part of trimmed.split(',')) {
    const entry = part.trim();
    if (!entry) {
      continue;
    }
    const match = /^(\d+)(?:-(\d+))?$/.exec(entry);
    if (!match) {
      return `Invalid entry "${entry}"`;
    }
    const from = Number(match[1]);
    const to = match[2] != null ? Number(match[2]) : from;
    if (from < 1 || from > 65535 || to < 1 || to > 65535) {
      return `Port out of range in "${entry}"`;
    }
    if (from > to) {
      return `Reversed range "${entry}"`;
    }
  }
  return null;
}

// countPorts estimates how many distinct ports a spec selects.
function countPorts(spec: string): number {
  const seen = new Set<number>();
  for (const part of spec.split(',')) {
    const entry = part.trim();
    if (!entry) {
      continue;
    }
    const match = /^(\d+)(?:-(\d+))?$/.exec(entry);
    if (!match) {
      continue;
    }
    const from = Number(match[1]);
    const to = match[2] != null ? Number(match[2]) : from;
    if (from < 1 || to > 65535 || from > to) {
      continue;
    }
    for (let port = from; port <= to && seen.size < 65535; port += 1) {
      seen.add(port);
    }
  }
  return seen.size;
}

// describePort renders one open port as a terminal line.
function describePort(entry: PortOpenEvent, showHost: boolean): string {
  const result = entry.result;
  const parts = [`${result.port}/${result.protocol}`, 'open'];
  const name = result.product || result.service;
  if (name) {
    parts.push(name);
  }
  if (result.tls) {
    parts.push('TLS');
  }
  const extra = result.detail || result.banner;
  if (extra) {
    parts.push(extra);
  }
  const prefix = showHost ? `${entry.label || entry.host} · ` : '';
  return `${prefix}${parts.join(' · ')}`;
}

interface PortScanModalProps {
  open: boolean;
  host: string;
  label?: string;
  /** Resolved scan targets available for the "all targets" scope. */
  targets: PortScanTarget[];
  onClose: () => void;
  onLog: (level: LogLevel, text: string) => void;
}

const PortScanModal = ({ open, host, label, targets, onClose, onLog }: PortScanModalProps) => {
  const [options, setOptions] = useState<PortScanOptions>(DEFAULT_OPTIONS);
  const [phase, setPhase] = useState<Phase>('options');
  const [results, setResults] = useState<PortOpenEvent[]>([]);
  const [progress, setProgress] = useState<PortScanProgress | null>(null);
  const [done, setDone] = useState<PortScanDone | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [filter, setFilter] = useState('');
  const [sort, setSort] = useState<SortKey>('port');
  const [showActivity, setShowActivity] = useState(false);
  const logIdRef = useRef(0);
  const startedAtRef = useRef(0);
  const durationRef = useRef(0);

  // pushLog mirrors a line into the modal's inline terminal and the shared
  // ports log channel.
  const pushLog = useCallback(
    (level: LogLevel, text: string) => {
      logIdRef.current += 1;
      const line: LogLine = { id: logIdRef.current, time: Date.now(), level, text, channel: 'ports' };
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
    setResults([]);
    setProgress(null);
    setDone(null);
    setError(null);
    setLogs([]);
    setFilter('');
    setSort('port');
    setShowActivity(false);
    startedAtRef.current = 0;
    durationRef.current = 0;
    setOptions((previous) => ({ ...previous, scope: 'single' }));
  }, [open, host]);

  // The "all targets" scope is meaningless with fewer than two targets.
  useEffect(() => {
    if (targets.length <= 1) {
      setOptions((previous) => (previous.scope === 'single' ? previous : { ...previous, scope: 'single' }));
    }
  }, [targets.length]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const showHost = targets.length > 1;
    const offOpen = EventsOn(EVENT_PORT_OPEN, (event: PortOpenEvent) => {
      setResults((previous) => [...previous, event]);
      pushLog('ok', describePort(event, showHost));
    });
    const offProgress = EventsOn(EVENT_PORT_PROGRESS, (event: PortScanProgress) => {
      setProgress(event);
    });
    const offDone = EventsOn(EVENT_PORT_DONE, (event: PortScanDone) => {
      setDone(event);
      setProgress(null);
      setPhase('done');
      durationRef.current = startedAtRef.current ? Date.now() - startedAtRef.current : 0;
      const scope = event.targets > 1 ? `${event.targets} targets · ` : '';
      pushLog('ok', `portscan complete · ${scope}${event.open} open / ${event.scanned} ports each`);
    });
    const offError = EventsOn(EVENT_PORT_ERROR, (event: { message: string }) => {
      setError(event.message);
      setProgress(null);
      setPhase('done');
      durationRef.current = startedAtRef.current ? Date.now() - startedAtRef.current : 0;
      pushLog('error', `portscan error: ${event.message}`);
    });
    return () => {
      offOpen();
      offProgress();
      offDone();
      offError();
    };
  }, [open, pushLog, targets.length]);

  const rangeError = options.preset === 'custom' ? validateRange(options.portRange) : null;
  const canScanAll = targets.length > 1 && options.scope === 'all';
  const canStart = (options.preset !== 'custom' || rangeError === null) && (canScanAll || Boolean(host));

  const handleClose = () => {
    if (phase === 'scanning') {
      void CancelPortScan();
    }
    onClose();
  };

  useEscape(open, handleClose);

  const sortedResults = useMemo(
    () =>
      [...results].sort((a, b) =>
        a.host === b.host ? a.result.port - b.result.port : a.host.localeCompare(b.host),
      ),
    [results],
  );

  const multi = options.scope === 'all' && targets.length > 1;

  const filtered = useMemo(() => {
    const query = filter.trim().toLowerCase();
    if (!query) {
      return sortedResults;
    }
    return sortedResults.filter((entry) =>
      [
        String(entry.result.port),
        entry.result.protocol,
        entry.result.service,
        entry.result.product,
        entry.result.detail,
        entry.result.banner,
        entry.host,
        entry.label,
      ].some((value) => (value ?? '').toLowerCase().includes(query)),
    );
  }, [filter, sortedResults]);

  // groups orders the resolved targets first (so empty hosts are still shown
  // once the scan is done), then any extra hosts seen in the results.
  const groups = useMemo(() => {
    const scanned = multi ? targets : [{ label: label ?? '', host }];
    const order: { host: string; label: string }[] = [];
    const seen = new Set<string>();
    if (phase === 'done') {
      for (const target of scanned) {
        if (target.host && !seen.has(target.host)) {
          seen.add(target.host);
          order.push({ host: target.host, label: target.label });
        }
      }
    }
    for (const entry of filtered) {
      if (!seen.has(entry.host)) {
        seen.add(entry.host);
        order.push({ host: entry.host, label: entry.label ?? '' });
      }
    }
    const byHost = new Map<string, PortOpenEvent[]>();
    for (const entry of filtered) {
      const rows = byHost.get(entry.host);
      if (rows) {
        rows.push(entry);
      } else {
        byHost.set(entry.host, [entry]);
      }
    }
    return order.map((group) => {
      const rows = byHost.get(group.host) ?? [];
      rows.sort((a, b) =>
        sort === 'service'
          ? (a.result.service ?? '').localeCompare(b.result.service ?? '') || a.result.port - b.result.port
          : a.result.port - b.result.port,
      );
      return { ...group, rows };
    });
  }, [filtered, host, label, multi, phase, sort, targets]);

  const showHost = groups.length > 1;

  if (!open) {
    return null;
  }

  const portSummary =
    options.preset === 'custom'
      ? `${options.portRange} · ${countPorts(options.portRange)} ports`
      : PRESETS.find((preset) => preset.id === options.preset)?.label ?? options.preset;

  const start = () => {
    if (!canStart) {
      return;
    }
    const scanAll = canScanAll;
    startedAtRef.current = Date.now();
    durationRef.current = 0;
    setResults([]);
    setProgress(null);
    setDone(null);
    setError(null);
    setLogs([]);
    setFilter('');
    setShowActivity(false);
    setPhase('scanning');
    const scope = scanAll ? `${targets.length} targets` : host;
    pushLog('info', `▶ portscan ${scope} · ${options.protocol} · ${portSummary}`);
    ScanPorts(
      main.PortScanRequest.createFrom({
        host: scanAll ? '' : host,
        targets: scanAll
          ? targets.map((target) => main.PortScanTarget.createFrom({ label: target.label, host: target.host }))
          : [],
        protocol: options.protocol,
        preset: options.preset === 'custom' ? '' : options.preset,
        portRange: options.preset === 'custom' ? options.portRange : '',
        concurrency: options.concurrency,
        timeoutMs: options.timeoutMs,
        probe: options.probe,
      }),
    ).catch(() => {
      // Failures arrive through the portscan:error event.
    });
  };

  const handleExport = () => {
    if (sortedResults.length === 0) {
      return;
    }
    const scannedTargets = multi ? targets : [{ label: label ?? '', host }];
    const rows = sortedResults.map((entry) =>
      main.PortScanRow.createFrom({
        host: entry.host,
        label: entry.label ?? '',
        port: entry.result.port,
        protocol: entry.result.protocol,
        service: entry.result.service ?? '',
        product: entry.result.product ?? '',
        detail: entry.result.detail ?? '',
        banner: entry.result.banner ?? '',
        tls: entry.result.tls ?? false,
      }),
    );
    const report = main.PortScanReport.createFrom({
      target: label || host,
      scope: multi ? `all targets (${targets.length})` : 'single host',
      startedAt: startedAtRef.current,
      durationMs: durationRef.current,
      protocol: options.protocol === 'udp' ? 'UDP probe' : 'TCP connect',
      ports:
        options.preset === 'custom'
          ? 'Custom range'
          : PRESETS.find((preset) => preset.id === options.preset)?.label ?? options.preset,
      portCount: done?.scanned ?? 0,
      probe: options.probe,
      concurrency: options.concurrency,
      timeoutMs: options.timeoutMs,
      scanned: done?.scanned ?? 0,
      open: sortedResults.length,
      targets: done?.targets ?? scannedTargets.length,
      resolvedTargets: scannedTargets.map((target) =>
        main.PortScanTargetInfo.createFrom({ label: target.label, host: target.host }),
      ),
      rows,
    });
    ExportPortScanReport(report)
      .then((path) => {
        if (path) {
          pushLog('ok', `port scan report saved to ${path}`);
        }
      })
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        pushLog('error', `export failed: ${message}`);
      });
  };

  const percent = progress && progress.total > 0 ? (progress.done / progress.total) * 100 : 0;

  return (
    <Modal
      title="PORT SCAN"
      subtitle={
        <>
          {label ? `${label} · ` : ''}
          {host}
        </>
      }
      ariaLabel="Port scan"
      variant="modal--ports"
      onClose={handleClose}
      footer={
        <>
          {phase === 'options' && (
            <>
              <button type="button" className="btn" onClick={handleClose}>
                Cancel
              </button>
              <button type="button" className="btn btn--primary" disabled={!canStart} onClick={start}>
                Start scan
              </button>
            </>
          )}
          {phase === 'scanning' && (
            <button type="button" className="btn" onClick={() => void CancelPortScan()}>
              Stop
            </button>
          )}
          {phase === 'done' && (
            <>
              <button type="button" className="btn" onClick={handleClose}>
                Close
              </button>
              <button
                type="button"
                className="btn"
                disabled={sortedResults.length === 0}
                onClick={handleExport}
              >
                Export report
              </button>
              <button type="button" className="btn btn--primary" disabled={!canStart} onClick={start}>
                Rescan
              </button>
            </>
          )}
        </>
      }
    >
          {phase === 'options' ? (
            <>
              {targets.length > 1 && (
                <div className="scan-group">
                  <div className="scan-group-title">TARGETS</div>
                  <div className="port-toggle">
                    <button
                      type="button"
                      className={`port-toggle-btn${options.scope === 'single' ? ' is-active' : ''}`}
                      onClick={() => setOptions((previous) => ({ ...previous, scope: 'single' }))}
                    >
                      This host
                    </button>
                    <button
                      type="button"
                      className={`port-toggle-btn${options.scope === 'all' ? ' is-active' : ''}`}
                      onClick={() => setOptions((previous) => ({ ...previous, scope: 'all' }))}
                    >
                      All targets ({targets.length})
                    </button>
                  </div>
                  <div className="port-note">
                    {options.scope === 'all'
                      ? `Scans every resolved target (${targets.length}) and streams the open ports below.`
                      : host}
                  </div>
                </div>
              )}

              <div className="scan-group">
                <div className="scan-group-title">PORTS</div>
                <label className="scan-option">
                  <input
                    type="radio"
                    name="port-mode"
                    checked={options.preset !== 'custom'}
                    onChange={() => setOptions((previous) => ({ ...previous, preset: 'top100' }))}
                  />
                  <span className="scan-option-main">
                    <span className="scan-option-label">Common ports</span>
                    <span className="scan-option-hint">Curated lists of frequently open ports</span>
                  </span>
                </label>
                {options.preset !== 'custom' && (
                  <div className="port-presets">
                    {PRESETS.map((preset) => (
                      <button
                        key={preset.id}
                        type="button"
                        className={`port-preset${options.preset === preset.id ? ' is-active' : ''}`}
                        title={preset.hint}
                        onClick={() => setOptions((previous) => ({ ...previous, preset: preset.id }))}
                      >
                        {preset.label}
                      </button>
                    ))}
                  </div>
                )}
                <label className="scan-option">
                  <input
                    type="radio"
                    name="port-mode"
                    checked={options.preset === 'custom'}
                    onChange={() => setOptions((previous) => ({ ...previous, preset: 'custom' }))}
                  />
                  <span className="scan-option-main">
                    <span className="scan-option-label">Port range</span>
                    <span className="scan-option-hint">Single ports, ranges or a mix</span>
                  </span>
                </label>
                {options.preset === 'custom' && (
                  <div className="port-range">
                    <div className="input-wrap">
                      <span className="input-prompt">›</span>
                      <input
                        className="input selectable"
                        type="text"
                        value={options.portRange}
                        spellCheck={false}
                        autoComplete="off"
                        placeholder="22,80,443-445"
                        onChange={(event) =>
                          setOptions((previous) => ({ ...previous, portRange: event.target.value }))
                        }
                      />
                    </div>
                    <span className={`port-range-hint${rangeError ? ' is-error' : ''}`}>
                      {rangeError ?? `${countPorts(options.portRange)} ports`}
                    </span>
                  </div>
                )}
              </div>

              <div className="scan-group">
                <div className="scan-group-title">TRANSPORT</div>
                <div className="port-toggle">
                  <button
                    type="button"
                    className={`port-toggle-btn${options.protocol === 'tcp' ? ' is-active' : ''}`}
                    onClick={() => setOptions((previous) => ({ ...previous, protocol: 'tcp' }))}
                  >
                    TCP connect
                  </button>
                  <button
                    type="button"
                    className={`port-toggle-btn${options.protocol === 'udp' ? ' is-active' : ''}`}
                    onClick={() => setOptions((previous) => ({ ...previous, protocol: 'udp' }))}
                  >
                    UDP probe
                  </button>
                </div>
                <label className="scan-option">
                  <input
                    type="checkbox"
                    checked={options.probe}
                    onChange={() => setOptions((previous) => ({ ...previous, probe: !previous.probe }))}
                  />
                  <span className="scan-option-main">
                    <span className="scan-option-label">Identify protocols</span>
                    <span className="scan-option-hint">
                      Banner grab, HTTP request and TLS handshake on TCP ports; protocol-specific replies on UDP
                    </span>
                  </span>
                </label>
                {options.protocol === 'udp' && (
                  <div className="port-note">
                    UDP is best-effort: only replies are reported, so filtered ports look closed.
                  </div>
                )}
              </div>

              <div className="scan-group">
                <div className="scan-group-title">PACING</div>
                <div className="scan-fields">
                  <div className="field">
                    <label className="field-label" htmlFor="port-concurrency">
                      CONCURRENCY
                    </label>
                    <input
                      id="port-concurrency"
                      className="input input--num selectable"
                      type="number"
                      min={1}
                      max={512}
                      value={options.concurrency}
                      onChange={(event) =>
                        setOptions((previous) => ({
                          ...previous,
                          concurrency: clamp(Number(event.target.value) || 64, 1, 512),
                        }))
                      }
                    />
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="port-timeout">
                      TIMEOUT (MS)
                    </label>
                    <input
                      id="port-timeout"
                      className="input input--num selectable"
                      type="number"
                      min={50}
                      max={5000}
                      step={50}
                      value={options.timeoutMs}
                      onChange={(event) =>
                        setOptions((previous) => ({
                          ...previous,
                          timeoutMs: clamp(Number(event.target.value) || 500, 50, 5000),
                        }))
                      }
                    />
                  </div>
                </div>
                <div className="port-note">
                  Port order is randomised and probes are jittered to reduce the scan signature. Only scan hosts you
                  are authorised to test.
                </div>
              </div>
            </>
          ) : (
            <>
              {phase === 'scanning' && (
                <div className="port-progress">
                  <div className="port-progress-head">
                    <span>
                      {progress
                        ? `${multi ? `target ${progress.target}/${progress.targets} · ` : ''}${progress.done}/${progress.total}`
                        : 'starting…'}
                    </span>
                    <span>{progress?.open ?? results.length} open</span>
                  </div>
                  <div className="port-progress-bar">
                    <i style={{ width: `${percent}%` }} />
                  </div>
                </div>
              )}

              {error && <div className="port-error">{error}</div>}

              {phase === 'done' && !error && (
                <div className="port-summary">
                  <b>{results.length}</b> open
                  {done ? ` · ${done.scanned} scanned${done.targets > 1 ? ' each' : ''}` : ''}
                  {multi || (done?.targets ?? 1) > 1 ? ` · ${done?.targets ?? targets.length} targets` : ''}
                </div>
              )}

              {results.length > 0 && (
                <>
                  <div className="port-results-toolbar">
                    <div className="input-wrap port-filter">
                      <span className="input-prompt">›</span>
                      <input
                        className="input selectable"
                        type="text"
                        value={filter}
                        spellCheck={false}
                        autoComplete="off"
                        placeholder="filter ports, services, hosts"
                        onChange={(event) => setFilter(event.target.value)}
                      />
                    </div>
                    <div className="port-sort">
                      <button
                        type="button"
                        className={`port-sort-btn${sort === 'port' ? ' is-active' : ''}`}
                        onClick={() => setSort('port')}
                      >
                        Port
                      </button>
                      <button
                        type="button"
                        className={`port-sort-btn${sort === 'service' ? ' is-active' : ''}`}
                        onClick={() => setSort('service')}
                      >
                        Service
                      </button>
                    </div>
                    <span className="port-results-count">
                      {filtered.length === results.length
                        ? `${results.length} open`
                        : `${filtered.length} / ${results.length}`}
                    </span>
                  </div>

                  {filtered.length === 0 ? (
                    <div className="port-empty">No open ports match “{filter}”.</div>
                  ) : (
                    <div className="port-table">
                      {groups.map((group) => (
                        <Fragment key={group.host}>
                          {showHost && (
                            <div className="port-host">
                              <span className="port-host-name selectable">
                                {group.label && group.label !== group.host ? group.label : group.host}
                              </span>
                              {group.label && group.label !== group.host && (
                                <span className="port-host-addr selectable">{group.host}</span>
                              )}
                              <span className="port-host-count">
                                {group.rows.length} open
                              </span>
                            </div>
                          )}
                          <div className="port-row port-row--head">
                            <span>PORT</span>
                            <span>PROTO</span>
                            <span>SERVICE</span>
                            <span>IDENTIFICATION</span>
                          </div>
                          {group.rows.length === 0 ? (
                            <div className="port-row port-row--empty">
                              <span>no open ports</span>
                            </div>
                          ) : (
                            group.rows.map((entry) => (
                              <div className="port-row" key={`${entry.host}:${entry.result.port}/${entry.result.protocol}`}>
                                <span className="port-num">{entry.result.port}</span>
                                <span className="port-proto">{entry.result.protocol}</span>
                                <span className="port-service">{entry.result.service || '—'}</span>
                                <span className="port-ident">
                                  {entry.result.product && (
                                    <span className="port-product">{entry.result.product}</span>
                                  )}
                                  {entry.result.tls && <span className="port-tag">TLS</span>}
                                  {(entry.result.detail || entry.result.banner) && (
                                    <span className="port-banner" title={entry.result.detail || entry.result.banner}>
                                      {entry.result.detail || entry.result.banner}
                                    </span>
                                  )}
                                </span>
                              </div>
                            ))
                          )}
                        </Fragment>
                      ))}
                    </div>
                  )}
                </>
              )}

              {phase === 'done' && results.length === 0 && !error && (
                <div className="port-empty">No open ports found.</div>
              )}

              <div className="domain-group">
                <button
                  type="button"
                  className={`port-activity-toggle${showActivity ? ' is-open' : ''}`}
                  onClick={() => setShowActivity((previous) => !previous)}
                  aria-expanded={showActivity}
                >
                  <span className="port-activity-caret">{showActivity ? '▾' : '▸'}</span>
                  ACTIVITY · {logs.length}
                </button>
                {showActivity && (
                  <div className="port-log">
                    <ConsoleBody lines={logs} />
                  </div>
                )}
              </div>
            </>
          )}
    </Modal>
  );
};

export default PortScanModal;
