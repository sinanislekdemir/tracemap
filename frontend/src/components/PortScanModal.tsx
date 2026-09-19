import { useEffect, useMemo, useState } from 'react';
import { Cancel, ScanPorts } from '../../wailsjs/go/main/App';
import { main } from '../../wailsjs/go/models';
import { EventsOn } from '../../wailsjs/runtime/runtime';
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
  PortResult,
  PortScanDone,
  PortScanOptions,
  PortScanProgress,
} from '../types';

type Phase = 'options' | 'scanning' | 'done';

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

interface PortScanModalProps {
  open: boolean;
  host: string;
  label?: string;
  onClose: () => void;
  onLog: (level: LogLevel, text: string) => void;
}

const PortScanModal = ({ open, host, label, onClose, onLog }: PortScanModalProps) => {
  const [options, setOptions] = useState<PortScanOptions>(DEFAULT_OPTIONS);
  const [phase, setPhase] = useState<Phase>('options');
  const [results, setResults] = useState<PortResult[]>([]);
  const [progress, setProgress] = useState<PortScanProgress | null>(null);
  const [done, setDone] = useState<PortScanDone | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      return;
    }
    setPhase('options');
    setResults([]);
    setProgress(null);
    setDone(null);
    setError(null);
  }, [open, host]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const offOpen = EventsOn(EVENT_PORT_OPEN, (event: PortResult) => {
      setResults((previous) => [...previous, event]);
      const name = event.product || event.service || 'unknown';
      onLog('ok', `port ${event.protocol}/${event.port} open · ${name}`);
    });
    const offProgress = EventsOn(EVENT_PORT_PROGRESS, (event: PortScanProgress) => {
      setProgress(event);
    });
    const offDone = EventsOn(EVENT_PORT_DONE, (event: PortScanDone) => {
      setDone(event);
      setProgress(null);
      setPhase('done');
      onLog('ok', `portscan ${event.host} · ${event.open} open / ${event.scanned} scanned`);
    });
    const offError = EventsOn(EVENT_PORT_ERROR, (event: { message: string }) => {
      setError(event.message);
      setProgress(null);
      setPhase('done');
      onLog('error', `portscan error: ${event.message}`);
    });
    return () => {
      offOpen();
      offProgress();
      offDone();
      offError();
    };
  }, [open, onLog]);

  const rangeError = options.preset === 'custom' ? validateRange(options.portRange) : null;
  const canStart = options.preset !== 'custom' || rangeError === null;

  const handleClose = () => {
    if (phase === 'scanning') {
      Cancel();
    }
    onClose();
  };

  useEscape(open, handleClose);

  const sortedResults = useMemo(
    () => [...results].sort((a, b) => a.port - b.port),
    [results],
  );

  if (!open) {
    return null;
  }

  const portSummary =
    options.preset === 'custom'
      ? `${options.portRange} · ${countPorts(options.portRange)} ports`
      : PRESETS.find((preset) => preset.id === options.preset)?.label ?? options.preset;

  const start = () => {
    if (!host || !canStart) {
      return;
    }
    setResults([]);
    setProgress(null);
    setDone(null);
    setError(null);
    setPhase('scanning');
    onLog('info', `▶ portscan ${host} · ${options.protocol} · ${portSummary}`);
    ScanPorts(
      main.PortScanRequest.createFrom({
        host,
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
            <button type="button" className="btn" onClick={() => Cancel()}>
              Stop
            </button>
          )}
          {phase === 'done' && (
            <>
              <button type="button" className="btn" onClick={handleClose}>
                Close
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
                    <span>{progress ? `${progress.done}/${progress.total}` : 'starting…'}</span>
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
                  {done ? ` · ${done.scanned} scanned` : ''}
                </div>
              )}

              {sortedResults.length === 0 ? (
                <div className="modal-note">{phase === 'scanning' ? 'Scanning…' : 'No open ports found.'}</div>
              ) : (
                <div className="port-table">
                  <div className="port-row port-row--head">
                    <span>PORT</span>
                    <span>PROTO</span>
                    <span>SERVICE</span>
                    <span>IDENTIFIED</span>
                  </div>
                  {sortedResults.map((result) => (
                    <div className="port-row" key={`${result.protocol}-${result.port}`}>
                      <span className="port-num selectable">{result.port}</span>
                      <span className="port-proto">{result.protocol}</span>
                      <span className="port-service">{result.service || '—'}</span>
                      <span className="port-ident">
                        {result.tls && <span className="port-tag">TLS</span>}
                        <span className="port-product selectable">{result.product || '—'}</span>
                        {(result.detail || result.banner) && (
                          <span className="port-banner selectable">{result.detail || result.banner}</span>
                        )}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
    </Modal>
  );
};

export default PortScanModal;
