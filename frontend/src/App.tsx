import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties, PointerEvent as ReactPointerEvent } from 'react';
import {
  Cancel,
  ClearHistory,
  DeleteHistory,
  ListHistory,
  LoadHistory,
  SaveHistory,
  Scan,
  Trace,
  TraceTargets,
} from '../wailsjs/go/main/App';
import { EventsOff, EventsOn } from '../wailsjs/runtime/runtime';
import { main } from '../wailsjs/go/models';
import HistoryModal from './components/HistoryModal';
import HopList from './components/HopList';
import ScanModal from './components/ScanModal';
import StatusBar from './components/StatusBar';
import SubdomainList from './components/SubdomainList';
import Toolbar from './components/Toolbar';
import TraceList from './components/TraceList';
import TracerouteMap from './components/TracerouteMap';
import { TRACE_COLORS } from './colors';
import { buildDisplayHops, isLocated } from './traces';
import type {
  DNSRecord,
  DoneEvent,
  ErrorEvent,
  GeoEvent,
  HistoryEntry,
  HistorySummary,
  HopEvent,
  ScanOptions,
  ScanProgressEvent,
  ScanTarget,
  SubdomainResult,
  TargetEvent,
  TargetGeoEvent,
  TraceState,
} from './types';

const EVENT_HOP = 'trace:hop';
const EVENT_GEO = 'trace:geo';
const EVENT_TARGET = 'trace:target';
const EVENT_TARGET_GEO = 'trace:targetGeo';
const EVENT_DONE = 'trace:done';
const EVENT_ERROR = 'trace:error';
const EVENT_SCAN_RECORDS = 'scan:records';
const EVENT_SCAN_TARGETS = 'scan:targets';
const EVENT_SCAN_DONE = 'scan:done';
const EVENT_SUBDOMAINS = 'scan:subdomains';
const EVENT_SCAN_PROGRESS = 'scan:progress';

const MIN_SIDEBAR = 240;
const MAX_SIDEBAR = 560;

const App = () => {
  const [target, setTarget] = useState('example.com');
  const [maxHops, setMaxHops] = useState(30);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [traces, setTraces] = useState<TraceState[]>([]);
  const [records, setRecords] = useState<DNSRecord[]>([]);
  const [selectedTrace, setSelectedTrace] = useState<number | null>(null);
  const [selectedHop, setSelectedHop] = useState<number | null>(null);
  const [mode, setMode] = useState<'trace' | 'scan'>('trace');
  const [sidebarWidth, setSidebarWidth] = useState(320);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [lastTarget, setLastTarget] = useState('');
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyEntries, setHistoryEntries] = useState<HistorySummary[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyDisabled, setHistoryDisabled] = useState(false);
  const [viewMode, setViewMode] = useState<'live' | 'history'>('live');
  const [toast, setToast] = useState<string | null>(null);
  const [scanOpen, setScanOpen] = useState(false);
  const [subdomains, setSubdomains] = useState<SubdomainResult[]>([]);
  const [selectedSubs, setSelectedSubs] = useState<Set<string>>(new Set());
  const [scanProgress, setScanProgress] = useState<ScanProgressEvent | null>(null);
  const [tracingSubs, setTracingSubs] = useState(false);
  const busyRef = useRef(false);
  const toastTimer = useRef<number | null>(null);

  const showToast = useCallback((message: string) => {
    setToast(message);
    if (toastTimer.current != null) {
      window.clearTimeout(toastTimer.current);
    }
    toastTimer.current = window.setTimeout(() => setToast(null), 2600);
  }, []);

  useEffect(
    () => () => {
      if (toastTimer.current != null) {
        window.clearTimeout(toastTimer.current);
      }
    },
    [],
  );

  useEffect(() => {
    EventsOn(EVENT_HOP, (event: HopEvent) => {
      setTraces((previous) =>
        previous.map((trace) =>
          trace.id === event.target
            ? { ...trace, hops: [...trace.hops, { hop: event.hop, ip: event.ip, rttMs: event.rttMs }] }
            : trace,
        ),
      );
    });
    EventsOn(EVENT_GEO, (event: GeoEvent) => {
      setTraces((previous) =>
        previous.map((trace) =>
          trace.id === event.target
            ? {
                ...trace,
                hops: trace.hops.map((hop) => (hop.hop === event.hop ? { ...hop, geo: event.geo } : hop)),
              }
            : trace,
        ),
      );
    });
    EventsOn(EVENT_TARGET, (event: TargetEvent) => {
      setTraces((previous) =>
        previous.map((trace) => (trace.id === event.target ? { ...trace, targetIp: event.ip } : trace)),
      );
    });
    EventsOn(EVENT_TARGET_GEO, (event: TargetGeoEvent) => {
      setTraces((previous) =>
        previous.map((trace) => (trace.id === event.target ? { ...trace, targetGeo: event.geo } : trace)),
      );
    });
    EventsOn(EVENT_DONE, (event: DoneEvent) => {
      setTraces((previous) =>
        previous.map((trace) => (trace.id === event.target ? { ...trace, done: true } : trace)),
      );
      if (event.target === 0) {
        busyRef.current = false;
        setIsLoading(false);
      }
    });
    EventsOn(EVENT_ERROR, (event: ErrorEvent) => {
      setTraces((previous) =>
        previous.map((trace) => (trace.id === event.target ? { ...trace, error: event.message } : trace)),
      );
      if (event.target === 0) {
        busyRef.current = false;
        setError(event.message);
        setIsLoading(false);
      }
    });
    EventsOn(EVENT_SCAN_RECORDS, (event: DNSRecord[]) => {
      setRecords(event);
    });
    EventsOn(EVENT_SCAN_TARGETS, (event: ScanTarget[]) => {
      setTraces(
        event.map((scanTarget, index) => ({
          id: scanTarget.id,
          label: scanTarget.label,
          kind: scanTarget.kind,
          ip: scanTarget.ip,
          color: TRACE_COLORS[index % TRACE_COLORS.length],
          hops: [],
        })),
      );
      setSelectedTrace(event[0]?.id ?? null);
    });
    EventsOn(EVENT_SCAN_DONE, () => {
      busyRef.current = false;
      setIsLoading(false);
      setScanProgress(null);
      setTracingSubs(false);
    });
    EventsOn(EVENT_SUBDOMAINS, (event: SubdomainResult[]) => {
      setSubdomains(event);
      setSelectedSubs(new Set());
    });
    EventsOn(EVENT_SCAN_PROGRESS, (event: ScanProgressEvent) => {
      setScanProgress(event);
    });

    return () => {
      EventsOff(EVENT_HOP);
      EventsOff(EVENT_GEO);
      EventsOff(EVENT_TARGET);
      EventsOff(EVENT_TARGET_GEO);
      EventsOff(EVENT_DONE);
      EventsOff(EVENT_ERROR);
      EventsOff(EVENT_SCAN_RECORDS);
      EventsOff(EVENT_SCAN_TARGETS);
      EventsOff(EVENT_SCAN_DONE);
      EventsOff(EVENT_SUBDOMAINS);
      EventsOff(EVENT_SCAN_PROGRESS);
    };
  }, []);

  useEffect(() => {
    if (!isLoading || startedAt == null) {
      return;
    }
    setElapsedMs(Date.now() - startedAt);
    const id = window.setInterval(() => setElapsedMs(Date.now() - startedAt), 200);
    return () => window.clearInterval(id);
  }, [isLoading, startedAt]);

  const startOperation = useCallback(
    (nextMode: 'trace' | 'scan') => {
      busyRef.current = true;
      setMode(nextMode);
      setViewMode('live');
      setRecords([]);
      setTraces([]);
      setSelectedTrace(null);
      setSelectedHop(null);
      setError(null);
      setIsLoading(true);
      setStartedAt(Date.now());
      setElapsedMs(0);
      setSubdomains([]);
      setSelectedSubs(new Set());
      setScanProgress(null);
      setTracingSubs(false);
    },
    [],
  );

  const handleTrace = useCallback(() => {
    if (busyRef.current) {
      return;
    }
    const trimmed = target.trim();
    if (!trimmed) {
      setError('Enter a target hostname or IP address.');
      return;
    }
    startOperation('trace');
    setTraces([{ id: 0, label: trimmed, color: TRACE_COLORS[0], hops: [] }]);
    setSelectedTrace(0);
    setLastTarget(trimmed);
    Trace({ target: trimmed, maxHops }).catch(() => {
      // Failures are surfaced through the trace:error event.
    });
  }, [maxHops, startOperation, target]);

  const handleScan = useCallback(() => {
    if (busyRef.current) {
      return;
    }
    const trimmed = target.trim();
    if (!trimmed) {
      setError('Enter a domain to scan.');
      return;
    }
    setError(null);
    setScanOpen(true);
  }, [target]);

  const handleScanConfirm = useCallback(
    (options: ScanOptions) => {
      const trimmed = target.trim();
      if (!trimmed) {
        return;
      }
      setScanOpen(false);
      startOperation('scan');
      setLastTarget(trimmed);
      Scan(main.ScanRequest.createFrom({ domain: trimmed, maxHops, options })).catch(() => {
        // Failures are surfaced through the trace:error event.
      });
    },
    [maxHops, startOperation, target],
  );

  const handleToggleSub = useCallback((name: string) => {
    setSelectedSubs((previous) => {
      const next = new Set(previous);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
  }, []);

  const handleSelectAllSubs = useCallback(() => {
    setSelectedSubs(new Set(subdomains.map((subdomain) => subdomain.name)));
  }, [subdomains]);

  const handleClearSubs = useCallback(() => {
    setSelectedSubs(new Set());
  }, []);

  const handleTraceSubs = useCallback(() => {
    if (busyRef.current || selectedSubs.size === 0) {
      return;
    }
    const hosts = [...selectedSubs];
    busyRef.current = true;
    setIsLoading(true);
    setStartedAt(Date.now());
    setElapsedMs(0);
    setTracingSubs(true);
    TraceTargets(main.TraceTargetsRequest.createFrom({ domain: lastTarget, maxHops, hosts })).catch(() => {
      setTracingSubs(false);
    });
  }, [lastTarget, maxHops, selectedSubs]);

  const handleCancel = useCallback(() => {
    Cancel();
  }, []);

  const handleSelectTrace = useCallback((id: number) => {
    setSelectedTrace(id);
    setSelectedHop(null);
  }, []);

  const refreshHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const list = await ListHistory();
      setHistoryEntries(list as HistorySummary[]);
      setHistoryDisabled(false);
    } catch {
      setHistoryEntries([]);
      setHistoryDisabled(true);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  const handleOpenHistory = useCallback(() => {
    setHistoryOpen(true);
    void refreshHistory();
  }, [refreshHistory]);

  const handleAddToHistory = useCallback(() => {
    if (busyRef.current || traces.length === 0) {
      return;
    }
    const snapshot = traces.map((trace) => ({
      label: trace.label,
      kind: trace.kind,
      ip: trace.ip,
      targetIp: trace.targetIp,
      targetGeo: trace.targetGeo,
      error: trace.error,
      hops: trace.hops.map((hop) => ({
        hop: hop.hop,
        ip: hop.ip,
        rttMs: hop.rttMs,
        geo: hop.geo,
        isTarget: hop.isTarget,
      })),
    }));

    SaveHistory(
      main.HistorySaveRequest.createFrom({
        kind: mode,
        label: lastTarget || traces[0]?.label || 'trace',
        maxHops,
        traces: snapshot,
      }),
    )
      .then(() => {
        showToast('Saved to history');
        if (historyOpen) {
          void refreshHistory();
        }
      })
      .catch((err: unknown) => {
        showToast(err instanceof Error ? err.message : 'Could not save to history');
      });
  }, [historyOpen, lastTarget, maxHops, mode, refreshHistory, showToast, traces]);

  const handleLoadHistory = useCallback(
    (ids: number[]) => {
      if (ids.length === 0) {
        return;
      }
      LoadHistory(ids)
        .then((entries) => {
          const loaded: TraceState[] = [];
          (entries as HistoryEntry[]).forEach((entry) => {
            entry.traces.forEach((trace) => {
              const index = loaded.length;
              loaded.push({
                id: index,
                label: trace.label,
                kind: trace.kind,
                ip: trace.ip,
                color: TRACE_COLORS[index % TRACE_COLORS.length],
                targetIp: trace.targetIp,
                targetGeo: trace.targetGeo,
                hops: trace.hops.map((hop) => ({ ...hop })),
                error: trace.error,
                done: true,
              });
            });
          });
          if (loaded.length === 0) {
            showToast('Nothing to display');
            return;
          }
          busyRef.current = false;
          setIsLoading(false);
          setError(null);
          setRecords([]);
          setStartedAt(null);
          setElapsedMs(0);
          setTraces(loaded);
          setSelectedTrace(loaded[0].id);
          setSelectedHop(null);
          setViewMode('history');
          setHistoryOpen(false);
        })
        .catch((err: unknown) => {
          showToast(err instanceof Error ? err.message : 'Could not load history');
        });
    },
    [showToast],
  );

  const handleDeleteHistory = useCallback(
    (id: number) => {
      DeleteHistory(id)
        .then(() => {
          setHistoryEntries((previous) => previous.filter((entry) => entry.id !== id));
        })
        .catch((err: unknown) => {
          showToast(err instanceof Error ? err.message : 'Could not delete entry');
        });
    },
    [showToast],
  );

  const handleClearHistory = useCallback(() => {
    ClearHistory()
      .then(() => setHistoryEntries([]))
      .catch((err: unknown) => {
        showToast(err instanceof Error ? err.message : 'Could not clear history');
      });
  }, [showToast]);

  const handleExitHistoryView = useCallback(() => {
    setViewMode('live');
    setTraces([]);
    setSelectedTrace(null);
    setSelectedHop(null);
    setStartedAt(null);
    setElapsedMs(0);
  }, []);

  // Hops appearing in two or more traces are the correlation points between
  // paths. Count distinct traces per IP so a loop within one trace counts once.
  const sharedHops = useMemo(() => {
    const perIp = new Map<string, Set<number>>();
    for (const trace of traces) {
      const ips = new Set<string>();
      for (const hop of buildDisplayHops(trace)) {
        if (hop.ip) {
          ips.add(hop.ip);
        }
      }
      for (const ip of ips) {
        const set = perIp.get(ip) ?? new Set<number>();
        set.add(trace.id);
        perIp.set(ip, set);
      }
    }
    const shared = new Map<string, number>();
    for (const [ip, set] of perIp) {
      if (set.size >= 2) {
        shared.set(ip, set.size);
      }
    }
    return shared;
  }, [traces]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && busyRef.current) {
        handleCancel();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [handleCancel]);

  const onSplitterDown = useCallback(
    (event: ReactPointerEvent<HTMLDivElement>) => {
      event.preventDefault();
      const startX = event.clientX;
      const startWidth = sidebarWidth;
      const onMove = (moveEvent: PointerEvent) => {
        const next = Math.min(MAX_SIDEBAR, Math.max(MIN_SIDEBAR, startWidth + moveEvent.clientX - startX));
        setSidebarWidth(next);
      };
      const onUp = () => {
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
      };
      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
    },
    [sidebarWidth],
  );

  const activeTrace = traces.find((trace) => trace.id === selectedTrace) ?? traces[0];
  const displayHops = useMemo(() => (activeTrace ? buildDisplayHops(activeTrace) : []), [activeTrace]);

  const totals = useMemo(() => {
    let hops = 0;
    let located = 0;
    for (const trace of traces) {
      const display = buildDisplayHops(trace);
      hops += display.length;
      located += display.filter(isLocated).length;
    }
    return { hops, located };
  }, [traces]);

  const state: 'ready' | 'tracing' | 'done' | 'error' = error
    ? 'error'
    : isLoading
      ? 'tracing'
      : traces.length > 0
        ? 'done'
        : 'ready';

  const message = error
    ? error
    : isLoading
      ? scanProgress
        ? `discovering subdomains ${scanProgress.done}/${scanProgress.total} · ${scanProgress.found} found`
        : `${mode === 'scan' ? 'scanning' : 'probing'} ${lastTarget}…`
      : viewMode === 'history'
        ? `${traces.length} saved ${traces.length === 1 ? 'path' : 'paths'}`
        : traces.length > 0
          ? lastTarget
          : '';

  return (
    <div className="app" style={{ '--side': `${sidebarWidth}px` } as CSSProperties}>
      <header className="appbar">
        <div className="brand">
          <span className="brand-dot" data-state={state} />
          <span className="brand-name">TRACEROUTE</span>
          <span className="brand-sub">/ NETWORK CONSOLE</span>
        </div>
        <div className="appbar-meta">
          {viewMode === 'history' ? (
            <>
              <span className="appbar-history">
                HISTORY · {traces.length} paths{sharedHops.size > 0 ? ` · ${sharedHops.size} shared` : ''}
              </span>
              <button type="button" className="appbar-exit" onClick={handleExitHistoryView}>
                EXIT
              </button>
            </>
          ) : (
            <>
              <span>GEO · IPWHO.IS</span>
              <span>DNS · A/AAAA/CNAME/MX/NS</span>
            </>
          )}
        </div>
      </header>

      <Toolbar
        target={target}
        onTargetChange={setTarget}
        maxHops={maxHops}
        onMaxHopsChange={setMaxHops}
        isLoading={isLoading}
        onTrace={handleTrace}
        onScan={handleScan}
        onCancel={handleCancel}
        onHistory={handleOpenHistory}
        onAddToHistory={handleAddToHistory}
        canAddToHistory={!isLoading && traces.length > 0}
      />

      <div className="main">
        <aside className="sidebar">
          {records.length > 0 && (
            <details className="dns-panel" open>
              <summary>
                DNS RECORDS <span className="pane-count">{records.length}</span>
              </summary>
              <div className="dns-list">
                {records.map((record, index) => (
                  <div className="dns-row" key={`${record.type}-${record.value}-${index}`}>
                    <span className="dns-type">{record.type}</span>
                    <span className="dns-value selectable">
                      {record.value}
                      {record.priority ? ` · ${record.priority}` : ''}
                    </span>
                  </div>
                ))}
              </div>
            </details>
          )}

          {subdomains.length > 0 && (
            <>
              <div className="pane-head">
                <span>SUBDOMAINS</span>
                <span className="pane-count">{subdomains.length}</span>
              </div>
              <div className="sub-scroll">
                <SubdomainList
                  subdomains={subdomains}
                  selected={selectedSubs}
                  tracing={tracingSubs}
                  onToggle={handleToggleSub}
                  onSelectAll={handleSelectAllSubs}
                  onClear={handleClearSubs}
                  onTrace={handleTraceSubs}
                />
              </div>
            </>
          )}

          {traces.length > 1 && (
            <>
              <div className="pane-head">
                <span>TARGETS</span>
                <span className="pane-count">{traces.length}</span>
              </div>
              <div className="trace-list">
                <TraceList traces={traces} selected={selectedTrace} onSelect={handleSelectTrace} />
              </div>
            </>
          )}

          <div className="pane-head">
            <span className="pane-title">{activeTrace ? activeTrace.label : 'HOPS'}</span>
            <span className="pane-count">{displayHops.length}</span>
          </div>
          <div className="hop-scroll">
            <HopList
              hops={displayHops}
              selectedHop={selectedHop}
              onSelectHop={setSelectedHop}
              sharedHops={sharedHops}
            />
          </div>
        </aside>

        <div className="splitter" onPointerDown={onSplitterDown} role="separator" aria-orientation="vertical" />

        <TracerouteMap
          traces={traces}
          selectedTrace={selectedTrace}
          selectedHop={selectedHop}
          onSelectTrace={handleSelectTrace}
          onSelectHop={setSelectedHop}
          sharedHops={sharedHops}
        />
      </div>

      <StatusBar
        state={state}
        message={message}
        targets={traces.length}
        hops={totals.hops}
        located={totals.located}
        elapsedMs={elapsedMs}
      />

      <HistoryModal
        open={historyOpen}
        entries={historyEntries}
        loading={historyLoading}
        disabled={historyDisabled}
        onClose={() => setHistoryOpen(false)}
        onLoad={handleLoadHistory}
        onDelete={handleDeleteHistory}
        onClear={handleClearHistory}
      />

      <ScanModal
        open={scanOpen}
        domain={target}
        maxHops={maxHops}
        onDomainChange={setTarget}
        onMaxHopsChange={setMaxHops}
        onCancel={() => setScanOpen(false)}
        onConfirm={handleScanConfirm}
      />

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
};

export default App;
