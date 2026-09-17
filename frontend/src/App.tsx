import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties, PointerEvent as ReactPointerEvent } from 'react';
import {
  Cancel,
  CheckTools,
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
import Console from './components/Console';
import ContextMenu from './components/ContextMenu';
import HistoryModal from './components/HistoryModal';
import HopList from './components/HopList';
import MissingToolModal from './components/MissingToolModal';
import PortScanModal from './components/PortScanModal';
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
  LogLevel,
  LogLine,
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

const MIN_RIGHT = 240;
const MAX_RIGHT = 560;

const MIN_CONSOLE = 96;
const MAX_CONSOLE = 560;
const MAX_LOG_LINES = 500;

const App = () => {
  const [target, setTarget] = useState('example.com');
  const [maxHops, setMaxHops] = useState(30);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [traces, setTraces] = useState<TraceState[]>([]);
  const [records, setRecords] = useState<DNSRecord[]>([]);
  const [selectedTraces, setSelectedTraces] = useState<Set<number>>(new Set());
  const [focusedTrace, setFocusedTrace] = useState<number | null>(null);
  const [selectedHop, setSelectedHop] = useState<number | null>(null);
  const [mode, setMode] = useState<'trace' | 'scan'>('trace');
  const [sidebarWidth, setSidebarWidth] = useState(320);
  const [rightWidth, setRightWidth] = useState(340);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [rightbarOpen, setRightbarOpen] = useState(true);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [lastTarget, setLastTarget] = useState('');
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyEntries, setHistoryEntries] = useState<HistorySummary[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyDisabled, setHistoryDisabled] = useState(false);
  const [viewMode, setViewMode] = useState<'live' | 'history'>('live');
  const [toast, setToast] = useState<string | null>(null);
  const [toolError, setToolError] = useState<{ message: string; hint: string } | null>(null);
  const [scanOpen, setScanOpen] = useState(false);
  const [subdomains, setSubdomains] = useState<SubdomainResult[]>([]);
  const [selectedSubs, setSelectedSubs] = useState<Set<string>>(new Set());
  const [scanProgress, setScanProgress] = useState<ScanProgressEvent | null>(null);
  const [tracingSubs, setTracingSubs] = useState(false);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; host: string; label: string } | null>(null);
  const [portScan, setPortScan] = useState<{ host: string; label: string } | null>(null);
  const [logLines, setLogLines] = useState<LogLine[]>([]);
  const [consoleOpen, setConsoleOpen] = useState(true);
  const [consoleHeight, setConsoleHeight] = useState(200);
  const busyRef = useRef(false);
  const toastTimer = useRef<number | null>(null);
  const logIdRef = useRef(0);
  const scanPhaseRef = useRef<string | null>(null);

  const appendLog = useCallback((level: LogLevel, text: string) => {
    logIdRef.current += 1;
    const line: LogLine = { id: logIdRef.current, time: Date.now(), level, text };
    setLogLines((previous) => {
      const next = [...previous, line];
      return next.length > MAX_LOG_LINES ? next.slice(next.length - MAX_LOG_LINES) : next;
    });
  }, []);

  const showToast = useCallback((message: string) => {
    setToast(message);
    if (toastTimer.current != null) {
      window.clearTimeout(toastTimer.current);
    }
    toastTimer.current = window.setTimeout(() => setToast(null), 2600);
  }, []);

  const openContextMenu = useCallback((x: number, y: number, host: string, label: string) => {
    if (!host) {
      return;
    }
    const width = 240;
    const height = 108;
    setContextMenu({
      x: Math.max(8, Math.min(x, window.innerWidth - width)),
      y: Math.max(8, Math.min(y, window.innerHeight - height)),
      host,
      label,
    });
  }, []);

  const handleCopyIp = useCallback(
    (ip: string) => {
      navigator.clipboard?.writeText(ip).then(
        () => showToast(`Copied ${ip}`),
        () => showToast('Could not copy to clipboard'),
      );
    },
    [showToast],
  );

  useEffect(
    () => () => {
      if (toastTimer.current != null) {
        window.clearTimeout(toastTimer.current);
      }
    },
    [],
  );

  useEffect(() => {
    CheckTools()
      .then((status) => {
        if (!status.available) {
          setToolError({
            message: status.message || 'No traceroute tool was found on this system.',
            hint: status.hint || '',
          });
        }
      })
      .catch(() => {
        // Failures still surface through the trace:error path.
      });
  }, []);

  useEffect(() => {
    EventsOn(EVENT_HOP, (event: HopEvent) => {
      setTraces((previous) =>
        previous.map((trace) =>
          trace.id === event.target
            ? { ...trace, hops: [...trace.hops, { hop: event.hop, ip: event.ip, rttMs: event.rttMs }] }
            : trace,
        ),
      );
      appendLog(
        'info',
        `t${event.target} · hop ${String(event.hop).padStart(2, '0')} · ${event.ip || '* * *'} · ${
          event.rttMs != null ? `${event.rttMs.toFixed(1)} ms` : '—'
        }`,
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
      const place = [event.geo.city, event.geo.country].filter(Boolean).join(', ') || 'unknown';
      appendLog('info', `t${event.target} · hop ${String(event.hop).padStart(2, '0')} · geo ${place}${event.geo.asn ? ` · ${event.geo.asn}` : ''}`);
    });
    EventsOn(EVENT_TARGET, (event: TargetEvent) => {
      setTraces((previous) =>
        previous.map((trace) => (trace.id === event.target ? { ...trace, targetIp: event.ip } : trace)),
      );
      appendLog('ok', `t${event.target} · target resolved ${event.ip}`);
    });
    EventsOn(EVENT_TARGET_GEO, (event: TargetGeoEvent) => {
      setTraces((previous) =>
        previous.map((trace) => (trace.id === event.target ? { ...trace, targetGeo: event.geo } : trace)),
      );
      const place = [event.geo.city, event.geo.country].filter(Boolean).join(', ') || 'unknown';
      appendLog('info', `t${event.target} · target geo ${place}`);
    });
    EventsOn(EVENT_DONE, (event: DoneEvent) => {
      setTraces((previous) =>
        previous.map((trace) => (trace.id === event.target ? { ...trace, done: true } : trace)),
      );
      if (event.target === 0) {
        busyRef.current = false;
        setIsLoading(false);
      }
      appendLog('ok', `t${event.target} · done · ${event.hops} hops`);
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
      appendLog('error', `t${event.target} · error: ${event.message}`);
      if (event.code === 'missing-tool') {
        setToolError({ message: event.message, hint: event.hint ?? '' });
      }
    });
    EventsOn(EVENT_SCAN_RECORDS, (event: DNSRecord[]) => {
      setRecords(event);
      appendLog('info', `dns · ${event.length} records resolved`);
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
      setSelectedTraces(new Set());
      setFocusedTrace(event[0]?.id ?? null);
      appendLog('ok', `scan · ${event.length} targets queued`);
    });
    EventsOn(EVENT_SCAN_DONE, () => {
      busyRef.current = false;
      setIsLoading(false);
      setScanProgress(null);
      setTracingSubs(false);
      appendLog('ok', 'scan · complete');
    });
    EventsOn(EVENT_SUBDOMAINS, (event: SubdomainResult[]) => {
      setSubdomains(event);
      setSelectedSubs(new Set());
      appendLog('ok', `subdomains · ${event.length} found`);
    });
    EventsOn(EVENT_SCAN_PROGRESS, (event: ScanProgressEvent) => {
      setScanProgress(event);
      if (event.phase !== scanPhaseRef.current) {
        scanPhaseRef.current = event.phase;
        appendLog('info', `scan · ${event.phase}`);
      }
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
  }, [appendLog]);

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
      setSelectedTraces(new Set());
      setFocusedTrace(null);
      setSelectedHop(null);
      setError(null);
      setIsLoading(true);
      setStartedAt(Date.now());
      setElapsedMs(0);
      setSubdomains([]);
      setSelectedSubs(new Set());
      setScanProgress(null);
      setTracingSubs(false);
      setRightbarOpen(true);
      scanPhaseRef.current = null;
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
    setSelectedTraces(new Set());
    setFocusedTrace(0);
    setLastTarget(trimmed);
    appendLog('info', `▶ trace ${trimmed} · max ${maxHops} hops`);
    Trace({ target: trimmed, maxHops }).catch(() => {
      // Failures are surfaced through the trace:error event.
    });
  }, [appendLog, maxHops, startOperation, target]);

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

  const handlePortScan = useCallback(() => {
    const trimmed = target.trim();
    if (!trimmed) {
      setError('Enter a host to scan for ports.');
      return;
    }
    setError(null);
    setPortScan({ host: trimmed, label: trimmed });
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
      appendLog('info', `▶ scan ${trimmed} · max ${maxHops} hops`);
      Scan(main.ScanRequest.createFrom({ domain: trimmed, maxHops, options })).catch(() => {
        // Failures are surfaced through the trace:error event.
      });
    },
    [appendLog, maxHops, startOperation, target],
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
    appendLog('info', `▶ trace ${hosts.length} selected ${hosts.length === 1 ? 'host' : 'hosts'}`);
    TraceTargets(main.TraceTargetsRequest.createFrom({ domain: lastTarget, maxHops, hosts })).catch(() => {
      setTracingSubs(false);
    });
  }, [appendLog, lastTarget, maxHops, selectedSubs]);

  const handleCancel = useCallback(() => {
    appendLog('warn', '■ cancel requested');
    Cancel();
  }, [appendLog]);

  const handleToggleTrace = useCallback(
    (id: number) => {
      const removing = selectedTraces.has(id);
      setSelectedTraces((previous) => {
        const next = new Set(previous);
        if (removing) {
          next.delete(id);
        } else {
          next.add(id);
        }
        return next;
      });
      setFocusedTrace((current) => {
        if (!removing) {
          return id;
        }
        if (current !== id) {
          return current;
        }
        const remaining = [...selectedTraces].filter((traceId) => traceId !== id);
        return remaining.length > 0 ? remaining[0] : null;
      });
      setSelectedHop(null);
    },
    [selectedTraces],
  );

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
          setSelectedTraces(new Set());
          setFocusedTrace(loaded[0].id);
          setSelectedHop(null);
          setViewMode('history');
          setHistoryOpen(false);
          appendLog('info', `history · loaded ${loaded.length} ${loaded.length === 1 ? 'path' : 'paths'}`);
        })
        .catch((err: unknown) => {
          showToast(err instanceof Error ? err.message : 'Could not load history');
        });
    },
    [appendLog, showToast],
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
    setSelectedTraces(new Set());
    setFocusedTrace(null);
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
      const wasOpen = sidebarOpen;
      let moved = false;
      const onMove = (moveEvent: PointerEvent) => {
        if (!wasOpen) {
          return;
        }
        if (Math.abs(moveEvent.clientX - startX) > 3) {
          moved = true;
        }
        const next = Math.min(MAX_SIDEBAR, Math.max(MIN_SIDEBAR, startWidth + moveEvent.clientX - startX));
        setSidebarWidth(next);
      };
      const onUp = () => {
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
        if (!moved) {
          setSidebarOpen((value) => !value);
        }
      };
      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
    },
    [sidebarOpen, sidebarWidth],
  );

  const onRightSplitterDown = useCallback(
    (event: ReactPointerEvent<HTMLDivElement>) => {
      event.preventDefault();
      const startX = event.clientX;
      const startWidth = rightWidth;
      const wasOpen = rightbarOpen;
      let moved = false;
      const onMove = (moveEvent: PointerEvent) => {
        if (!wasOpen) {
          return;
        }
        if (Math.abs(moveEvent.clientX - startX) > 3) {
          moved = true;
        }
        const next = Math.min(MAX_RIGHT, Math.max(MIN_RIGHT, startWidth - (moveEvent.clientX - startX)));
        setRightWidth(next);
      };
      const onUp = () => {
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
        if (!moved) {
          setRightbarOpen((value) => !value);
        }
      };
      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
    },
    [rightbarOpen, rightWidth],
  );

  const onConsoleResizeDown = useCallback(
    (event: ReactPointerEvent<HTMLDivElement>) => {
      event.preventDefault();
      const startY = event.clientY;
      const startHeight = consoleHeight;
      const maxHeight = Math.min(MAX_CONSOLE, Math.round(window.innerHeight * 0.6));
      const onMove = (moveEvent: PointerEvent) => {
        const next = Math.min(maxHeight, Math.max(MIN_CONSOLE, startHeight + (startY - moveEvent.clientY)));
        setConsoleHeight(next);
      };
      const onUp = () => {
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
      };
      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
    },
    [consoleHeight],
  );

  const handleToggleConsole = useCallback(() => setConsoleOpen((value) => !value), []);
  const handleClearConsole = useCallback(() => setLogLines([]), []);

  const activeTrace = traces.find((trace) => trace.id === focusedTrace) ?? traces[0];
  const displayHops = useMemo(() => (activeTrace ? buildDisplayHops(activeTrace) : []), [activeTrace]);
  const hasDiscovery = records.length > 0 || subdomains.length > 0;

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
    <div
      className="app"
      style={{ '--side': `${sidebarWidth}px`, '--right': `${rightWidth}px` } as CSSProperties}
    >
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
        onPortScan={handlePortScan}
        onCancel={handleCancel}
        onHistory={handleOpenHistory}
        onAddToHistory={handleAddToHistory}
        canAddToHistory={!isLoading && traces.length > 0}
      />

      <div
        className="main"
        style={{
          gridTemplateColumns: [
            ...(sidebarOpen ? ['var(--side)'] : []),
            '16px',
            '1fr',
            ...(hasDiscovery ? ['16px', ...(rightbarOpen ? ['var(--right)'] : [])] : []),
          ].join(' '),
        }}
      >
        {sidebarOpen && (
        <aside className="sidebar">
          {traces.length > 1 && (
            <>
              <div className="pane-head">
                <span>TARGETS</span>
                <span className="pane-count">{traces.length}</span>
              </div>
              <div className="trace-list">
                <TraceList
                  traces={traces}
                  selected={selectedTraces}
                  onToggle={handleToggleTrace}
                  onContextMenu={(event, trace) => {
                    const host = trace.targetIp || trace.ip;
                    if (!host) {
                      return;
                    }
                    event.preventDefault();
                    event.stopPropagation();
                    openContextMenu(event.clientX, event.clientY, host, trace.label);
                  }}
                />
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
              onContextMenu={(event, hop) => {
                if (!hop.ip) {
                  return;
                }
                event.preventDefault();
                event.stopPropagation();
                openContextMenu(event.clientX, event.clientY, hop.ip, hop.isTarget ? 'target' : `hop ${hop.hop}`);
              }}
              sharedHops={sharedHops}
            />
          </div>
        </aside>
        )}

        <div
          className="splitter"
          onPointerDown={onSplitterDown}
          role="separator"
          aria-orientation="vertical"
          title={sidebarOpen ? 'Collapse hops panel' : 'Expand hops panel'}
        >
          <span className="splitter-arrow">{sidebarOpen ? '‹' : '›'}</span>
        </div>

        <TracerouteMap
          traces={traces}
          selectedTraces={selectedTraces}
          focusedTrace={focusedTrace}
          selectedHop={selectedHop}
          onToggleTrace={handleToggleTrace}
          onSelectHop={setSelectedHop}
          onContextMenu={(host, label, x, y) => openContextMenu(x, y, host, label)}
          sharedHops={sharedHops}
        />

        {hasDiscovery && (
          <div
            className="splitter splitter--right"
            onPointerDown={onRightSplitterDown}
            role="separator"
            aria-orientation="vertical"
            title={rightbarOpen ? 'Collapse discovery panel' : 'Expand discovery panel'}
          >
            <span className="splitter-arrow">{rightbarOpen ? '›' : '‹'}</span>
          </div>
        )}

        {hasDiscovery && rightbarOpen && (
          <aside className="rightbar">
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
              <div className="rightbar-section">
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
              </div>
            )}
          </aside>
        )}
      </div>

      <Console
        lines={logLines}
        open={consoleOpen}
        height={consoleHeight}
        state={state}
        onToggle={handleToggleConsole}
        onClear={handleClearConsole}
        onResizeStart={onConsoleResizeDown}
      />

      <StatusBar
        state={state}
        message={message}
        progress={scanProgress}
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

      <MissingToolModal
        open={toolError != null}
        message={toolError?.message ?? ''}
        hint={toolError?.hint ?? ''}
        onClose={() => setToolError(null)}
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

      <PortScanModal
        open={portScan != null}
        host={portScan?.host ?? ''}
        label={portScan?.label}
        onClose={() => setPortScan(null)}
        onLog={appendLog}
      />

      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          title={contextMenu.label}
          items={[
            {
              label: 'Find open ports',
              hint: contextMenu.host,
              onSelect: () => setPortScan({ host: contextMenu.host, label: contextMenu.label }),
            },
            { label: 'Copy IP', onSelect: () => handleCopyIp(contextMenu.host) },
          ]}
          onClose={() => setContextMenu(null)}
        />
      )}

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
};

export default App;
