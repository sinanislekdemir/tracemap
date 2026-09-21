import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent } from 'react';
import { NetClose, NetConnect, NetSend } from '../../wailsjs/go/main/App';
import { main } from '../../wailsjs/go/models';
import { EventsOn } from '../../wailsjs/runtime/runtime';
import { CHEATSHEETS } from '../cheatsheets';
import { EVENT_NET_CLOSED, EVENT_NET_DATA } from '../events';
import type { LogLevel, NetClosedEvent, NetDataEvent, NetStatus } from '../types';
import ContextMenu from './ContextMenu';

const MAX_ENTRIES = 2000;
const DEFAULT_TIMEOUT_MS = 10000;

type LineEnding = 'lf' | 'crlf' | 'none';

type EntryKind = 'in' | 'out' | 'info' | 'error';

interface Entry {
  id: number;
  kind: EntryKind;
  text: string;
}

interface NetcatPanelProps {
  /** Preloads the form; port/tls come from a port-scan hit when available. */
  request: { host: string; port?: number; tls?: boolean; nonce: number } | null;
  onLog: (level: LogLevel, text: string) => void;
  onOpenCheatsheet: (sheetId: string) => void;
}

// decodeChunk turns a base64 payload from the backend into printable text,
// escaping control characters so binary output cannot corrupt the terminal.
function decodeChunk(encoded: string): string {
  let bytes: Uint8Array;
  try {
    const binary = atob(encoded);
    bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
  } catch {
    return '';
  }
  return escapeControl(new TextDecoder('utf-8', { fatal: false }).decode(bytes));
}

function escapeControl(text: string): string {
  const normalized = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  let out = '';
  for (const ch of normalized) {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === '\n' || ch === '\t') {
      out += ch;
    } else if (code < 32 || code === 127) {
      out += `\\x${code.toString(16).padStart(2, '0')}`;
    } else {
      out += ch;
    }
  }
  return out;
}

const NetcatPanel = ({ request, onLog, onOpenCheatsheet }: NetcatPanelProps) => {
  const [host, setHost] = useState('');
  const [port, setPort] = useState('');
  const [tls, setTls] = useState(false);
  const [serverName, setServerName] = useState('');
  const [lineEnding, setLineEnding] = useState<LineEnding>('lf');
  const [status, setStatus] = useState<NetStatus>('idle');
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [remote, setRemote] = useState('');
  const [entries, setEntries] = useState<Entry[]>([]);
  const [input, setInput] = useState('');
  const [sheetMenuOpen, setSheetMenuOpen] = useState(false);
  const [sheetMenuPos, setSheetMenuPos] = useState({ x: 0, y: 0 });

  const sheetButtonRef = useRef<HTMLButtonElement>(null);
  const termRef = useRef<HTMLDivElement>(null);
  const pinnedRef = useRef(true);
  const entryIdRef = useRef(0);
  const sessionRef = useRef<string | null>(null);
  const hostRef = useRef<HTMLInputElement>(null);
  const portRef = useRef<HTMLInputElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const connectRef = useRef<HTMLButtonElement>(null);

  const append = (kind: EntryKind, text: string) => {
    setEntries((previous) => {
      const next = [...previous, { id: (entryIdRef.current += 1), kind, text }];
      return next.length > MAX_ENTRIES ? next.slice(next.length - MAX_ENTRIES) : next;
    });
  };

  useEffect(() => {
    sessionRef.current = sessionId;
  }, [sessionId]);

  // Closing the window unmounts the panel; make sure the backend session is
  // torn down with it.
  useEffect(
    () => () => {
      const id = sessionRef.current;
      if (id) {
        void NetClose(id);
      }
    },
    [],
  );

  useLayoutEffect(() => {
    if (!pinnedRef.current) {
      return;
    }
    const term = termRef.current;
    if (term) {
      term.scrollTop = term.scrollHeight;
    }
  }, [entries]);

  useEffect(() => {
    const offData = EventsOn(EVENT_NET_DATA, (event: NetDataEvent) => {
      if (event.session !== sessionRef.current) {
        return;
      }
      append('out', decodeChunk(event.data));
    });
    const offClosed = EventsOn(EVENT_NET_CLOSED, (event: NetClosedEvent) => {
      if (event.session !== sessionRef.current) {
        return;
      }
      append('info', `— ${event.reason} —`);
      setStatus('closed');
      setSessionId(null);
      setRemote('');
      onLog('info', `netcat session ended: ${event.reason}`);
    });
    return () => {
      offData();
      offClosed();
    };
  }, [onLog]);

  useEffect(() => {
    if (!request) {
      return;
    }
    setHost(request.host);
    if (request.port != null) {
      setPort(String(request.port));
    }
    if (request.tls != null) {
      setTls(request.tls);
    }
    if (request.host && request.port != null) {
      connectRef.current?.focus();
    } else if (request.host) {
      portRef.current?.focus();
    } else {
      hostRef.current?.focus();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [request?.nonce]);

  const onTermScroll = () => {
    const term = termRef.current;
    if (!term) {
      return;
    }
    pinnedRef.current = term.scrollHeight - term.scrollTop - term.clientHeight < 24;
  };

  const connect = async () => {
    const portNumber = Number(port);
    if (!host.trim()) {
      append('error', 'enter a host to connect to');
      return;
    }
    if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
      append('error', 'enter a port between 1 and 65535');
      return;
    }

    setStatus('connecting');
    append('info', `connecting to ${host.trim()}:${portNumber}${tls ? ' (tls)' : ''}…`);
    onLog('info', `▶ netcat ${host.trim()}:${portNumber}${tls ? ' tls' : ''}`);

    try {
      const session = await NetConnect(
        main.NetConnectRequest.createFrom({
          host: host.trim(),
          port: portNumber,
          timeoutMs: DEFAULT_TIMEOUT_MS,
          tls,
          serverName: serverName.trim(),
        }),
      );
      setSessionId(session.id);
      sessionRef.current = session.id;
      setRemote(session.remote ?? `${session.host}:${session.port}`);
      setStatus('connected');
      append('info', `connected${session.remote ? ` · ${session.remote}` : ''}`);
      onLog('ok', `netcat connected to ${session.host}:${session.port}`);
      inputRef.current?.focus();
    } catch (error) {
      setStatus('error');
      const message = error instanceof Error ? error.message : String(error);
      append('error', message);
      onLog('error', `netcat connect failed: ${message}`);
    }
  };

  const disconnect = async () => {
    if (!sessionId) {
      return;
    }
    try {
      await NetClose(sessionId);
    } catch {
      // The net:closed event reports the outcome.
    }
  };

  const send = async () => {
    if (!sessionId) {
      return;
    }
    const ending = lineEnding === 'crlf' ? '\r\n' : lineEnding === 'lf' ? '\n' : '';
    try {
      await NetSend(sessionId, input + ending);
      append('in', input);
      setInput('');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      append('error', message);
      onLog('error', `netcat send failed: ${message}`);
    }
  };

  const openSheetMenu = () => {
    const rect = sheetButtonRef.current?.getBoundingClientRect();
    if (rect) {
      setSheetMenuPos({ x: rect.left, y: rect.bottom + 6 });
    }
    setSheetMenuOpen(true);
  };

  const onInputKeyDown = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      void send();
    }
  };

  const onFieldKeyDown = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      void connect();
    }
  };

  const connected = status === 'connected' && sessionId != null;
  const statusLabel =
    status === 'idle'
      ? 'disconnected'
      : status === 'connected'
        ? remote || 'connected'
        : status === 'connecting'
          ? 'connecting…'
          : status;

  return (
    <div className="netcat">
      <div className="netcat-bar">
        <div className="input-wrap netcat-field netcat-field--host">
          <span className="input-prompt">›</span>
          <input
            ref={hostRef}
            className="input selectable"
            type="text"
            value={host}
            spellCheck={false}
            autoComplete="off"
            placeholder="hostname or IP"
            disabled={connected}
            onChange={(event) => setHost(event.target.value)}
            onKeyDown={onFieldKeyDown}
          />
        </div>
        <input
          ref={portRef}
          className="input input--num netcat-port selectable"
          type="number"
          min={1}
          max={65535}
          value={port}
          placeholder="port"
          disabled={connected}
          onChange={(event) => setPort(event.target.value)}
          onKeyDown={onFieldKeyDown}
        />
        <label className="netcat-check" title="Wrap the connection in a TLS handshake">
          <input
            type="checkbox"
            checked={tls}
            disabled={connected}
            onChange={() => setTls((value) => !value)}
          />
          TLS
        </label>
        {tls && !connected && (
          <input
            className="input netcat-sni selectable"
            type="text"
            value={serverName}
            spellCheck={false}
            autoComplete="off"
            placeholder="SNI (optional)"
            onChange={(event) => setServerName(event.target.value)}
          />
        )}
        <span className="netcat-spacer" />
        <button
          ref={sheetButtonRef}
          type="button"
          className={`btn netcat-sheets${sheetMenuOpen ? ' is-open' : ''}`}
          onClick={() => (sheetMenuOpen ? setSheetMenuOpen(false) : openSheetMenu())}
          title="Protocol command cheatsheets"
          aria-haspopup="menu"
          aria-expanded={sheetMenuOpen}
        >
          Cheatsheets <span className="btn-caret">▾</span>
        </button>
        <span className="netcat-status" data-state={status}>
          {statusLabel}
        </span>
        {connected ? (
          <button type="button" className="btn" onClick={disconnect}>
            Disconnect
          </button>
        ) : (
          <button
            ref={connectRef}
            type="button"
            className="btn btn--primary"
            onClick={connect}
            disabled={status === 'connecting'}
          >
            Connect
          </button>
        )}
      </div>

      <div className="netcat-term" ref={termRef} onScroll={onTermScroll}>
        {entries.length === 0 ? (
          <div className="netcat-empty">
            Connect to a host and port to start a session. Output appears here; send lines below.
          </div>
        ) : (
          entries.map((entry) => (
            <div className="netcat-line" key={entry.id} data-kind={entry.kind}>
              <span className="netcat-prefix">
                {entry.kind === 'out' ? '‹' : entry.kind === 'in' ? '›' : entry.kind === 'error' ? '!' : '·'}
              </span>
              <span className="netcat-text selectable">{entry.text}</span>
            </div>
          ))
        )}
      </div>

      <div className="netcat-input">
        <span className="input-prompt">›</span>
        <input
          ref={inputRef}
          className="input selectable"
          type="text"
          value={input}
          spellCheck={false}
          autoComplete="off"
          placeholder={connected ? 'type a line and press Enter' : 'not connected'}
          disabled={!connected}
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={onInputKeyDown}
        />
        <select
          className="netcat-ending"
          value={lineEnding}
          disabled={!connected}
          title="Line ending appended when sending"
          onChange={(event) => setLineEnding(event.target.value as LineEnding)}
        >
          <option value="lf">LF</option>
          <option value="crlf">CRLF</option>
          <option value="none">none</option>
        </select>
        <button type="button" className="btn" onClick={send} disabled={!connected}>
          Send
        </button>
      </div>

      {sheetMenuOpen && (
        <ContextMenu
          x={sheetMenuPos.x}
          y={sheetMenuPos.y}
          title="CHEATSHEETS"
          items={CHEATSHEETS.map((sheet) => ({
            label: sheet.title,
            hint: sheet.port,
            onSelect: () => onOpenCheatsheet(sheet.id),
          }))}
          onClose={() => setSheetMenuOpen(false)}
        />
      )}
    </div>
  );
};

export default NetcatPanel;
