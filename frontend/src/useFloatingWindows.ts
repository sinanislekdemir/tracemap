import { useCallback, useRef, useState } from 'react';
import { nextZ } from './zorder';
import type { FloatingWindowState, TerminalKind } from './types';

interface OpenOptions {
  title?: string;
  host?: string;
  /** Cheatsheet protocol id; makes cheatsheet windows singleton per sheet. */
  sheet?: string;
  /** Singleton windows focus the existing window of the same kind. */
  singleton?: boolean;
}

const DEFAULT_SIZES: Record<TerminalKind, { width: number; height: number }> = {
  console: { width: 560, height: 320 },
  dns: { width: 470, height: 250 },
  subdomains: { width: 510, height: 300 },
  crawl: { width: 620, height: 360 },
  trace: { width: 540, height: 300 },
  ports: { width: 520, height: 300 },
  origin: { width: 640, height: 400 },
  netcat: { width: 640, height: 440 },
  cheatsheet: { width: 600, height: 480 },
};

export const MIN_WINDOW_WIDTH = 280;
export const MIN_WINDOW_HEIGHT = 160;

let sequence = 0;

/**
 * useFloatingWindows is a tiny window manager: it owns each window's position,
 * size and stacking order. Mutations read and write a ref synchronously so
 * opening a window right after closing one in the same tick behaves.
 */
export function useFloatingWindows() {
  const [windows, setWindows] = useState<FloatingWindowState[]>([]);
  const windowsRef = useRef<FloatingWindowState[]>([]);
  const cascadeRef = useRef(0);

  const commit = useCallback((next: FloatingWindowState[]) => {
    windowsRef.current = next;
    setWindows(next);
  }, []);

  const focus = useCallback(
    (id: string) => {
      const z = nextZ();
      commit(windowsRef.current.map((win) => (win.id === id ? { ...win, z } : win)));
    },
    [commit],
  );

  const open = useCallback(
    (kind: TerminalKind, options: OpenOptions = {}) => {
      const singleton = options.singleton ?? kind !== 'netcat';
      if (singleton) {
        const existing = windowsRef.current.find(
          (win) =>
            win.kind === kind && (options.sheet === undefined || win.sheet === options.sheet),
        );
        if (existing) {
          focus(existing.id);
          return;
        }
      }

      sequence += 1;
      const index = cascadeRef.current++;
      const size = DEFAULT_SIZES[kind] ?? { width: 520, height: 320 };
      const width = Math.min(size.width, Math.max(MIN_WINDOW_WIDTH, window.innerWidth - 80));
      const height = Math.min(size.height, Math.max(MIN_WINDOW_HEIGHT, window.innerHeight - 80));
      const step = index % 8;
      const offsetX = step * 56;
      const offsetY = (step % 3) * 48;
      const x = Math.max(8, Math.min(window.innerWidth - width - 16, 90 + offsetX));
      const y = Math.max(8, Math.min(window.innerHeight - height - 16, 68 + offsetY));

      const win: FloatingWindowState = {
        id: `${kind}-${sequence}`,
        kind,
        title: options.title ?? kind.toUpperCase(),
        x,
        y,
        width,
        height,
        z: nextZ(),
        host: options.host,
        nonce: options.host ? Date.now() : undefined,
        sheet: options.sheet,
      };
      commit([...windowsRef.current, win]);
    },
    [commit, focus],
  );

  const close = useCallback(
    (id: string) => {
      commit(windowsRef.current.filter((win) => win.id !== id));
    },
    [commit],
  );

  const move = useCallback(
    (id: string, x: number, y: number) => {
      commit(windowsRef.current.map((win) => (win.id === id ? { ...win, x, y } : win)));
    },
    [commit],
  );

  const resize = useCallback(
    (id: string, width: number, height: number) => {
      commit(
        windowsRef.current.map((win) =>
          win.id === id
            ? {
                ...win,
                width: Math.max(MIN_WINDOW_WIDTH, width),
                height: Math.max(MIN_WINDOW_HEIGHT, height),
              }
            : win,
        ),
      );
    },
    [commit],
  );

  const closeKinds = useCallback(
    (kinds: TerminalKind[]) => {
      commit(windowsRef.current.filter((win) => !kinds.includes(win.kind)));
    },
    [commit],
  );

  return { windows, open, close, focus, move, resize, closeKinds };
}
