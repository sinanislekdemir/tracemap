export interface GeoData {
  lat: number;
  lon: number;
  city: string;
  country: string;
  asn: string;
  resolved: boolean;
}

export interface HopData {
  hop: number;
  ip?: string;
  rttMs?: number;
  geo?: GeoData;
  isTarget?: boolean;
  sharedCount?: number;
}

export interface HopEvent {
  target: number;
  hop: number;
  ip?: string;
  rttMs?: number;
}

export interface GeoEvent {
  target: number;
  hop: number;
  geo: GeoData;
}

export interface TargetEvent {
  target: number;
  ip: string;
}

export interface TargetGeoEvent {
  target: number;
  geo: GeoData;
}

export interface DoneEvent {
  target: number;
  hops: number;
}

export interface ErrorEvent {
  target: number;
  message: string;
}

export interface DNSRecord {
  type: string;
  name: string;
  value: string;
  priority?: number;
}

export interface ScanTarget {
  id: number;
  kind: string;
  label: string;
  ip: string;
}

export interface ScanOptions {
  expandNs: boolean;
  bruteForce: boolean;
  ptr: boolean;
  sweep24: boolean;
  services: boolean;
  autoTrace: boolean;
  maxTargets: number;
}

export interface SubdomainResult {
  name: string;
  source: string;
  ips: string[];
}

export interface ScanProgressEvent {
  phase: string;
  done: number;
  total: number;
  found: number;
}

export type LogLevel = 'info' | 'ok' | 'warn' | 'error';

export interface LogLine {
  id: number;
  time: number;
  level: LogLevel;
  text: string;
}

export interface TraceState {
  id: number;
  label: string;
  kind?: string;
  ip?: string;
  color: string;
  targetIp?: string;
  targetGeo?: GeoData;
  hops: HopData[];
  error?: string;
  done?: boolean;
}

export interface HistorySummary {
  id: number;
  kind: string;
  label: string;
  createdAt: number;
  traceCount: number;
  hopCount: number;
}

export interface HistoryHop {
  hop: number;
  ip?: string;
  rttMs?: number;
  geo?: GeoData;
  isTarget?: boolean;
}

export interface HistoryTrace {
  label: string;
  kind?: string;
  ip?: string;
  targetIp?: string;
  targetGeo?: GeoData;
  hops: HistoryHop[];
  error?: string;
}

export interface HistoryEntry {
  id: number;
  kind: string;
  label: string;
  createdAt: number;
  maxHops: number;
  traces: HistoryTrace[];
}
