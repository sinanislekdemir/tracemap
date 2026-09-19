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
  code?: string;
  hint?: string;
}

export interface ToolStatus {
  available: boolean;
  tool?: string;
  message?: string;
  hint?: string;
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
  wordlistPath: string;
  ptr: boolean;
  sweep24: boolean;
  services: boolean;
  crawl: boolean;
  crawlMaxPages: number;
  autoTrace: boolean;
  maxTargets: number;
}

export interface CrawlPage {
  url: string;
  depth: number;
  status: number;
  contentType?: string;
  title?: string;
  size: number;
  truncated?: boolean;
  html?: string;
  links?: string[];
  hosts?: string[];
}

export interface CrawlRobots {
  url: string;
  status: number;
  body?: string;
  sitemaps?: string[];
  paths?: string[];
}

export interface CrawlSitemap {
  url: string;
  status: number;
  urls?: string[];
  nested?: string[];
}

export interface CrawlResult {
  pages: CrawlPage[];
  robots?: CrawlRobots;
  sitemaps?: CrawlSitemap[];
  subdomains?: { name: string; ips: string[] }[];
  urls?: string[];
}

export interface CrawlLogEvent {
  level: LogLevel;
  message: string;
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

export interface PortResult {
  port: number;
  protocol: string;
  service?: string;
  product?: string;
  banner?: string;
  detail?: string;
  tls?: boolean;
}

export interface PortScanProgress {
  host: string;
  done: number;
  total: number;
  open: number;
}

export interface PortScanDone {
  host: string;
  scanned: number;
  open: number;
}

export interface PortScanOptions {
  protocol: 'tcp' | 'udp';
  preset: 'top20' | 'top100' | 'top1000' | 'custom';
  portRange: string;
  concurrency: number;
  timeoutMs: number;
  probe: boolean;
}

export interface NetDataEvent {
  session: string;
  /** Raw bytes, base64-encoded by the Go JSON encoder. */
  data: string;
}

export interface NetClosedEvent {
  session: string;
  reason: string;
}

export type NetStatus = 'idle' | 'connecting' | 'connected' | 'closed' | 'error';

export type LogLevel = 'info' | 'ok' | 'warn' | 'error';

export interface LogLine {
  id: number;
  time: number;
  level: LogLevel;
  text: string;
  /** Terminal channel this line belongs to (e.g. "dns", "crawl", "netcat"). */
  channel: string;
}

/** Every scan step owns a terminal channel and its own floating window. */
export type TerminalKind =
  | 'console'
  | 'dns'
  | 'subdomains'
  | 'crawl'
  | 'trace'
  | 'ports'
  | 'origin'
  | 'netcat'
  | 'cheatsheet';

export interface FloatingWindowState {
  id: string;
  kind: TerminalKind;
  title: string;
  x: number;
  y: number;
  width: number;
  height: number;
  z: number;
  /** Netcat windows carry the host to connect to. */
  host?: string;
  nonce?: number;
  /** Cheatsheet windows carry the protocol sheet id to render. */
  sheet?: string;
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

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info';

export interface DomainProgressEvent {
  phase: string;
  message: string;
}

export interface OriginProgressEvent {
  phase: string;
  message: string;
}

export interface OriginLogEvent {
  level: LogLevel;
  message: string;
}

/** Location and existence of the user's unmask rules file. */
export interface UnmaskRulesInfo {
  path: string;
  exists: boolean;
}

/** A confirmed/likely origin placed on the map. */
export interface OriginMarker {
  ip: string;
  lat: number;
  lon: number;
  verdict: string;
  label: string;
}
