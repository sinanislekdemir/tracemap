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

/** One deduplicated hop across the correlated paths (correlation mode). */
export interface CorrelatedHop {
  ip: string;
  /** Total appearances across the paths, revisits included. */
  count: number;
  /** Number of distinct paths the hop appears in. */
  paths: number;
  geo?: GeoData;
  isTarget?: boolean;
  position: [number, number];
  labels: string[];
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

/** A verbose step from IPv4 CIDR block discovery. */
export interface BlockLogEvent {
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
  /** True when an FTP service accepted an anonymous login, false when it
   * required authentication, undefined when not checked. */
  ftpAnonymous?: boolean;
}

/** One host in a multi-target port scan. */
export interface PortScanTarget {
  label: string;
  host: string;
}

/** An open port tagged with the target it was found on. */
export interface PortOpenEvent {
  host: string;
  label?: string;
  result: PortResult;
}

/** One open port as exported to a tab-separated report. */
export interface PortScanRow {
  host: string;
  label?: string;
  port: number;
  protocol: string;
  service?: string;
  product?: string;
  detail?: string;
  banner?: string;
  tls?: boolean;
  ftpAnonymous?: boolean;
}

export interface PortScanProgress {
  host: string;
  done: number;
  total: number;
  open: number;
  target: number;
  targets: number;
}

export interface PortScanDone {
  host: string;
  scanned: number;
  open: number;
  targets: number;
}

export interface PortScanOptions {
  protocol: 'tcp' | 'udp';
  preset: 'top20' | 'top100' | 'top1000' | 'custom';
  portRange: string;
  concurrency: number;
  timeoutMs: number;
  probe: boolean;
  scope: 'single' | 'all';
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
  /** Netcat windows carry the host/port/TLS to preload the connection form. */
  host?: string;
  port?: number;
  tls?: boolean;
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

/** One stored geolocation reply in the persistent cache. */
export interface GeoCacheEntry {
  ip: string;
  lat: number;
  lon: number;
  city: string;
  country: string;
  asn: string;
  fetchedAt: number;
  expired: boolean;
}

/** State of the persistent geolocation cache. */
export interface GeoCacheInfo {
  enabled: boolean;
  path: string;
  count: number;
}

/** The local GeoLite2 database backing the country IP block browser. */
export interface IPBlocksInfo {
  available: boolean;
  path?: string;
  database?: string;
  build?: string;
  ipVersion?: number;
  message?: string;
}

/** One country's share of the local database. */
export interface CountryBlockSummary {
  code: string;
  name: string;
  blocks: number;
  addresses: string;
}

/** A request for one page of a country's network blocks. */
export interface CountryBlocksQuery {
  country: string;
  family?: string;
  filter?: string;
  limit?: number;
}

/** One page of a country's network blocks. */
export interface CountryBlocksResult {
  country: string;
  family?: string;
  filter?: string;
  total: number;
  matched: number;
  addresses: string;
  blocks: string[];
  truncated: boolean;
}

/** Progress while the local database is walked. */
export interface IPBlocksProgressEvent {
  phase: string;
  done: number;
  total: number;
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

/** One response header in an endpoint analysis, tagged with its role. */
export interface HttpHeader {
  name: string;
  value: string;
  kind: string;
}

/** One Set-Cookie with its security flags and inferred technology. */
export interface HttpCookie {
  name: string;
  value?: string;
  domain?: string;
  path?: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  session: boolean;
  expires?: number;
  maxAge?: number;
  tech?: string;
  flags?: string[];
}

/** The interpreted caching policy of an endpoint. */
export interface HttpCache {
  cacheControl?: string;
  directives?: string[];
  pragma?: string;
  expires?: string;
  age: number;
  etag?: string;
  lastModified?: string;
  vary?: string[];
  public: boolean;
  private: boolean;
  noStore: boolean;
  noCache: boolean;
  maxAge: number;
  sMaxAge: number;
  cacheable: boolean;
  shared: boolean;
  cdn?: string;
}

/** One detected technology and the evidence for it. */
export interface HttpTech {
  name: string;
  category: string;
  evidence: string;
}

/** TLS handshake summary. */
export interface HttpTLS {
  version?: string;
  cipher?: string;
  alpn?: string;
  subject?: string;
  issuer?: string;
  sans?: string[];
  notAfter?: number;
  daysLeft: number;
}

/** One redirect hop. */
export interface HttpRedirect {
  from: string;
  to: string;
  status: number;
}

/** One item on the endpoint analysis checklist. */
export interface HttpCheck {
  id: string;
  category: string;
  title: string;
  status: CheckStatus;
  detail: string;
}

/** Full analysis of one HTTP endpoint. */
export interface HttpReport {
  url: string;
  finalUrl?: string;
  host?: string;
  status: number;
  https: boolean;
  contentType?: string;
  server?: string;
  headers?: HttpHeader[];
  checks: HttpCheck[];
  cookies?: HttpCookie[];
  caching: HttpCache;
  tech?: HttpTech[];
  tls?: HttpTLS;
  redirects?: HttpRedirect[];
  bodySize?: number;
  truncated?: boolean;
  error?: string;
  score: number;
  grade: string;
  analyzedAt: number;
}

/** An endpoint to analyze, with where it came from. */
export interface HttpEndpointTarget {
  url: string;
  label?: string;
  source?: string;
}

export interface HttpProgressEvent {
  url: string;
  done: number;
  total: number;
}

export interface HttpLogEvent {
  url: string;
  label?: string;
  level: LogLevel;
  message: string;
}
