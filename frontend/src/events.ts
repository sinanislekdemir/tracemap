// Event names emitted by the Go backend (see the Event* constants in app.go).
// They live in one module so the backend and every subscriber cannot drift.
export const EVENT_HOP = 'trace:hop';
export const EVENT_GEO = 'trace:geo';
export const EVENT_TARGET = 'trace:target';
export const EVENT_TARGET_GEO = 'trace:targetGeo';
export const EVENT_DONE = 'trace:done';
export const EVENT_ERROR = 'trace:error';

export const EVENT_SCAN_RECORDS = 'scan:records';
export const EVENT_SCAN_TARGETS = 'scan:targets';
export const EVENT_SCAN_DONE = 'scan:done';
export const EVENT_SUBDOMAINS = 'scan:subdomains';
export const EVENT_SUBDOMAIN_LOG = 'scan:subdomainLog';
export const EVENT_SCAN_PROGRESS = 'scan:progress';
export const EVENT_CRAWL_PAGE = 'scan:crawlPage';
export const EVENT_CRAWL = 'scan:crawl';
export const EVENT_CRAWL_LOG = 'scan:crawlLog';

export const EVENT_PORT_OPEN = 'portscan:open';
export const EVENT_PORT_PROGRESS = 'portscan:progress';
export const EVENT_PORT_DONE = 'portscan:done';
export const EVENT_PORT_ERROR = 'portscan:error';

export const EVENT_NET_DATA = 'net:data';
export const EVENT_NET_CLOSED = 'net:closed';
export const EVENT_NET_ERROR = 'net:error';

export const EVENT_DOMAIN_PROGRESS = 'domain:progress';

export const EVENT_ORIGIN_PROGRESS = 'origin:progress';
export const EVENT_ORIGIN_LOG = 'origin:log';
