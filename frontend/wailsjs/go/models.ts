export namespace domaincheck {
	
	export class Check {
	    id: string;
	    category: string;
	    title: string;
	    status: string;
	    detail: string;
	
	    static createFrom(source: any = {}) {
	        return new Check(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.category = source["category"];
	        this.title = source["title"];
	        this.status = source["status"];
	        this.detail = source["detail"];
	    }
	}
	export class DNSRecord {
	    type: string;
	    name: string;
	    value: string;
	
	    static createFrom(source: any = {}) {
	        return new DNSRecord(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.name = source["name"];
	        this.value = source["value"];
	    }
	}
	export class DNSReport {
	    records: DNSRecord[];
	    txt: string[];
	    spf: string[];
	    spfPolicy?: string;
	    spfLookups: number;
	    dmarc: string[];
	    dmarcPolicy?: string;
	    dmarcRua?: string[];
	    dkim: string[];
	    mtaSts?: string[];
	    tlsRpt?: string[];
	    caa: string[];
	    dnsKey: boolean;
	    ds: boolean;
	    nameservers: string[];
	    mx: string[];
	    addresses: string[];
	
	    static createFrom(source: any = {}) {
	        return new DNSReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.records = this.convertValues(source["records"], DNSRecord);
	        this.txt = source["txt"];
	        this.spf = source["spf"];
	        this.spfPolicy = source["spfPolicy"];
	        this.spfLookups = source["spfLookups"];
	        this.dmarc = source["dmarc"];
	        this.dmarcPolicy = source["dmarcPolicy"];
	        this.dmarcRua = source["dmarcRua"];
	        this.dkim = source["dkim"];
	        this.mtaSts = source["mtaSts"];
	        this.tlsRpt = source["tlsRpt"];
	        this.caa = source["caa"];
	        this.dnsKey = source["dnsKey"];
	        this.ds = source["ds"];
	        this.nameservers = source["nameservers"];
	        this.mx = source["mx"];
	        this.addresses = source["addresses"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Registration {
	    found: boolean;
	    source?: string;
	    domain: string;
	    registrar?: string;
	    createdAt?: number;
	    updatedAt?: number;
	    expiresAt?: number;
	    ageDays: number;
	    daysToExpiry: number;
	    statuses?: string[];
	    nameservers?: string[];
	    registrant?: string;
	    country?: string;
	    dnssec?: string;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new Registration(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.found = source["found"];
	        this.source = source["source"];
	        this.domain = source["domain"];
	        this.registrar = source["registrar"];
	        this.createdAt = source["createdAt"];
	        this.updatedAt = source["updatedAt"];
	        this.expiresAt = source["expiresAt"];
	        this.ageDays = source["ageDays"];
	        this.daysToExpiry = source["daysToExpiry"];
	        this.statuses = source["statuses"];
	        this.nameservers = source["nameservers"];
	        this.registrant = source["registrant"];
	        this.country = source["country"];
	        this.dnssec = source["dnssec"];
	        this.error = source["error"];
	    }
	}
	export class WebReport {
	    url: string;
	    https: boolean;
	    httpStatus?: number;
	    redirectsHttps: boolean;
	    tlsVersion?: string;
	    certSubject?: string;
	    certIssuer?: string;
	    certNotBefore?: number;
	    certNotAfter?: number;
	    certDaysLeft: number;
	    headers?: Record<string, string>;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new WebReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.url = source["url"];
	        this.https = source["https"];
	        this.httpStatus = source["httpStatus"];
	        this.redirectsHttps = source["redirectsHttps"];
	        this.tlsVersion = source["tlsVersion"];
	        this.certSubject = source["certSubject"];
	        this.certIssuer = source["certIssuer"];
	        this.certNotBefore = source["certNotBefore"];
	        this.certNotAfter = source["certNotAfter"];
	        this.certDaysLeft = source["certDaysLeft"];
	        this.headers = source["headers"];
	        this.error = source["error"];
	    }
	}
	export class Report {
	    domain: string;
	    analyzedAt: number;
	    score: number;
	    grade: string;
	    checks: Check[];
	    registration?: Registration;
	    dns: DNSReport;
	    web: WebReport;
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.domain = source["domain"];
	        this.analyzedAt = source["analyzedAt"];
	        this.score = source["score"];
	        this.grade = source["grade"];
	        this.checks = this.convertValues(source["checks"], Check);
	        this.registration = this.convertValues(source["registration"], Registration);
	        this.dns = this.convertValues(source["dns"], DNSReport);
	        this.web = this.convertValues(source["web"], WebReport);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace geolocator {
	
	export class GeoData {
	    lat: number;
	    lon: number;
	    city: string;
	    country: string;
	    asn: string;
	    resolved: boolean;
	
	    static createFrom(source: any = {}) {
	        return new GeoData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.lat = source["lat"];
	        this.lon = source["lon"];
	        this.city = source["city"];
	        this.country = source["country"];
	        this.asn = source["asn"];
	        this.resolved = source["resolved"];
	    }
	}

}

export namespace history {
	
	export class Hop {
	    hop: number;
	    ip?: string;
	    rttMs?: number;
	    geo?: Geo;
	    isTarget?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Hop(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hop = source["hop"];
	        this.ip = source["ip"];
	        this.rttMs = source["rttMs"];
	        this.geo = this.convertValues(source["geo"], Geo);
	        this.isTarget = source["isTarget"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Geo {
	    lat: number;
	    lon: number;
	    city: string;
	    country: string;
	    asn: string;
	    resolved: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Geo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.lat = source["lat"];
	        this.lon = source["lon"];
	        this.city = source["city"];
	        this.country = source["country"];
	        this.asn = source["asn"];
	        this.resolved = source["resolved"];
	    }
	}
	export class Trace {
	    label: string;
	    kind?: string;
	    ip?: string;
	    targetIp?: string;
	    targetGeo?: Geo;
	    hops: Hop[];
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new Trace(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.kind = source["kind"];
	        this.ip = source["ip"];
	        this.targetIp = source["targetIp"];
	        this.targetGeo = this.convertValues(source["targetGeo"], Geo);
	        this.hops = this.convertValues(source["hops"], Hop);
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Entry {
	    id: number;
	    kind: string;
	    label: string;
	    createdAt: number;
	    maxHops: number;
	    traces: Trace[];
	
	    static createFrom(source: any = {}) {
	        return new Entry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.kind = source["kind"];
	        this.label = source["label"];
	        this.createdAt = source["createdAt"];
	        this.maxHops = source["maxHops"];
	        this.traces = this.convertValues(source["traces"], Trace);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class Summary {
	    id: number;
	    kind: string;
	    label: string;
	    createdAt: number;
	    traceCount: number;
	    hopCount: number;
	
	    static createFrom(source: any = {}) {
	        return new Summary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.kind = source["kind"];
	        this.label = source["label"];
	        this.createdAt = source["createdAt"];
	        this.traceCount = source["traceCount"];
	        this.hopCount = source["hopCount"];
	    }
	}

}

export namespace main {
	
	export class HistorySaveRequest {
	    kind: string;
	    label: string;
	    maxHops: number;
	    traces: history.Trace[];
	
	    static createFrom(source: any = {}) {
	        return new HistorySaveRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.kind = source["kind"];
	        this.label = source["label"];
	        this.maxHops = source["maxHops"];
	        this.traces = this.convertValues(source["traces"], history.Trace);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class NetConnectRequest {
	    host: string;
	    port: number;
	    timeoutMs: number;
	    tls: boolean;
	    serverName: string;
	
	    static createFrom(source: any = {}) {
	        return new NetConnectRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.port = source["port"];
	        this.timeoutMs = source["timeoutMs"];
	        this.tls = source["tls"];
	        this.serverName = source["serverName"];
	    }
	}
	export class NetSession {
	    id: string;
	    host: string;
	    port: number;
	    tls: boolean;
	    local?: string;
	    remote?: string;
	
	    static createFrom(source: any = {}) {
	        return new NetSession(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.tls = source["tls"];
	        this.local = source["local"];
	        this.remote = source["remote"];
	    }
	}
	export class PortScanRow {
	    host: string;
	    label?: string;
	    port: number;
	    protocol: string;
	    service?: string;
	    product?: string;
	    detail?: string;
	    banner?: string;
	    tls?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new PortScanRow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.label = source["label"];
	        this.port = source["port"];
	        this.protocol = source["protocol"];
	        this.service = source["service"];
	        this.product = source["product"];
	        this.detail = source["detail"];
	        this.banner = source["banner"];
	        this.tls = source["tls"];
	    }
	}
	export class PortScanTargetInfo {
	    label: string;
	    host: string;
	
	    static createFrom(source: any = {}) {
	        return new PortScanTargetInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.host = source["host"];
	    }
	}
	export class PortScanReport {
	    target: string;
	    scope: string;
	    startedAt: number;
	    durationMs: number;
	    protocol: string;
	    ports: string;
	    portCount: number;
	    probe: boolean;
	    concurrency: number;
	    timeoutMs: number;
	    scanned: number;
	    open: number;
	    targets: number;
	    resolvedTargets: PortScanTargetInfo[];
	    rows: PortScanRow[];
	
	    static createFrom(source: any = {}) {
	        return new PortScanReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = source["target"];
	        this.scope = source["scope"];
	        this.startedAt = source["startedAt"];
	        this.durationMs = source["durationMs"];
	        this.protocol = source["protocol"];
	        this.ports = source["ports"];
	        this.portCount = source["portCount"];
	        this.probe = source["probe"];
	        this.concurrency = source["concurrency"];
	        this.timeoutMs = source["timeoutMs"];
	        this.scanned = source["scanned"];
	        this.open = source["open"];
	        this.targets = source["targets"];
	        this.resolvedTargets = this.convertValues(source["resolvedTargets"], PortScanTargetInfo);
	        this.rows = this.convertValues(source["rows"], PortScanRow);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PortScanTarget {
	    label: string;
	    host: string;
	
	    static createFrom(source: any = {}) {
	        return new PortScanTarget(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.host = source["host"];
	    }
	}
	export class PortScanRequest {
	    host: string;
	    targets: PortScanTarget[];
	    protocol: string;
	    preset: string;
	    portRange: string;
	    concurrency: number;
	    timeoutMs: number;
	    probe: boolean;
	
	    static createFrom(source: any = {}) {
	        return new PortScanRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.targets = this.convertValues(source["targets"], PortScanTarget);
	        this.protocol = source["protocol"];
	        this.preset = source["preset"];
	        this.portRange = source["portRange"];
	        this.concurrency = source["concurrency"];
	        this.timeoutMs = source["timeoutMs"];
	        this.probe = source["probe"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	export class ScanOptions {
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
	
	    static createFrom(source: any = {}) {
	        return new ScanOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.expandNs = source["expandNs"];
	        this.bruteForce = source["bruteForce"];
	        this.wordlistPath = source["wordlistPath"];
	        this.ptr = source["ptr"];
	        this.sweep24 = source["sweep24"];
	        this.services = source["services"];
	        this.crawl = source["crawl"];
	        this.crawlMaxPages = source["crawlMaxPages"];
	        this.autoTrace = source["autoTrace"];
	        this.maxTargets = source["maxTargets"];
	    }
	}
	export class ScanRequest {
	    domain: string;
	    maxHops: number;
	    options: ScanOptions;
	
	    static createFrom(source: any = {}) {
	        return new ScanRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.domain = source["domain"];
	        this.maxHops = source["maxHops"];
	        this.options = this.convertValues(source["options"], ScanOptions);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ToolStatus {
	    available: boolean;
	    tool?: string;
	    message?: string;
	    hint?: string;
	
	    static createFrom(source: any = {}) {
	        return new ToolStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.available = source["available"];
	        this.tool = source["tool"];
	        this.message = source["message"];
	        this.hint = source["hint"];
	    }
	}
	export class TraceRequest {
	    target: string;
	    maxHops: number;
	
	    static createFrom(source: any = {}) {
	        return new TraceRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = source["target"];
	        this.maxHops = source["maxHops"];
	    }
	}
	export class TraceTargetsRequest {
	    domain: string;
	    maxHops: number;
	    hosts: string[];
	
	    static createFrom(source: any = {}) {
	        return new TraceTargetsRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.domain = source["domain"];
	        this.maxHops = source["maxHops"];
	        this.hosts = source["hosts"];
	    }
	}
	export class UnmaskRulesInfo {
	    path: string;
	    exists: boolean;
	
	    static createFrom(source: any = {}) {
	        return new UnmaskRulesInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.exists = source["exists"];
	    }
	}

}

export namespace origin {
	
	export class CertInfo {
	    sha256: string;
	    subject?: string;
	    issuer?: string;
	    sans?: string[];
	    notAfter?: number;
	
	    static createFrom(source: any = {}) {
	        return new CertInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sha256 = source["sha256"];
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.sans = source["sans"];
	        this.notAfter = source["notAfter"];
	    }
	}
	export class Baseline {
	    proxiedIps: string[];
	    proxied: boolean;
	    markers?: string[];
	    cert: CertInfo;
	    status: number;
	    headers?: Record<string, string>;
	    faviconSha?: string;
	    bodySha?: string;
	
	    static createFrom(source: any = {}) {
	        return new Baseline(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.proxiedIps = source["proxiedIps"];
	        this.proxied = source["proxied"];
	        this.markers = source["markers"];
	        this.cert = this.convertValues(source["cert"], CertInfo);
	        this.status = source["status"];
	        this.headers = source["headers"];
	        this.faviconSha = source["faviconSha"];
	        this.bodySha = source["bodySha"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Candidate {
	    ip: string;
	    hostnames?: string[];
	    sources: string[];
	
	    static createFrom(source: any = {}) {
	        return new Candidate(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.hostnames = source["hostnames"];
	        this.sources = source["sources"];
	    }
	}
	
	export class Evidence {
	    certMatch: boolean;
	    faviconMatch: boolean;
	    bodyMatch: boolean;
	    statusMatch: boolean;
	    proxyHeaders?: string[];
	    sniVariance: boolean;
	    fanIn: number;
	
	    static createFrom(source: any = {}) {
	        return new Evidence(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.certMatch = source["certMatch"];
	        this.faviconMatch = source["faviconMatch"];
	        this.bodyMatch = source["bodyMatch"];
	        this.statusMatch = source["statusMatch"];
	        this.proxyHeaders = source["proxyHeaders"];
	        this.sniVariance = source["sniVariance"];
	        this.fanIn = source["fanIn"];
	    }
	}
	export class Origin {
	    ip: string;
	    verdict: string;
	    score: number;
	    ports?: number[];
	    cert: CertInfo;
	    evidence: Evidence;
	    geo: geolocator.GeoData;
	    note?: string;
	
	    static createFrom(source: any = {}) {
	        return new Origin(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.verdict = source["verdict"];
	        this.score = source["score"];
	        this.ports = source["ports"];
	        this.cert = this.convertValues(source["cert"], CertInfo);
	        this.evidence = this.convertValues(source["evidence"], Evidence);
	        this.geo = this.convertValues(source["geo"], geolocator.GeoData);
	        this.note = source["note"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Report {
	    domain: string;
	    baseline: Baseline;
	    candidates: Candidate[];
	    origins: Origin[];
	    notes?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.domain = source["domain"];
	        this.baseline = this.convertValues(source["baseline"], Baseline);
	        this.candidates = this.convertValues(source["candidates"], Candidate);
	        this.origins = this.convertValues(source["origins"], Origin);
	        this.notes = source["notes"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

