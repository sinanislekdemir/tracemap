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
	export class PortScanRequest {
	    host: string;
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
	        this.protocol = source["protocol"];
	        this.preset = source["preset"];
	        this.portRange = source["portRange"];
	        this.concurrency = source["concurrency"];
	        this.timeoutMs = source["timeoutMs"];
	        this.probe = source["probe"];
	    }
	}
	export class ScanOptions {
	    expandNs: boolean;
	    bruteForce: boolean;
	    ptr: boolean;
	    sweep24: boolean;
	    services: boolean;
	    autoTrace: boolean;
	    maxTargets: number;
	
	    static createFrom(source: any = {}) {
	        return new ScanOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.expandNs = source["expandNs"];
	        this.bruteForce = source["bruteForce"];
	        this.ptr = source["ptr"];
	        this.sweep24 = source["sweep24"];
	        this.services = source["services"];
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

}

