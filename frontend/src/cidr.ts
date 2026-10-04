// IPv4 CIDR detection for the target box. When the box holds a CIDR block the
// app switches into block mode: Trace discovers the live hosts and traces them,
// and Scan opens the port scanner over the whole block. An optional ":ports"
// suffix (for example "10.0.0.0/24:22,80,443-445") selects the ports probed for
// liveness and scanned, instead of the built-in top-100 list. The grammar
// mirrors hostscan.ParseCIDR on the backend (IPv4 only) for the block part and
// portscan.ParsePorts for the port part, so both agree on what a block is.

export interface ParsedCIDR {
  /** Masked network address, e.g. "10.0.0.0". */
  network: string;
  /** Prefix length, 0-32. */
  prefix: number;
  /** Usable host count (network and broadcast excluded for /0-/30). */
  count: number;
  /**
   * Raw port specification from a ":ports" suffix, e.g. "22,80,443-445".
   * Undefined when the target has no explicit port list.
   */
  ports?: string;
  /** Number of distinct ports selected by ports (0 when ports is undefined). */
  portCount: number;
}

/** ipv4ToInt parses one decimal octet, returning null when it is out of range. */
function ipv4ToInt(part: string): number | null {
  if (!/^\d{1,3}$/.test(part)) {
    return null;
  }
  const value = Number(part);
  return value >= 0 && value <= 255 ? value : null;
}

/**
 * parsePortSpec validates a comma-separated port list (single ports and ranges,
 * e.g. "22,80,443-445") and returns the number of distinct ports it selects.
 * It returns null when the spec is empty or malformed, mirroring the backend's
 * portscan.ParsePorts grammar.
 */
function parsePortSpec(spec: string): number | null {
  const seen = new Set<number>();
  let entries = 0;
  for (const part of spec.split(',')) {
    const entry = part.trim();
    if (!entry) {
      continue;
    }
    entries += 1;
    const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(entry);
    if (!match) {
      return null;
    }
    const from = Number(match[1]);
    const to = match[2] != null ? Number(match[2]) : from;
    if (from < 1 || from > 65535 || to < 1 || to > 65535 || from > to) {
      return null;
    }
    for (let port = from; port <= to && seen.size < 65535; port += 1) {
      seen.add(port);
    }
  }
  if (entries === 0) {
    return null;
  }
  return seen.size;
}

/**
 * parseCIDR parses an IPv4 CIDR block such as "10.0.0.0/24" or "192.168.1.7/24",
 * with an optional ":ports" suffix such as "10.0.0.0/24:22,80,443-445". It
 * returns null when the input is not an IPv4 CIDR (a bare hostname, a bare IP,
 * IPv6 or malformed input) or when a present port suffix is malformed, so
 * callers can fall back to normal handling.
 */
export function parseCIDR(input: string): ParsedCIDR | null {
  const trimmed = input.trim();
  let block = trimmed;
  let ports: string | undefined;
  let portCount = 0;
  const colon = trimmed.indexOf(':');
  if (colon >= 0) {
    block = trimmed.slice(0, colon).trim();
    const spec = trimmed.slice(colon + 1).trim();
    const count = parsePortSpec(spec);
    if (count === null) {
      return null;
    }
    ports = spec;
    portCount = count;
  }
  const slash = block.lastIndexOf('/');
  if (slash <= 0 || slash === block.length - 1) {
    return null;
  }
  const address = block.slice(0, slash);
  const prefixText = block.slice(slash + 1);
  if (!/^\d{1,2}$/.test(prefixText)) {
    return null;
  }
  const prefix = Number(prefixText);
  if (prefix > 32) {
    return null;
  }

  const parts = address.split('.');
  if (parts.length !== 4) {
    return null;
  }
  const octets = parts.map(ipv4ToInt);
  if (octets.some((octet) => octet === null)) {
    return null;
  }

  const value = octets.reduce<number>((acc, octet) => (acc * 256 + (octet ?? 0)) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const networkValue = (value & mask) >>> 0;
  const network = [
    (networkValue >>> 24) & 255,
    (networkValue >>> 16) & 255,
    (networkValue >>> 8) & 255,
    networkValue & 255,
  ].join('.');

  const total = 2 ** (32 - prefix);
  const count = prefix >= 31 ? total : Math.max(0, total - 2);
  return { network, prefix, count, ports, portCount };
}

/** isCIDR reports whether input is a valid IPv4 CIDR block. */
export function isCIDR(input: string): boolean {
  return parseCIDR(input) !== null;
}
