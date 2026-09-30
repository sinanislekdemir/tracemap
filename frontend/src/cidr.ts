// IPv4 CIDR detection for the target box. When the box holds a CIDR block the
// app switches into block mode: Trace discovers the live hosts and traces them,
// and Scan opens the port scanner over the whole block. The grammar mirrors
// hostscan.ParseCIDR on the backend (IPv4 only) so both agree on what a block
// is.

export interface ParsedCIDR {
  /** Masked network address, e.g. "10.0.0.0". */
  network: string;
  /** Prefix length, 0-32. */
  prefix: number;
  /** Usable host count (network and broadcast excluded for /0-/30). */
  count: number;
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
 * parseCIDR parses an IPv4 CIDR block such as "10.0.0.0/24" or "192.168.1.7/24".
 * It returns null when the input is not an IPv4 CIDR (a bare hostname, a bare
 * IP, IPv6 or malformed input), so callers can fall back to normal handling.
 */
export function parseCIDR(input: string): ParsedCIDR | null {
  const trimmed = input.trim();
  const slash = trimmed.lastIndexOf('/');
  if (slash <= 0 || slash === trimmed.length - 1) {
    return null;
  }
  const address = trimmed.slice(0, slash);
  const prefixText = trimmed.slice(slash + 1);
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
  return { network, prefix, count };
}

/** isCIDR reports whether input is a valid IPv4 CIDR block. */
export function isCIDR(input: string): boolean {
  return parseCIDR(input) !== null;
}
