import type { HopData, TraceState } from './types';

// isLocated reports whether a hop has usable coordinates. (0, 0) is the null
// island and means "no coordinates".
export function isLocated(hop: HopData): boolean {
  const geo = hop.geo;
  if (!geo || !geo.resolved) {
    return false;
  }
  if (!Number.isFinite(geo.lat) || !Number.isFinite(geo.lon)) {
    return false;
  }
  return geo.lat !== 0 || geo.lon !== 0;
}

// The traceroute header reports the address the target resolved to. Ensure it is
// always present as the final entry: mark the hop that already holds it, or
// append a synthetic target row when the trace never reached it.
export function buildDisplayHops(trace: TraceState): HopData[] {
  if (!trace.targetIp) {
    return trace.hops;
  }

  let matchIndex = -1;
  trace.hops.forEach((hop, index) => {
    if (hop.ip === trace.targetIp) {
      matchIndex = index;
    }
  });

  if (matchIndex !== -1) {
    return trace.hops.map((hop, index) => (index === matchIndex ? { ...hop, isTarget: true } : hop));
  }

  const nextHop = trace.hops.length > 0 ? Math.max(...trace.hops.map((hop) => hop.hop)) + 1 : 1;
  return [...trace.hops, { hop: nextHop, ip: trace.targetIp, geo: trace.targetGeo, isTarget: true }];
}
