import type { FeatureCollection, Geometry, Position } from 'geojson';

// Leaflet's GeoJSON renderer does not cut polygons at the antimeridian, so a
// ring with a segment spanning more than 180° of longitude is drawn the long
// way around the world (a visible band across the map). Natural Earth ships
// Fiji, Russia and Antarctica that way. We split those rings into equivalent
// pieces that stay inside [-180, 180] before handing the data to Leaflet.

type Ring = Position[];

const LON_MIN = -180;
const LON_MAX = 180;
const LAT_MIN = -90;
const LAT_MAX = 90;
const EPSILON = 1e-9;

/** Make a ring's longitudes continuous so consecutive points never jump >180°. */
function unwrapRing(ring: Ring): Ring {
  const pts = ring.length > 1 ? ring.slice(0, -1) : ring;
  if (pts.length === 0) {
    return [];
  }
  const out: Ring = [[pts[0][0], pts[0][1]]];
  for (let i = 1; i < pts.length; i += 1) {
    let lon = pts[i][0];
    const prev = out[i - 1][0];
    while (lon - prev > 180) lon -= 360;
    while (prev - lon > 180) lon += 360;
    out.push([lon, pts[i][1]]);
  }
  return out;
}

function shiftedRing(ring: Ring, shift: number): Ring {
  if (shift === 0) {
    return ring;
  }
  return ring.map((p) => [p[0] + shift, p[1]] as Position);
}

function intersectLon(a: Position, b: Position, lon: number): Position {
  const t = (lon - a[0]) / (b[0] - a[0]);
  return [lon, a[1] + t * (b[1] - a[1])];
}

function intersectLat(a: Position, b: Position, lat: number): Position {
  const t = (lat - a[1]) / (b[1] - a[1]);
  return [a[0] + t * (b[0] - a[0]), lat];
}

/** Sutherland–Hodgman clip of one ring against an axis-aligned half-plane. */
function clipRing(
  ring: Ring,
  inside: (p: Position) => boolean,
  intersect: (a: Position, b: Position) => Position,
): Ring {
  if (ring.length === 0) {
    return [];
  }
  const out: Ring = [];
  for (let i = 0; i < ring.length; i += 1) {
    const cur = ring[i];
    const prev = ring[(i + ring.length - 1) % ring.length];
    const curIn = inside(cur);
    const prevIn = inside(prev);
    if (curIn) {
      if (!prevIn) {
        out.push(intersect(prev, cur));
      }
      out.push([cur[0], cur[1]]);
    } else if (prevIn) {
      out.push(intersect(prev, cur));
    }
  }
  return out;
}

function clipRect(ring: Ring): Ring {
  let out = ring;
  out = clipRing(out, (p) => p[0] >= LON_MIN, (a, b) => intersectLon(a, b, LON_MIN));
  out = clipRing(out, (p) => p[0] <= LON_MAX, (a, b) => intersectLon(a, b, LON_MAX));
  out = clipRing(out, (p) => p[1] >= LAT_MIN, (a, b) => intersectLat(a, b, LAT_MIN));
  out = clipRing(out, (p) => p[1] <= LAT_MAX, (a, b) => intersectLat(a, b, LAT_MAX));
  return out;
}

/** Drop consecutive duplicates and re-close a ring (GeoJSON rings are closed). */
function closeRing(ring: Ring): Ring {
  const out: Ring = [];
  for (const p of ring) {
    const last = out[out.length - 1];
    if (!last || Math.abs(last[0] - p[0]) > EPSILON || Math.abs(last[1] - p[1]) > EPSILON) {
      out.push([p[0], p[1]]);
    }
  }
  if (out.length >= 2) {
    const first = out[0];
    const last = out[out.length - 1];
    if (Math.abs(first[0] - last[0]) > EPSILON || Math.abs(first[1] - last[1]) > EPSILON) {
      out.push([first[0], first[1]]);
    }
  }
  return out;
}

function ringArea(ring: Ring): number {
  let area = 0;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i, i += 1) {
    area += ring[j][0] * ring[i][1] - ring[i][0] * ring[j][1];
  }
  return Math.abs(area) / 2;
}

/** Split one polygon (exterior ring first, then holes) into antimeridian-safe polygons. */
function splitPolygon(rings: Ring[]): Position[][][] {
  const unwrapped = rings.map(unwrapRing);
  const exterior = unwrapped[0];
  if (!exterior || exterior.length < 3) {
    return [];
  }

  let minLon = Infinity;
  let maxLon = -Infinity;
  for (const p of exterior) {
    if (p[0] < minLon) minLon = p[0];
    if (p[0] > maxLon) maxLon = p[0];
  }

  const firstShift = Math.ceil((LON_MIN - maxLon) / 360);
  const lastShift = Math.floor((LON_MAX - minLon) / 360);
  const polygons: Position[][][] = [];

  for (let k = firstShift; k <= lastShift; k += 1) {
    const shift = k * 360;
    const outer = closeRing(clipRect(shiftedRing(exterior, shift)));
    if (outer.length < 4 || ringArea(outer) < EPSILON) {
      continue;
    }
    const holes: Ring[] = [];
    for (let h = 1; h < unwrapped.length; h += 1) {
      const hole = closeRing(clipRect(shiftedRing(unwrapped[h], shift)));
      if (hole.length >= 4 && ringArea(hole) >= EPSILON) {
        holes.push(hole);
      }
    }
    polygons.push([outer, ...holes]);
  }

  return polygons;
}

export function splitAntimeridian<P>(
  fc: FeatureCollection<Geometry, P>,
): FeatureCollection<Geometry, P> {
  return {
    ...fc,
    features: fc.features.map((feature) => {
      const geometry = feature.geometry;
      if (!geometry) {
        return feature;
      }
      if (geometry.type === 'Polygon') {
        const coordinates = splitPolygon(geometry.coordinates as Ring[]);
        return { ...feature, geometry: { type: 'MultiPolygon', coordinates } };
      }
      if (geometry.type === 'MultiPolygon') {
        const coordinates = geometry.coordinates.flatMap((rings) => splitPolygon(rings as Ring[]));
        return { ...feature, geometry: { type: 'MultiPolygon', coordinates } };
      }
      return feature;
    }),
  };
}
