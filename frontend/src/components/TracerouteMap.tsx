import { Fragment, useEffect, useState } from 'react';
import {
  CircleMarker,
  MapContainer,
  Marker,
  Polyline,
  Popup,
  ScaleControl,
  TileLayer,
  useMap,
} from 'react-leaflet';
import { divIcon } from 'leaflet';
import type { LatLngBoundsExpression, LatLngExpression } from 'leaflet';
import { buildDisplayHops, isLocated } from '../traces';
import type { HopData, OriginMarker, TraceState } from '../types';

interface TracerouteMapProps {
  traces: TraceState[];
  selectedTraces: Set<number>;
  focusedTrace: number | null;
  selectedHop: number | null;
  onToggleTrace: (id: number) => void;
  onSelectHop: (hop: number) => void;
  onContextMenu?: (host: string, label: string, x: number, y: number) => void;
  sharedHops?: Map<string, number>;
  origins?: OriginMarker[];
}

const DEFAULT_CENTER: LatLngExpression = [25, 10];
const DEFAULT_ZOOM = 2;

const TILE_URL = 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';
const TILE_ATTRIBUTION =
  '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors';

// originIcon marks a confirmed/likely origin discovered by "Unmask target".
const originIcon = divIcon({
  className: 'origin-marker',
  html: '🏢',
  iconSize: [28, 28],
  iconAnchor: [14, 14],
  popupAnchor: [0, -14],
});

type Coord = [number, number];

interface Located {
  hop: HopData;
  position: Coord;
}

interface Rendered {
  trace: TraceState;
  hops: HopData[];
  located: Located[];
  coords: Coord[];
  route: Coord[];
}

/** Quadratic bezier between two coordinates, bowing consistently to one side. */
function curveSegment(a: Coord, b: Coord): Coord[] {
  const [lat1, lon1] = a;
  const [lat2, lon2] = b;
  const dx = lon2 - lon1;
  const dy = lat2 - lat1;
  const bow = 0.16;
  const cx = (lon1 + lon2) / 2 - dy * bow;
  const cy = (lat1 + lat2) / 2 + dx * bow;

  const steps = 20;
  const points: Coord[] = [];
  for (let i = 0; i <= steps; i += 1) {
    const t = i / steps;
    const mt = 1 - t;
    const lon = mt * mt * lon1 + 2 * mt * t * cx + t * t * lon2;
    const lat = mt * mt * lat1 + 2 * mt * t * cy + t * t * lat2;
    points.push([lat, lon]);
  }
  return points;
}

function buildRoute(points: Coord[]): Coord[] {
  if (points.length < 2) {
    return points;
  }
  const route: Coord[] = [points[0]];
  for (let i = 1; i < points.length; i += 1) {
    route.push(...curveSegment(points[i - 1], points[i]).slice(1));
  }
  return route;
}

function locate(hops: HopData[]): Located[] {
  return hops.flatMap((hop) => {
    if (!isLocated(hop) || !hop.geo) {
      return [];
    }
    return [{ hop, position: [hop.geo.lat, hop.geo.lon] as Coord }];
  });
}

function MapEffects({ positions, focus, focusActive }: { positions: Coord[]; focus: Coord | null; focusActive: boolean }) {
  const map = useMap();
  const key = JSON.stringify(positions);

  useEffect(() => {
    if (focusActive || positions.length === 0) {
      return;
    }
    if (positions.length === 1) {
      map.setView(positions[0], 6);
      return;
    }
    map.fitBounds(positions as LatLngBoundsExpression, { padding: [56, 56], maxZoom: 7 });
  }, [map, key, focusActive]);

  useEffect(() => {
    if (focus) {
      map.flyTo(focus, Math.max(map.getZoom(), 5), { duration: 0.7 });
    }
  }, [map, focus?.[0], focus?.[1]]);

  return null;
}

const TracerouteMap = ({
  traces,
  selectedTraces,
  focusedTrace,
  selectedHop,
  onToggleTrace,
  onSelectHop,
  onContextMenu,
  sharedHops,
  origins,
}: TracerouteMapProps) => {
  const [legendOpen, setLegendOpen] = useState(true);
  const visible = selectedTraces.size === 0 ? traces : traces.filter((trace) => selectedTraces.has(trace.id));

  const rendered: Rendered[] = visible.map((trace) => {
    const hops = buildDisplayHops(trace);
    const located = locate(hops);
    const coords = located.map((entry) => entry.position);
    return { trace, hops, located, coords, route: buildRoute(coords) };
  });

  const originCoords = (origins ?? []).map((origin) => [origin.lat, origin.lon] as Coord);
  const allCoords = [...rendered.flatMap((entry) => entry.coords), ...originCoords];
  const totalHops = rendered.reduce((sum, entry) => sum + entry.hops.length, 0);
  const totalLocated = rendered.reduce((sum, entry) => sum + entry.located.length, 0);

  const activeRendered = rendered.find((entry) => entry.trace.id === focusedTrace) ?? rendered[0];
  const focus = activeRendered?.located.find((entry) => entry.hop.hop === selectedHop)?.position ?? null;

  return (
    <div className="map-wrap">
      <div className="map-canvas">
        <MapContainer center={DEFAULT_CENTER} zoom={DEFAULT_ZOOM} scrollWheelZoom zoomControl attributionControl>
          <TileLayer attribution={TILE_ATTRIBUTION} url={TILE_URL} subdomains={['a', 'b', 'c']} />
          <ScaleControl position="bottomleft" imperial={false} />

          {rendered.map(({ trace, located, route }) => {
            const hasTarget = located.some((entry) => entry.hop.isTarget);
            return (
              <Fragment key={trace.id}>
                {route.length > 1 && (
                  <>
                    <Polyline
                      positions={route}
                      className="route-glow"
                      pathOptions={{
                        color: trace.color,
                        weight: 7,
                        opacity: 0.45,
                        lineCap: 'round',
                      }}
                    />
                    <Polyline
                      positions={route}
                      className="route-line"
                      pathOptions={{
                        color: trace.color,
                        weight: 2,
                        opacity: 0.95,
                        lineCap: 'round',
                      }}
                    />
                  </>
                )}

                {located.map(({ hop, position }, index) => {
                  const isLast = index === located.length - 1;
                  const isTarget = Boolean(hop.isTarget);
                  const isDest = isTarget || (!hasTarget && isLast);
                  const isOrigin = index === 0;
                  const shared = hop.ip ? sharedHops?.get(hop.ip) : undefined;
                  const dotClasses = ['hop-dot'];
                  if (isDest) dotClasses.push('hop-dot--dest');
                  if (shared) dotClasses.push('hop-dot--shared');
                  return (
                    <CircleMarker
                      key={`${trace.id}:${hop.hop}:${isDest}`}
                      center={position}
                      radius={isDest ? 6 : shared ? 6 : isOrigin ? 5 : 4}
                      className={dotClasses.join(' ')}
                      pathOptions={{
                        color: trace.color,
                        fillColor: isDest || isOrigin ? trace.color : '#0a2833',
                        fillOpacity: isDest ? 0.95 : isOrigin ? 0.9 : 0.8,
                        opacity: 1,
                        weight: shared ? 3 : 2,
                      }}
                      eventHandlers={{
                        click: () => {
                          onToggleTrace(trace.id);
                          onSelectHop(hop.hop);
                        },
                        contextmenu: (event) => {
                          if (!hop.ip) {
                            return;
                          }
                          event.originalEvent.preventDefault();
                          event.originalEvent.stopPropagation();
                          onContextMenu?.(hop.ip, trace.label, event.originalEvent.clientX, event.originalEvent.clientY);
                        },
                      }}
                    >
                      <Popup>
                        <b>{trace.label}</b>
                        <br />
                        HOP&nbsp;&nbsp;{hop.hop} · {hop.ip || 'unknown'}
                        <br />
                        RTT&nbsp;{hop.rttMs != null ? `${hop.rttMs.toFixed(1)} ms` : '—'}
                        <br />
                        LOC&nbsp;{hop.geo?.city || 'unknown'}
                        {hop.geo?.country ? ` (${hop.geo.country})` : ''}
                        <br />
                        ASN&nbsp;{hop.geo?.asn || 'unknown'}
                        {shared ? (
                          <>
                            <br />
                            SHARED&nbsp;×{shared}
                          </>
                        ) : null}
                      </Popup>
                    </CircleMarker>
                  );
                })}
              </Fragment>
            );
          })}

          {(origins ?? []).map((origin) => (
            <Marker key={`origin:${origin.ip}`} position={[origin.lat, origin.lon]} icon={originIcon}>
              <Popup>
                <b>🏢 ORIGIN</b>
                <br />
                {origin.ip}
                <br />
                {origin.label}
                <br />
                VERDICT&nbsp;{origin.verdict}
              </Popup>
            </Marker>
          ))}

          <MapEffects positions={allCoords} focus={focus} focusActive={selectedHop != null} />
        </MapContainer>

        <div className="map-legend">
          <button
            type="button"
            className="legend-title"
            onClick={() => setLegendOpen((open) => !open)}
            aria-expanded={legendOpen}
            title={legendOpen ? 'Collapse traces legend' : 'Expand traces legend'}
          >
            <span className="legend-caret">{legendOpen ? '▾' : '▸'}</span>
            TRACES
            <span className="legend-count">{traces.length}</span>
          </button>
          {legendOpen && (
            <>
              <div className="legend-rows">
                {traces.map((trace) => (
                  <button
                    key={trace.id}
                    type="button"
                    className={`legend-row${selectedTraces.has(trace.id) ? ' is-selected' : ''}`}
                    onClick={() => onToggleTrace(trace.id)}
                  >
                    <span className="legend-line" style={{ background: trace.color }} />
                    <span className="legend-label">{trace.label}</span>
                    <span className="legend-ip selectable">{trace.ip}</span>
                  </button>
                ))}
              </div>
              <div className="legend-hint">filled = endpoint · hollow = hop</div>
            </>
          )}
        </div>

        <div className="map-hud">
          <b>{totalLocated}</b>/{totalHops} LOCATED
          {sharedHops && sharedHops.size > 0 ? (
            <span className="map-hud-shared"> · {sharedHops.size} SHARED</span>
          ) : null}
          {origins && origins.length > 0 ? (
            <span className="map-hud-origin"> · {origins.length} ORIGIN</span>
          ) : null}
        </div>
      </div>
    </div>
  );
};

export default TracerouteMap;
