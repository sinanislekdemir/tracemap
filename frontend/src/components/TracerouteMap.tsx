import { Fragment, useEffect, useState } from 'react';
import {
  CircleMarker,
  GeoJSON,
  MapContainer,
  Marker,
  Polyline,
  Popup,
  ScaleControl,
  Tooltip,
  useMap,
} from 'react-leaflet';
import { divIcon } from 'leaflet';
import type { LatLngBoundsExpression, LatLngExpression } from 'leaflet';
import { buildDisplayHops, isLocated } from '../traces';
import { correlationColor } from '../colors';
import { formatCoords } from '../format';
import OsmLink from './OsmLink';
import cities from '../assets/cities.json';
import { countries, land } from '../world';
import type { CorrelatedHop, HopData, OriginMarker, TraceState } from '../types';

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
  theme: 'dark' | 'light';
  /** Correlation mode: draw deduplicated hops instead of per-trace routes. */
  correlate?: boolean;
  correlated?: CorrelatedHop[];
}

const DEFAULT_CENTER: LatLngExpression = [25, 10];
const DEFAULT_ZOOM = 2;
const MAX_ZOOM = 8;

// City labels stay hidden at world zoom and only appear once the map is
// close enough that they don't overlap; below that only the dots show.
const LABEL_ZOOM = 3;
const ALL_LABELS_ZOOM = 5;
const MAJOR_POP = 2_000_000;

// Leaflet draws the vector basemap with inline SVG attributes, so the colours
// cannot come from CSS variables; keep a small palette per theme instead. The
// sea colour lives in CSS (`--map-sea`) and must stay in sync with `land`.
const MAP_COLORS = {
  dark: {
    land: '#182630',
    coast: '#3a5a73',
    border: '#243b4d',
    dot: '#7d9bb0',
    hopFill: '#0a2833',
  },
  light: {
    land: '#f5f8fb',
    coast: '#9db4c8',
    border: '#c3d0dc',
    dot: '#8fa6b8',
    hopFill: '#d8e4ee',
  },
};

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

/** Major-world-city reference dots; names appear only when zoomed in. */
function CityLayer({ dotColor }: { dotColor: string }) {
  const map = useMap();
  const [zoom, setZoom] = useState(map.getZoom());

  useEffect(() => {
    const onZoom = () => setZoom(map.getZoom());
    map.on('zoomend', onZoom);
    return () => {
      map.off('zoomend', onZoom);
    };
  }, [map]);

  const showAll = zoom >= ALL_LABELS_ZOOM;
  const showMajor = zoom >= LABEL_ZOOM;

  return (
    <>
      {cities.map((city) => {
        const label = showAll || (showMajor && (city.worldcity || city.pop >= MAJOR_POP));
        return (
          <CircleMarker
            key={`city:${city.name}:${city.lat}:${city.lon}`}
            center={[city.lat, city.lon]}
            radius={showAll ? 2 : 1.6}
            interactive={false}
            className="city-dot"
            pathOptions={{ color: dotColor, fillColor: dotColor, fillOpacity: 0.7, weight: 0 }}
          >
            {label ? (
              <Tooltip permanent direction="right" offset={[3, 0]} className="city-label">
                {city.name}
              </Tooltip>
            ) : null}
          </CircleMarker>
        );
      })}
    </>
  );
}

function MapEffects({ positions, focus, focusActive }: { positions: Coord[]; focus: Coord | null; focusActive: boolean }) {
  const map = useMap();
  const key = JSON.stringify(positions);

  useEffect(() => {
    if (focusActive || positions.length === 0) {
      return;
    }
    if (positions.length === 1) {
      map.setView(positions[0], 4);
      return;
    }
    map.fitBounds(positions as LatLngBoundsExpression, { padding: [56, 56], maxZoom: 5 });
  }, [map, key, focusActive]);

  useEffect(() => {
    if (focus) {
      map.flyTo(focus, Math.max(map.getZoom(), 4), { duration: 0.7 });
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
  theme,
  correlate = false,
  correlated,
}: TracerouteMapProps) => {
  const mapColors = MAP_COLORS[theme];
  const landStyle = {
    color: mapColors.coast,
    weight: 0.8,
    fillColor: mapColors.land,
    fillOpacity: 1,
  };
  const borderStyle = {
    color: mapColors.border,
    weight: 0.45,
    fill: false,
    opacity: 0.9,
  };
  const [legendOpen, setLegendOpen] = useState(true);
  const visible = selectedTraces.size === 0 ? traces : traces.filter((trace) => selectedTraces.has(trace.id));

  const correlatedHops = correlated ?? [];

  const rendered: Rendered[] = visible.map((trace) => {
    const hops = buildDisplayHops(trace);
    const located = locate(hops);
    const coords = located.map((entry) => entry.position);
    return { trace, hops, located, coords, route: buildRoute(coords) };
  });

  const originCoords = (origins ?? []).map((origin) => [origin.lat, origin.lon] as Coord);
  const allCoords = correlate
    ? [...correlatedHops.map((hop) => hop.position as Coord), ...originCoords]
    : [...rendered.flatMap((entry) => entry.coords), ...originCoords];
  const totalHops = rendered.reduce((sum, entry) => sum + entry.hops.length, 0);
  const totalLocated = rendered.reduce((sum, entry) => sum + entry.located.length, 0);
  const totalVisits = correlatedHops.reduce((sum, hop) => sum + hop.count, 0);

  const activeRendered = rendered.find((entry) => entry.trace.id === focusedTrace) ?? rendered[0];
  const focus = correlate
    ? selectedHop != null
      ? correlatedHops[selectedHop]?.position ?? null
      : null
    : activeRendered?.located.find((entry) => entry.hop.hop === selectedHop)?.position ?? null;

  return (
    <div className="map-wrap">
      <div className="map-canvas">
        <MapContainer
          center={DEFAULT_CENTER}
          zoom={DEFAULT_ZOOM}
          maxZoom={MAX_ZOOM}
          scrollWheelZoom
          zoomControl
          attributionControl
        >
          <GeoJSON
            key={`land:${theme}`}
            data={land}
            interactive={false}
            attribution="Natural Earth"
            style={landStyle}
          />
          <GeoJSON
            key={`countries:${theme}`}
            data={countries}
            interactive={false}
            style={borderStyle}
          />
          <CityLayer key={`cities:${theme}`} dotColor={mapColors.dot} />
          <ScaleControl position="bottomleft" imperial={false} />

          {!correlate &&
            rendered.map(({ trace, located, route }) => {
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
                        fillColor: isDest || isOrigin ? trace.color : mapColors.hopFill,
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
                        LAT/LON&nbsp;{hop.geo ? formatCoords(hop.geo.lat, hop.geo.lon) : 'unknown'}
                        <br />
                        ASN&nbsp;{hop.geo?.asn || 'unknown'}
                        {hop.geo ? (
                          <>
                            <br />
                            <OsmLink
                              className="popup-osm"
                              lat={hop.geo.lat}
                              lon={hop.geo.lon}
                            />
                          </>
                        ) : null}
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

          {correlate &&
            correlatedHops.map((hop, index) => {
              const color = correlationColor(hop.count);
              const radius = 4 + Math.min(hop.count - 1, 6) * 1.4;
              return (
                <CircleMarker
                  key={`corr:${hop.ip}`}
                  center={hop.position}
                  radius={radius}
                  className={`corr-dot${selectedHop === index ? ' corr-dot--selected' : ''}${hop.isTarget ? ' corr-dot--target' : ''}`}
                  pathOptions={{
                    color,
                    fillColor: color,
                    fillOpacity: hop.count > 1 ? 0.85 : 0.5,
                    opacity: 1,
                    weight: hop.isTarget ? 3 : 2,
                  }}
                  eventHandlers={{
                    click: () => onSelectHop(index),
                    contextmenu: (event) => {
                      event.originalEvent.preventDefault();
                      event.originalEvent.stopPropagation();
                      onContextMenu?.(
                        hop.ip,
                        hop.isTarget ? 'target' : `hop ×${hop.count}`,
                        event.originalEvent.clientX,
                        event.originalEvent.clientY,
                      );
                    },
                  }}
                >
                  {hop.count > 1 ? (
                    <Tooltip permanent direction="right" offset={[radius, 0]} className="corr-label">
                      ×{hop.count}
                    </Tooltip>
                  ) : null}
                  <Popup>
                    <b>{hop.isTarget ? 'TARGET' : 'CORRELATED HOP'}</b>
                    <br />
                    {hop.ip}
                    <br />
                    REVISITS&nbsp;×{hop.count} on {hop.paths} {hop.paths === 1 ? 'path' : 'paths'}
                    <br />
                    LOC&nbsp;{hop.geo?.city || 'unknown'}
                    {hop.geo?.country ? ` (${hop.geo.country})` : ''}
                    <br />
                    ASN&nbsp;{hop.geo?.asn || 'unknown'}
                    {hop.geo ? (
                      <>
                        <br />
                        <OsmLink className="popup-osm" lat={hop.geo.lat} lon={hop.geo.lon} />
                      </>
                    ) : null}
                    {hop.labels.length > 0 ? (
                      <>
                        <br />
                        PATHS&nbsp;{hop.labels.slice(0, 4).join(', ')}
                        {hop.labels.length > 4 ? ` +${hop.labels.length - 4}` : ''}
                      </>
                    ) : null}
                  </Popup>
                </CircleMarker>
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
              <div className="legend-hint">
                {correlate ? 'dot size + label = revisits' : 'filled = endpoint · hollow = hop'}
              </div>
            </>
          )}
        </div>

        <div className="map-hud">
          {correlate ? (
            <>
              <b>{correlatedHops.length}</b> UNIQUE · <b>{totalVisits}</b> VISITS
            </>
          ) : (
            <>
              <b>{totalLocated}</b>/{totalHops} LOCATED
              {sharedHops && sharedHops.size > 0 ? (
                <span className="map-hud-shared"> · {sharedHops.size} SHARED</span>
              ) : null}
            </>
          )}
          {origins && origins.length > 0 ? (
            <span className="map-hud-origin"> · {origins.length} ORIGIN</span>
          ) : null}
        </div>
      </div>
    </div>
  );
};

export default TracerouteMap;
