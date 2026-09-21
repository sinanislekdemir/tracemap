import type { KeyboardEvent, MouseEvent } from 'react';
import { formatCoords } from '../format';
import { correlationColor } from '../colors';
import OsmLink from './OsmLink';
import type { CorrelatedHop } from '../types';

interface CorrelationListProps {
  hops: CorrelatedHop[];
  selectedIndex: number | null;
  onSelect: (index: number) => void;
  onContextMenu?: (event: MouseEvent, hop: CorrelatedHop) => void;
}

function locationText(hop: CorrelatedHop): string {
  const geo = hop.geo;
  if (!geo) {
    return 'unknown location';
  }
  if (!geo.resolved) {
    return geo.city || 'unknown location';
  }
  const parts = [geo.city, geo.country].filter(Boolean);
  return parts.length > 0 ? parts.join(', ') : 'unknown location';
}

// CorrelationList is the correlation-mode counterpart of HopList: one row per
// unique located hop, ordered by how often the paths revisit it.
const CorrelationList = ({ hops, selectedIndex, onSelect, onContextMenu }: CorrelationListProps) => {
  if (hops.length === 0) {
    return (
      <div className="empty">
        <span>NO LOCATED HOPS</span>
        <span>Correlation needs geolocated hops from the loaded paths.</span>
      </div>
    );
  }

  return (
    <>
      {hops.map((hop, index) => {
        const classes = ['hop', 'hop--corr'];
        if (hop.isTarget) classes.push('is-target');
        if (index === selectedIndex) classes.push('is-selected');
        const color = correlationColor(hop.count);

        const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            onSelect(index);
          }
        };

        return (
          <div
            key={hop.ip}
            role="button"
            tabIndex={0}
            className={classes.join(' ')}
            onClick={() => onSelect(index)}
            onKeyDown={onKeyDown}
            onContextMenu={(event) => onContextMenu?.(event, hop)}
          >
            <span
              className="corr-count"
              style={{ color, borderColor: color }}
              title={`Seen ${hop.count} times on ${hop.paths} of the correlated paths`}
            >
              ×{hop.count}
            </span>
            <span className="hop-main">
              <span className="hop-ip selectable">{hop.ip}</span>
              <span className="hop-loc">
                {locationText(hop)}
                {hop.geo?.asn ? <span className="hop-asn"> · {hop.geo.asn}</span> : null}
              </span>
              {hop.geo ? (
                <span className="hop-coords">{formatCoords(hop.geo.lat, hop.geo.lon)}</span>
              ) : null}
            </span>
            <span className="corr-paths" title="Distinct paths containing this hop">
              {hop.paths}
              <i>PATH{hop.paths === 1 ? '' : 'S'}</i>
            </span>
            {hop.geo ? (
              <OsmLink className="hop-osm" label="OSM" lat={hop.geo.lat} lon={hop.geo.lon} />
            ) : (
              <span className="hop-osm hop-osm--empty" aria-hidden="true" />
            )}
          </div>
        );
      })}
    </>
  );
};

export default CorrelationList;
