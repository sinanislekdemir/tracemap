import type { HopData } from '../types';

interface HopListProps {
  hops: HopData[];
  selectedHop: number | null;
  onSelectHop: (hop: number) => void;
  sharedHops?: Map<string, number>;
}

function locationText(hop: HopData): string {
  if (!hop.ip) {
    return 'no reply';
  }
  const geo = hop.geo;
  if (!geo) {
    return 'resolving…';
  }
  if (!geo.resolved) {
    return geo.city || 'unknown location';
  }
  const parts = [geo.city, geo.country].filter(Boolean);
  return parts.length > 0 ? parts.join(', ') : 'unknown location';
}

function rttColor(ms: number, max: number): string {
  const t = max > 0 ? Math.min(1, ms / max) : 0;
  if (t < 0.34) return 'var(--ok)';
  if (t < 0.67) return 'var(--accent)';
  if (t < 0.9) return 'var(--warn)';
  return 'var(--err)';
}

const HopList = ({ hops, selectedHop, onSelectHop, sharedHops }: HopListProps) => {
  if (hops.length === 0) {
    return (
      <div className="empty">
        <span>NO HOPS YET</span>
        <span>
          Enter a target and press <span className="empty-kbd">TRACE</span>
          <br />
          <span className="empty-kbd">ENTER</span> to run · <span className="empty-kbd">ESC</span> to cancel
        </span>
      </div>
    );
  }

  const rtts = hops.map((hop) => hop.rttMs).filter((rtt): rtt is number => rtt != null && rtt > 0);
  const maxRtt = rtts.length > 0 ? Math.max(...rtts) : 0;

  return (
    <>
      {hops.map((hop) => {
        const dead = !hop.ip;
        const shared = hop.ip ? sharedHops?.get(hop.ip) : undefined;
        const classes = ['hop'];
        if (dead) classes.push('is-dead');
        if (hop.isTarget) classes.push('is-target');
        if (shared) classes.push('is-shared');
        if (hop.hop === selectedHop) classes.push('is-selected');

        const barPct = hop.rttMs != null && maxRtt > 0 ? Math.max(6, (hop.rttMs / maxRtt) * 100) : 0;

        return (
          <button
            key={hop.hop}
            type="button"
            className={classes.join(' ')}
            onClick={() => onSelectHop(hop.hop)}
          >
            <span className="hop-num">{hop.isTarget ? 'TGT' : String(hop.hop).padStart(2, '0')}</span>
            <span className="hop-main">
              <span className="hop-ip selectable">
                {hop.ip || '* * *'}
                {shared ? <span className="hop-shared" title={`On ${shared} traces`}>×{shared}</span> : null}
              </span>
              <span className="hop-loc">
                {locationText(hop)}
                {hop.geo?.asn ? <span className="hop-asn"> · {hop.geo.asn}</span> : null}
              </span>
            </span>
            <span className="hop-rtt">
              <span className="hop-rtt-val">
                {hop.rttMs != null ? `${hop.rttMs.toFixed(1)} ms` : '—'}
              </span>
              <span className="hop-bar">
                <i
                  style={{
                    width: `${barPct}%`,
                    background: hop.rttMs != null ? rttColor(hop.rttMs, maxRtt) : 'transparent',
                  }}
                />
              </span>
            </span>
          </button>
        );
      })}
    </>
  );
};

export default HopList;
