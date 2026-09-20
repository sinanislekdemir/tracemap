import type { MouseEvent } from 'react';
import { BrowserOpenURL } from '../../wailsjs/runtime/runtime';
import { osmUrl } from '../format';

interface OsmLinkProps {
  lat: number;
  lon: number;
  label?: string;
  className?: string;
  title?: string;
}

// OsmLink opens an OpenStreetMap permalink in the user's default browser via the
// Wails runtime, instead of navigating the embedded webview.
const OsmLink = ({ lat, lon, label = 'Open in OpenStreetMap', className, title }: OsmLinkProps) => {
  const url = osmUrl(lat, lon);

  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    event.preventDefault();
    event.stopPropagation();
    BrowserOpenURL(url);
  };

  return (
    <a
      className={className}
      href={url}
      title={title ?? label}
      rel="noreferrer"
      onClick={handleClick}
    >
      {label}
    </a>
  );
};

export default OsmLink;
