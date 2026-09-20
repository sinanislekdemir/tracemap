import { feature } from 'topojson-client';
import type { GeometryCollection, Topology } from 'topojson-specification';
import raw from 'world-atlas/countries-110m.json?raw';
import { splitAntimeridian } from './antimeridian';

export interface CountryProperties {
  name?: string;
}

type WorldObjects = { countries: GeometryCollection<CountryProperties> };

const world = JSON.parse(raw) as Topology<WorldObjects>;

// Natural Earth 1:110m country boundaries, converted and cut at the
// antimeridian once at module load so Leaflet draws no wrap-around artifacts.
export const countries = splitAntimeridian(feature(world, world.objects.countries));
