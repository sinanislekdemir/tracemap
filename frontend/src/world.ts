import { feature } from 'topojson-client';
import type { GeometryCollection, Topology } from 'topojson-specification';
import raw from 'world-atlas/countries-50m.json?raw';
import { splitAntimeridian } from './antimeridian';

export interface CountryProperties {
  name?: string;
}

type WorldObjects = {
  countries: GeometryCollection<CountryProperties>;
  land: GeometryCollection;
};

const world = JSON.parse(raw) as Topology<WorldObjects>;

// Natural Earth 1:50m boundaries, converted and cut at the antimeridian once at
// module load so Leaflet draws no wrap-around artifacts. `land` is the union of
// all landmasses and supplies the coastline for the fill; `countries` supplies
// the internal borders drawn on top.
export const land = splitAntimeridian(feature(world, world.objects.land));
export const countries = splitAntimeridian(feature(world, world.objects.countries));
