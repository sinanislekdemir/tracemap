package origin

import "context"

// zoneNames is the phase-3 hook for local name enumeration without Certificate
// Transparency.
//
// TODO(phase 3): implement NSEC zone walking (query a nonexistent name, follow
// the NSEC chain to the next existing owner) and a best-effort AXFR against the
// authoritative nameserver. Both are local DNS only and add no dependency.
// NSEC3-hashed zones defeat the walk and most servers refuse AXFR, so this is
// opportunistic. Until then, candidate generation relies on the reused scan,
// SPF/MX records and certificate SANs (see gatherCandidates).
func zoneNames(_ context.Context, _ string, _ Options) []string {
	return nil
}
