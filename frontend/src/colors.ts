// Distinct, dark-background friendly colours assigned to traces in order.
export const TRACE_COLORS = [
  '#2dd4ef',
  '#f5b642',
  '#a78bfa',
  '#3ddc97',
  '#ff6b6b',
  '#f472b6',
  '#60a5fa',
  '#facc15',
  '#4ade80',
  '#fb923c',
  '#c084fc',
  '#38bdf8',
];

// Revisit heat for correlation mode: a hop seen once stays cool, hops shared by
// more paths warm up so the most-revisited points stand out.
export function correlationColor(count: number): string {
  if (count >= 4) {
    return '#ff6b6b';
  }
  if (count >= 2) {
    return '#f5b642';
  }
  return '#38bdf8';
}
