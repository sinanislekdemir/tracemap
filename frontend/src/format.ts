// Shared display formatting helpers.

// joinList renders a list of strings for a report field, or an em dash when it
// is empty or missing.
export const joinList = (values?: string[]): string =>
  values && values.length > 0 ? values.join(', ') : '—';

// formatDateMs renders Unix milliseconds as a short local date, or an em dash
// when unset.
export const formatDateMs = (ms?: number): string => {
  if (!ms) {
    return '—';
  }
  return new Date(ms).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
};

// shortHash truncates a hash for display, or an em dash when missing.
export const shortHash = (value?: string): string => (value ? value.slice(0, 16) : '—');
