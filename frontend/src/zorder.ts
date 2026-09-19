// Shared stacking-order counter for every floating surface (terminal windows
// and tool dialogs). Focusing any surface raises it above the others, so a
// dialog and a window behave like peers rather than one always covering the
// other.
let current = 1000;

export const nextZ = () => (current += 1);
