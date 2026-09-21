export type Motion = 'on' | 'off';

const STORAGE_KEY = 'traceroute.motion';

export function loadMotion(): Motion {
  try {
    return localStorage.getItem(STORAGE_KEY) === 'off' ? 'off' : 'on';
  } catch {
    return 'on';
  }
}

export function applyMotion(motion: Motion): void {
  document.documentElement.dataset.motion = motion;
  try {
    localStorage.setItem(STORAGE_KEY, motion);
  } catch {
    // storage unavailable; motion still applies for this session
  }
}
