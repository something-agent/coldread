export function chainsMatch(a: string, b: string): boolean { return a.toLowerCase() === b.toLowerCase(); }
export function hostOf(url: string): string | null { try { return new URL(url).hostname.toLowerCase(); } catch { return null; } }
export const nowSec = () => Math.floor(Date.now() / 1000);
