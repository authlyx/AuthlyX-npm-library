export function clampString(input: unknown): string {
  if (input === null || input === undefined) return '';
  return String(input);
}

export function stripTrailingSlashes(url: string): string {
  return url.replace(/\/+$/, '');
}

export function canonicalJson(obj: unknown): string {
  const stable = (value: any): any => {
    if (value === null || value === undefined) return value;
    if (Array.isArray(value)) return value.map(stable);
    if (typeof value !== 'object') return value;
    const out: Record<string, any> = {};
    for (const k of Object.keys(value).sort()) out[k] = stable(value[k]);
    return out;
  };
  return JSON.stringify(stable(obj));
}

export function nowMs(): number {
  return Date.now();
}

export function parseIsoMs(iso: string): number | null {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : null;
}

export function computeDaysLeft(expiryIso: string): number {
  const ms = expiryIso ? parseIsoMs(expiryIso) : null;
  if (!ms) return 0;
  const diff = ms - nowMs();
  const days = Math.floor(diff / (24 * 60 * 60 * 1000));
  return days > 0 ? days : 0;
}

export function safeJsonParse(text: string): any | null {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

