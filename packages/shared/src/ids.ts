/**
 * Tiny id helpers. Use the runtime-provided crypto.randomUUID where available
 * (Node 18+, all evergreen browsers). Fallback to a time+random shim.
 */
export function newId(prefix?: string): string {
  let raw: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g: any = globalThis;
  if (g.crypto && typeof g.crypto.randomUUID === "function") {
    raw = g.crypto.randomUUID();
  } else {
    raw = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }
  return prefix ? `${prefix}_${raw}` : raw;
}

export function shortId(n = 8): string {
  return Math.random().toString(36).slice(2, 2 + n);
}
