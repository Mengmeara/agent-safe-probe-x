export function pct(x: number | undefined | null): string {
  if (x === null || x === undefined) return "—";
  return `${(x * 100).toFixed(1)}%`;
}

export function timeAgo(ms: number): string {
  const diffSec = (Date.now() - ms) / 1000;
  if (diffSec < 60) return `${Math.floor(diffSec)}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

export function durationMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

export function shortId(id: string): string {
  const i = id.indexOf("_");
  const body = i === -1 ? id : id.slice(i + 1);
  return body.slice(0, 8);
}
