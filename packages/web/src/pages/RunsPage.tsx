import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../lib/api.js";
import { durationMs, pct, shortId, timeAgo } from "../lib/format.js";
import { Badge } from "../components/Badge.js";
import clsx from "clsx";

export function RunsPage() {
  const q = useQuery({
    queryKey: ["runs"],
    queryFn: api.listRuns,
    refetchInterval: 3000,
  });

  return (
    <div className="max-w-6xl mx-auto px-6 py-8">
      <header className="flex items-end justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold">Runs</h1>
          <p className="text-sm text-ink-500">
            Each row is one benchmark execution against the bundled agents.
          </p>
        </div>
        <Link
          to="/runs/new"
          className="px-3 py-1.5 rounded-md bg-accent-info/15 text-accent-info hover:bg-accent-info/25 text-sm font-medium"
        >
          + New Run
        </Link>
      </header>

      {q.isLoading && <div className="text-ink-500 text-sm">Loading…</div>}
      {q.error && (
        <div className="text-accent-attack text-sm">
          Failed to load: {(q.error as Error).message}
        </div>
      )}

      {q.data && q.data.length === 0 && (
        <div className="border border-dashed border-bg-500 rounded-md p-12 text-center">
          <div className="text-ink-500 mb-2">No runs yet.</div>
          <Link
            to="/runs/new"
            className="text-accent-info hover:underline text-sm"
          >
            Configure your first run →
          </Link>
        </div>
      )}

      {q.data && q.data.length > 0 && (
        <div className="overflow-hidden border border-bg-600 rounded-lg">
          <table className="w-full text-sm">
            <thead className="bg-bg-700 text-ink-500 text-xs uppercase tracking-wide">
              <tr>
                <th className="text-left px-4 py-2 font-normal">Status</th>
                <th className="text-left px-4 py-2 font-normal">Run</th>
                <th className="text-left px-4 py-2 font-normal">Attack</th>
                <th className="text-left px-4 py-2 font-normal">Model(s)</th>
                <th className="text-right px-4 py-2 font-normal">Progress</th>
                <th className="text-right px-4 py-2 font-normal">ASR</th>
                <th className="text-right px-4 py-2 font-normal">RR</th>
                <th className="text-right px-4 py-2 font-normal">Started</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {q.data.map((r) => (
                <tr
                  key={r.id}
                  className="border-t border-bg-600 hover:bg-bg-700/40 transition-colors"
                >
                  <td className="px-4 py-3">
                    <StatusBadge status={r.status} />
                  </td>
                  <td className="px-4 py-3 font-mono text-ink-700">
                    <Link
                      to={`/runs/${r.id}`}
                      className="hover:text-accent-info"
                    >
                      {r.label ?? shortId(r.id)}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-ink-700">
                    <span className="text-xs">{r.config.injection_method}</span>
                    {r.config.defense_type && (
                      <span className="text-ink-500 text-xs ml-2">
                        + {r.config.defense_type}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-ink-700 text-xs font-mono">
                    {r.config.llms.join(", ")}
                  </td>
                  <td className="px-4 py-3 text-right text-ink-700 font-mono text-xs">
                    {r.progress.done}/{r.progress.total}
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-xs">
                    {r.metrics ? pct(r.metrics.asr) : "—"}
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-xs">
                    {r.metrics ? pct(r.metrics.rr) : "—"}
                  </td>
                  <td className="px-4 py-3 text-right text-ink-500 text-xs">
                    {timeAgo(r.started_at_ms)}
                  </td>
                  <td className="px-4 py-3 text-right text-ink-500 text-xs">
                    {r.ended_at_ms && (
                      <span>
                        {durationMs(r.ended_at_ms - r.started_at_ms)}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const tone =
    status === "running"
      ? "info"
      : status === "completed"
        ? "safe"
        : status === "failed"
          ? "attack"
          : "default";
  return (
    <Badge tone={tone as Parameters<typeof Badge>[0]["tone"]}>
      <span className={clsx("w-1 h-1 rounded-full", {
        "bg-accent-info animate-pulse": status === "running",
        "bg-accent-safe": status === "completed",
        "bg-accent-attack": status === "failed",
        "bg-ink-500": status !== "running" && status !== "completed" && status !== "failed",
      })} />
      {status}
    </Badge>
  );
}
