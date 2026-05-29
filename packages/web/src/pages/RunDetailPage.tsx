import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { RunEvent, RunSummary } from "@asp-x/shared";
import { api, subscribeRunEvents } from "../lib/api.js";
import { Badge } from "../components/Badge.js";
import { durationMs, pct, shortId, timeAgo } from "../lib/format.js";
import clsx from "clsx";

export function RunDetailPage() {
  const { id = "" } = useParams<{ id: string }>();
  const qc = useQueryClient();

  const runQ = useQuery({
    queryKey: ["run", id],
    queryFn: () => api.getRun(id),
    refetchInterval: (q) => (q.state.data?.status === "running" ? 2000 : false),
  });
  const resultsQ = useQuery({
    queryKey: ["results", id],
    queryFn: () => api.listResults(id),
    refetchInterval: (q) => (runQ.data?.status === "running" || (q.state.data?.length ?? 0) === 0 ? 2000 : false),
  });

  const [liveLog, setLiveLog] = useState<RunEvent[]>([]);
  useEffect(() => {
    if (!id) return;
    const off = subscribeRunEvents(id, (ev) => {
      setLiveLog((cur) => [...cur.slice(-50), ev]);
      if (ev.type === "result.completed" || ev.type === "run.completed" || ev.type === "run.failed") {
        void qc.invalidateQueries({ queryKey: ["run", id] });
        void qc.invalidateQueries({ queryKey: ["results", id] });
      }
    });
    return off;
  }, [id, qc]);

  if (runQ.isLoading) return <div className="px-6 py-8 text-ink-500">Loading…</div>;
  if (runQ.error || !runQ.data)
    return <div className="px-6 py-8 text-accent-attack">Not found.</div>;

  const run = runQ.data;
  const results = resultsQ.data ?? [];

  return (
    <div className="max-w-6xl mx-auto px-6 py-8 space-y-6 animate-fade-up">
      <header className="flex items-start justify-between gap-4">
        <div>
          <div className="text-xs text-ink-500 mb-1 font-mono">
            Run · {shortId(run.id)}
          </div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-3">
            {run.label ?? run.config.injection_method}
            <StatusBadge status={run.status} />
          </h1>
          <p className="text-sm text-ink-500 mt-1">
            Started {timeAgo(run.started_at_ms)}
            {run.ended_at_ms && ` · took ${durationMs(run.ended_at_ms - run.started_at_ms)}`}
          </p>
        </div>
        <div className="flex gap-2">
          {run.status === "running" && (
            <button
              onClick={() => void api.cancelRun(run.id).then(() => qc.invalidateQueries({ queryKey: ["run", run.id] }))}
              className="btn-ghost"
            >
              Cancel
            </button>
          )}
          <Link to="/" className="btn-ghost">
            ← Back
          </Link>
        </div>
      </header>

      <MetricsCards run={run} />

      <ConfigSummary run={run} />

      <section>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm uppercase tracking-wide text-ink-500 font-semibold">
            Results ({results.length})
          </h2>
          {run.status === "running" && (
            <span className="text-xs text-ink-500">
              {run.progress.done} / {run.progress.total} complete
            </span>
          )}
        </div>
        {results.length === 0 && (
          <div className="card p-12 text-center text-ink-500">
            Waiting for first result…
          </div>
        )}
        {results.length > 0 && (
          <div className="card overflow-hidden">
            <table className="w-full text-sm">
              <thead className="text-ink-500 text-xs uppercase tracking-wider">
                <tr className="border-b hairline">
                  <th className="text-left px-4 py-3 font-medium">Agent</th>
                  <th className="text-left px-4 py-3 font-medium">Variant</th>
                  <th className="text-left px-4 py-3 font-medium">Target tool</th>
                  <th className="text-left px-4 py-3 font-medium">Task</th>
                  <th className="text-center px-4 py-3 font-medium">ASR</th>
                  <th className="text-center px-4 py-3 font-medium">RR</th>
                  <th className="text-center px-4 py-3 font-medium">PNA</th>
                  <th className="text-right px-4 py-3 font-medium">Trace</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r) => (
                  <tr
                    key={r.id}
                    className="border-t hairline hover:bg-white/[0.03] transition-colors"
                  >
                    <td className="px-4 py-2 text-xs">{r.agent_id}</td>
                    <td className="px-4 py-2 text-xs font-mono text-ink-700">
                      {r.attack_variant ?? "—"}
                    </td>
                    <td className="px-4 py-2 text-xs font-mono text-ink-700">
                      {r.attack_target_tool ?? "—"}
                    </td>
                    <td className="px-4 py-2 text-xs text-ink-500 truncate max-w-xs">
                      {r.task}
                    </td>
                    <td className="px-4 py-2 text-center">
                      <Dot active={r.judge.attack_success} tone="attack" />
                    </td>
                    <td className="px-4 py-2 text-center">
                      <Dot active={r.judge.refused} tone="warn" />
                    </td>
                    <td className="px-4 py-2 text-center">
                      {r.judge.original_task_success === undefined ? (
                        <span className="text-ink-500 text-xs">—</span>
                      ) : (
                        <Dot active={r.judge.original_task_success} tone="safe" />
                      )}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <Link
                        to={`/runs/${run.id}/results/${r.id}`}
                        className="text-accent-info hover:underline text-xs"
                      >
                        view →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {run.status === "running" && liveLog.length > 0 && (
        <section>
          <h2 className="text-sm uppercase tracking-wide text-ink-500 font-semibold mb-2">
            Live event stream
          </h2>
          <div className="card bg-bg-900/60 p-3 font-mono text-xs h-48 overflow-auto space-y-0.5">
            {liveLog.slice(-20).map((ev, i) => (
              <div key={i} className="text-ink-500">
                <span className="text-accent-info">{ev.type}</span>
                {ev.type === "result.completed" && (
                  <>
                    {" "}
                    <span className="text-ink-700">{ev.result.agent_id}</span>{" "}
                    {ev.result.judge.attack_success ? (
                      <span className="text-accent-attack">ASR✓</span>
                    ) : (
                      <span className="text-accent-safe">ASR✗</span>
                    )}
                  </>
                )}
                {ev.type === "run.progress" && (
                  <>
                    {" "}
                    <span className="text-ink-700">
                      {ev.progress.done}/{ev.progress.total}
                    </span>
                  </>
                )}
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function MetricsCards({ run }: { run: RunSummary }) {
  return (
    <div className="grid grid-cols-4 gap-3">
      <Metric
        label="ASR"
        value={run.metrics ? pct(run.metrics.asr) : "—"}
        hint="Attack success rate"
        tone="attack"
      />
      <Metric
        label="RR"
        value={run.metrics ? pct(run.metrics.rr) : "—"}
        hint="Refusal rate"
        tone="warn"
      />
      <Metric
        label="PNA"
        value={run.metrics ? pct(run.metrics.pna) : "—"}
        hint="Original task success"
        tone="safe"
      />
      <Metric
        label="N"
        value={String(run.progress.done)}
        sub={`/ ${run.progress.total}`}
        hint="Runs completed"
      />
    </div>
  );
}

function Metric({
  label,
  value,
  sub,
  hint,
  tone = "default",
}: {
  label: string;
  value: string;
  sub?: string;
  hint?: string;
  tone?: "default" | "attack" | "warn" | "safe";
}) {
  const accent = {
    default: "text-ink-900",
    attack: "text-accent-attack",
    warn: "text-accent-warn",
    safe: "text-accent-safe",
  }[tone];
  const bar = {
    default: "from-ink-500/40",
    attack: "from-accent-attack",
    warn: "from-accent-warn",
    safe: "from-accent-safe",
  }[tone];
  const glow = {
    default: "",
    attack: "hover:shadow-glow-attack",
    warn: "hover:shadow-glow-warn",
    safe: "hover:shadow-glow-safe",
  }[tone];
  return (
    <div
      className={clsx(
        "card card-hover relative overflow-hidden p-4 transition-shadow duration-300",
        glow,
      )}
    >
      <div className={clsx("absolute inset-x-0 top-0 h-px bg-gradient-to-r to-transparent", bar)} />
      <div className="text-[11px] uppercase tracking-wider text-ink-500 mb-1.5">{label}</div>
      <div className={clsx("text-3xl font-semibold font-mono tracking-tight", accent)}>
        {value}
        {sub && <span className="text-ink-500 text-sm font-normal ml-1">{sub}</span>}
      </div>
      {hint && <div className="text-[10px] uppercase text-ink-400 mt-1.5 tracking-wide">{hint}</div>}
    </div>
  );
}

function ConfigSummary({ run }: { run: RunSummary }) {
  const c = run.config;
  return (
    <section className="card p-4 text-xs">
      <div className="flex flex-wrap gap-x-6 gap-y-1.5">
        <ConfigLine k="injection_method" v={c.injection_method} />
        <ConfigLine k="attack_tool" v={c.attack_tool} />
        <ConfigLine k="variants" v={c.attack_types.join(", ")} />
        <ConfigLine k="llms" v={c.llms.join(", ")} />
        {c.defense_type && <ConfigLine k="defense" v={c.defense_type} />}
        {c.agents && <ConfigLine k="agents" v={c.agents.join(", ")} />}
        {c.task_num && <ConfigLine k="task_num" v={String(c.task_num)} />}
        <ConfigLine k="max_steps" v={String(c.max_steps)} />
      </div>
    </section>
  );
}

function ConfigLine({ k, v }: { k: string; v: string }) {
  return (
    <div>
      <span className="text-ink-500">{k}:</span>{" "}
      <span className="text-ink-700 font-mono">{v}</span>
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
      <span
        className={clsx("w-1 h-1 rounded-full", {
          "bg-accent-info animate-pulse": status === "running",
          "bg-accent-safe": status === "completed",
          "bg-accent-attack": status === "failed",
          "bg-ink-500": ["pending", "cancelled"].includes(status),
        })}
      />
      {status}
    </Badge>
  );
}

function Dot({
  active,
  tone,
}: {
  active: boolean;
  tone: "attack" | "warn" | "safe";
}) {
  const cls = {
    attack: "bg-accent-attack",
    warn: "bg-accent-warn",
    safe: "bg-accent-safe",
  }[tone];
  return (
    <span
      className={clsx(
        "inline-block w-2 h-2 rounded-full",
        active ? cls : "bg-bg-500",
      )}
    />
  );
}
