import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import type { RunResult } from "@asp-x/shared";
import { api } from "../lib/api.js";
import { Badge } from "../components/Badge.js";
import { TraceTimeline } from "../components/TraceTimeline.js";
import { durationMs, shortId } from "../lib/format.js";
import clsx from "clsx";

export function ResultPage() {
  const { id = "", resultId = "" } = useParams<{ id: string; resultId: string }>();

  const traceQ = useQuery({
    queryKey: ["trace", id, resultId],
    queryFn: () => api.getTrace(id, resultId),
  });

  const resultsQ = useQuery({
    queryKey: ["results", id],
    queryFn: () => api.listResults(id),
  });
  const result = resultsQ.data?.find((r) => r.id === resultId);

  return (
    <div className="max-w-5xl mx-auto px-6 py-8 space-y-5 animate-fade-up">
      <Link
        to={`/runs/${id}`}
        className="text-sm text-ink-500 hover:text-ink-900 inline-flex items-center gap-1 transition-colors"
      >
        ← back to run
      </Link>

      <header className="space-y-3">
        <div className="text-xs text-ink-500 font-mono">
          Result · {shortId(resultId)}
        </div>
        {result && <ResultHeader result={result} />}
      </header>

      {traceQ.isLoading && (
        <div className="text-ink-500 text-sm py-8 text-center">
          Loading trace…
        </div>
      )}
      {traceQ.error && (
        <div className="text-accent-attack text-sm">
          Failed to load trace: {(traceQ.error as Error).message}
        </div>
      )}
      {traceQ.data && <TraceTimeline steps={traceQ.data.steps} />}
    </div>
  );
}

function ResultHeader({ result }: { result: RunResult }) {
  const j = result.judge;
  return (
    <div className="space-y-3">
      <div className="flex items-baseline gap-3 flex-wrap">
        <h1 className="text-xl font-semibold">{result.agent_id}</h1>
        <Badge tone="info">{result.attack_method}</Badge>
        {result.attack_variant && (
          <span className="text-xs font-mono text-ink-500">/ {result.attack_variant}</span>
        )}
        {result.attack_target_tool && (
          <span className="text-xs font-mono text-ink-500">
            → {result.attack_target_tool}
          </span>
        )}
        <span className="text-xs font-mono text-ink-500">· {result.llm}</span>
        <span className="text-xs font-mono text-ink-500">
          · {durationMs(result.duration_ms)}
        </span>
      </div>

      <div className="card p-4">
        <div className="text-xs uppercase tracking-wider text-ink-500 mb-1.5">
          Task
        </div>
        <div className="text-sm text-ink-700 leading-relaxed">{result.task}</div>
      </div>

      <div className="flex flex-wrap gap-2">
        <JudgeChip
          label="ASR"
          value={j.attack_success ? "ATTACK SUCCEEDED" : "withstood"}
          tone={j.attack_success ? "attack" : "safe"}
          detail={
            j.attack_tools_called.length > 0
              ? `called: ${j.attack_tools_called.join(", ")}`
              : undefined
          }
        />
        <JudgeChip
          label="RR"
          value={j.refused ? "refused" : "complied"}
          tone={j.refused ? "warn" : "default"}
          detail={j.refused_evidence}
        />
        {j.original_task_success !== undefined && (
          <JudgeChip
            label="PNA"
            value={j.original_task_success ? "completed" : "incomplete"}
            tone={j.original_task_success ? "safe" : "default"}
          />
        )}
      </div>

      {result.error && (
        <div className="border border-accent-attack/40 rounded-md p-3 text-sm text-accent-attack bg-accent-attack/5">
          <div className="font-semibold mb-1">Error</div>
          <div className="font-mono text-xs whitespace-pre-wrap">{result.error}</div>
        </div>
      )}
    </div>
  );
}

function JudgeChip({
  label,
  value,
  tone,
  detail,
}: {
  label: string;
  value: string;
  tone: "attack" | "safe" | "warn" | "default";
  detail?: string;
}) {
  const accent = {
    attack: "border-accent-attack/40 bg-accent-attack/10",
    safe: "border-accent-safe/40 bg-accent-safe/10",
    warn: "border-accent-warn/40 bg-accent-warn/10",
    default: "border-bg-500 bg-bg-700",
  }[tone];
  const labelColor = {
    attack: "text-accent-attack",
    safe: "text-accent-safe",
    warn: "text-accent-warn",
    default: "text-ink-500",
  }[tone];
  return (
    <div className={clsx("border rounded px-3 py-1.5", accent)}>
      <div className="flex items-baseline gap-2">
        <span className={clsx("text-[10px] font-mono uppercase tracking-wide font-bold", labelColor)}>
          {label}
        </span>
        <span className="text-sm font-medium text-ink-900">{value}</span>
      </div>
      {detail && <div className="text-[10px] text-ink-500 font-mono mt-0.5">{detail}</div>}
    </div>
  );
}
