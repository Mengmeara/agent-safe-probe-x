import { useState } from "react";
import type {
  TraceStep,
  TraceStepKind,
  InjectionMark,
} from "@asp-x/shared";
import clsx from "clsx";

/**
 * Vertical timeline of a single agent execution. Each step is a card pinned
 * to a colour-coded marker on the rail. Injected steps and attack-tool calls
 * are visually flagged so a reviewer can spot the failure mode at a glance.
 */
export function TraceTimeline({ steps }: { steps: TraceStep[] }) {
  const [filter, setFilter] = useState<"all" | "injected" | "tools">("all");
  const filtered = steps.filter((s) => {
    if (filter === "injected")
      return (
        s.injection !== undefined ||
        (s.observation?.injected ?? false) ||
        (s.observation?.was_attack_tool ?? false)
      );
    if (filter === "tools") return s.kind === "tool_call" || s.kind === "observation";
    return true;
  });

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm uppercase tracking-wider text-ink-500 font-semibold">
          Trajectory ({steps.length} step{steps.length === 1 ? "" : "s"})
        </h2>
        <div className="flex gap-1 bg-white/[0.03] border border-white/[0.06] rounded-lg p-0.5 text-xs">
          {(["all", "tools", "injected"] as const).map((k) => (
            <button
              key={k}
              onClick={() => setFilter(k)}
              className={clsx(
                "px-2.5 py-1 rounded-md transition-all duration-150",
                filter === k
                  ? "bg-white/[0.08] text-ink-900 shadow-[0_1px_0_0_rgba(255,255,255,0.06)_inset]"
                  : "text-ink-500 hover:text-ink-900",
              )}
            >
              {k}
            </button>
          ))}
        </div>
      </div>

      <div className="relative">
        <div className="absolute left-[15px] top-2 bottom-2 w-px bg-gradient-to-b from-white/[0.04] via-white/[0.1] to-white/[0.04]" />
        <ol className="space-y-2.5">
          {filtered.map((step) => (
            <TraceStepCard key={step.index} step={step} />
          ))}
        </ol>
      </div>
    </div>
  );
}

const STEP_META: Record<
  TraceStepKind,
  { label: string; tone: string; ring: string; bg: string }
> = {
  system_prompt: {
    label: "SYS",
    tone: "text-accent-system",
    ring: "ring-accent-system/30",
    bg: "bg-accent-system/10",
  },
  user_task: {
    label: "USR",
    tone: "text-accent-user",
    ring: "ring-accent-user/30",
    bg: "bg-accent-user/10",
  },
  memory_lookup: {
    label: "MEM",
    tone: "text-accent-info",
    ring: "ring-accent-info/30",
    bg: "bg-accent-info/10",
  },
  assistant_thought: {
    label: "THK",
    tone: "text-ink-700",
    ring: "ring-bg-500",
    bg: "bg-bg-700",
  },
  tool_call: {
    label: "TOL",
    tone: "text-accent-tool",
    ring: "ring-accent-tool/30",
    bg: "bg-accent-tool/10",
  },
  observation: {
    label: "OBS",
    tone: "text-accent-info",
    ring: "ring-accent-info/30",
    bg: "bg-accent-info/10",
  },
  final_answer: {
    label: "FIN",
    tone: "text-accent-safe",
    ring: "ring-accent-safe/30",
    bg: "bg-accent-safe/10",
  },
  error: {
    label: "ERR",
    tone: "text-accent-attack",
    ring: "ring-accent-attack/30",
    bg: "bg-accent-attack/10",
  },
};

function TraceStepCard({ step }: { step: TraceStep }) {
  const meta = STEP_META[step.kind];
  const isInjected = step.injection !== undefined || step.observation?.injected === true;
  const isAttackHit =
    step.kind === "observation" && step.observation?.was_attack_tool === true;
  return (
    <li className="relative pl-11">
      <div
        className={clsx(
          "absolute left-0 top-1 w-8 h-8 rounded-xl grid place-items-center text-[10px] font-mono font-bold ring-2 backdrop-blur-sm z-10",
          meta.tone,
          meta.ring,
          meta.bg,
          isAttackHit && "ring-accent-attack/70 shadow-glow-attack",
        )}
      >
        {meta.label}
      </div>
      <div
        className={clsx(
          "border rounded-xl p-3.5 bg-bg-800/70 backdrop-blur-sm transition-colors",
          isInjected
            ? "border-accent-attack/40 shadow-[0_0_0_1px_rgba(255,93,93,0.12),0_8px_28px_-14px_rgba(255,93,93,0.5)]"
            : isAttackHit
              ? "border-accent-attack/60 shadow-glow-attack"
              : "border-white/[0.07] hover:border-white/[0.12]",
        )}
      >
        <div className="flex items-center justify-between mb-1">
          <div className={clsx("text-[11px] font-mono uppercase tracking-wide", meta.tone)}>
            {step.kind}
          </div>
          <div className="text-[10px] text-ink-500 font-mono tabular-nums">
            +{step.t_ms}ms
          </div>
        </div>

        {step.injection && <InjectionAnnotation mark={step.injection} />}
        {step.observation && (
          <ObservationBlock
            obs={step.observation}
            wasAttackTool={isAttackHit}
            wasInjected={step.observation.injected}
          />
        )}
        {step.tool_call && (
          <ToolCallBlock
            tc={step.tool_call}
            isAttack={isAttackHit}
          />
        )}
        {step.content !== undefined && (step.kind !== "observation" && step.kind !== "tool_call") && (
          <ExpandableContent text={step.content} />
        )}
      </div>
    </li>
  );
}

function InjectionAnnotation({ mark }: { mark: InjectionMark }) {
  return (
    <div className="mb-2 rounded border border-accent-attack/30 bg-accent-attack/5 p-2 text-xs">
      <div className="flex items-center gap-2 mb-1">
        <span className="font-mono uppercase tracking-wide text-accent-attack">
          ⚠ injection
        </span>
        <span className="text-accent-attack font-mono">{mark.method}</span>
        {mark.variant && (
          <span className="text-ink-500 font-mono">/ {mark.variant}</span>
        )}
        <span className="text-ink-500 font-mono">→ {mark.target_tool}</span>
        {mark.trigger && (
          <span className="text-accent-warn font-mono">trigger: "{mark.trigger}"</span>
        )}
      </div>
      <details>
        <summary className="cursor-pointer text-ink-500 hover:text-ink-700 text-[11px]">
          payload
        </summary>
        <pre className="mt-1 whitespace-pre-wrap font-mono text-[11px] text-ink-700 break-words">
          {mark.payload}
        </pre>
      </details>
    </div>
  );
}

function ToolCallBlock({
  tc,
  isAttack,
}: {
  tc: NonNullable<TraceStep["tool_call"]>;
  isAttack: boolean;
}) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-1">
        <span className="font-mono text-sm text-ink-900">{tc.name}</span>
        {isAttack && (
          <span className="text-[10px] font-mono uppercase tracking-wide text-accent-attack bg-accent-attack/15 border border-accent-attack/40 rounded px-1.5 py-0.5">
            ATTACK LURE
          </span>
        )}
        <span className="text-[10px] font-mono text-ink-500">id={tc.id}</span>
      </div>
      <ArgsBlock args={tc.arguments} />
    </div>
  );
}

function ObservationBlock({
  obs,
  wasAttackTool,
  wasInjected,
}: {
  obs: NonNullable<TraceStep["observation"]>;
  wasAttackTool: boolean;
  wasInjected: boolean;
}) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-[10px] font-mono text-ink-500">←</span>
        <span className="font-mono text-sm text-ink-900">{obs.tool_name}</span>
        {wasAttackTool && (
          <span className="text-[10px] font-mono uppercase tracking-wide text-accent-attack bg-accent-attack/15 border border-accent-attack/40 rounded px-1.5 py-0.5">
            ATTACK HIT
          </span>
        )}
        {wasInjected && (
          <span className="text-[10px] font-mono uppercase tracking-wide text-accent-warn bg-accent-warn/15 border border-accent-warn/40 rounded px-1.5 py-0.5">
            opi-poisoned
          </span>
        )}
      </div>
      <ExpandableContent text={obs.content} mono />
    </div>
  );
}

function ArgsBlock({ args }: { args: Record<string, unknown> }) {
  const json = JSON.stringify(args, null, 2);
  if (Object.keys(args).length === 0) {
    return <div className="text-[11px] text-ink-500 font-mono">no arguments</div>;
  }
  return (
    <pre className="text-[11px] font-mono whitespace-pre-wrap text-ink-700 bg-bg-700/50 rounded p-2 max-h-32 overflow-auto">
      {json}
    </pre>
  );
}

function ExpandableContent({ text, mono }: { text: string; mono?: boolean }) {
  const [open, setOpen] = useState(text.length < 280);
  const preview = text.length > 280 ? `${text.slice(0, 280)}…` : text;
  return (
    <div>
      <div
        className={clsx(
          "text-sm whitespace-pre-wrap break-words text-ink-700",
          mono && "font-mono text-xs",
        )}
      >
        {open ? text : preview}
      </div>
      {text.length > 280 && (
        <button
          onClick={() => setOpen((v) => !v)}
          className="text-[11px] text-accent-info hover:underline mt-1"
        >
          {open ? "collapse" : `show all (${text.length} chars)`}
        </button>
      )}
    </div>
  );
}
