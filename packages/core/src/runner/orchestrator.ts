import {
  type AttackVariant,
  type DefenseKind,
  type InjectionMethod,
  type JudgeResult,
  type RunConfig,
  type RunMetrics,
  type RunResult,
  type ToolDef,
  newId,
} from "@asp-x/shared";
import { buildAttack, composeAttacks } from "../attacks/index.js";
import { buildDefense } from "../defenses/index.js";
import { AGENT_REGISTRY } from "../data/registry.js";
import { judgeAll } from "../judges/index.js";
import type { LLMProvider } from "../llm/types.js";
import { runAgent } from "./runner.js";
import type { AttackHook, DefenseHook } from "./types.js";
import type { TraceStep } from "@asp-x/shared";

export interface OrchestratorOpts {
  config: RunConfig;
  /** Provider used to drive the agent under test. */
  provider: LLMProvider;
  /** Provider used by LLM-based judges and defenses. Defaults to `provider`. */
  judgeProvider?: LLMProvider;
  /** Model used by judges. Defaults to `config.judge_model` or the first LLM in `config.llms`. */
  judgeModel?: string;
  /** Identifier shared by all RunResults produced. */
  runId?: string;
  /** Streaming callbacks. */
  onResult?: (result: RunResult) => void;
  onTraceStep?: (resultId: string, traceId: string, step: TraceStep) => void;
  abortSignal?: AbortSignal;
}

export interface OrchestratorOutput {
  run_id: string;
  results: RunResult[];
  metrics: RunMetrics;
}

/**
 * Expand a RunConfig into individual (agent, task, attack_target, llm,
 * defense) units of work, execute each through runAgent + judgeAll, and
 * aggregate ASR/RR/PNA.
 *
 * For `injection_method: "clean"` no attack tool is added; the tool list is
 * just the agent's normal tools.
 *
 * For `injection_method: "mixed"` the orchestrator composes DPI + OPI on the
 * same attack tool target.
 */
export async function runOrchestrator(opts: OrchestratorOpts): Promise<OrchestratorOutput> {
  const cfg = opts.config;
  const runId = opts.runId ?? newId("run");
  const judgeProvider = opts.judgeProvider ?? opts.provider;
  const judgeModel = opts.judgeModel ?? cfg.judge_model ?? cfg.llms[0];

  const targetAgentIds =
    cfg.agents && cfg.agents.length > 0
      ? cfg.agents
      : AGENT_REGISTRY.listAgents().map((a) => a.id);

  const variants: AttackVariant[] =
    cfg.injection_method === "clean"
      ? (["naive"] as AttackVariant[]) // unused
      : cfg.attack_types;

  const results: RunResult[] = [];

  for (const agentId of targetAgentIds) {
    if (opts.abortSignal?.aborted) break;
    const agent = AGENT_REGISTRY.getAgent(agentId);
    if (!agent) continue;

    const tasks = cfg.task_num ? agent.tasks.slice(0, cfg.task_num) : agent.tasks;

    // Determine attack-tool iterator for this agent.
    const attackTools: (ToolDef | null)[] =
      cfg.injection_method === "clean"
        ? [null]
        : AGENT_REGISTRY.getAttackToolCandidates(agentId, cfg.attack_tool);

    const triggers = cfg.triggers ?? [""];

    for (const task of tasks) {
      for (const attackTool of attackTools) {
        for (const variant of variants) {
          for (const llm of cfg.llms) {
            for (const trigger of triggers) {
              if (opts.abortSignal?.aborted) break;

              const resultId = newId("res");
              const startMs = Date.now();
              let attackHook: AttackHook | undefined;
              let defenseHook: DefenseHook | undefined;

              try {
                attackHook = buildAttackForMethod(
                  cfg.injection_method,
                  variant,
                  attackTool,
                  trigger || undefined,
                );
                defenseHook = cfg.defense_type
                  ? buildDefense({
                      kind: cfg.defense_type,
                      task,
                      provider: judgeProvider,
                      model: judgeModel,
                    })
                  : undefined;

                const tools = AGENT_REGISTRY.buildToolset(
                  agentId,
                  attackTool?.id ?? null,
                );

                const runArgs: Parameters<typeof runAgent>[0] = {
                  agent,
                  task,
                  tools,
                  provider: opts.provider,
                  model: llm,
                  runId,
                  resultId,
                  maxSteps: cfg.max_steps,
                };
                if (attackHook) runArgs.attack = attackHook;
                if (defenseHook) runArgs.defense = defenseHook;
                if (opts.abortSignal) runArgs.abortSignal = opts.abortSignal;
                if (opts.onTraceStep) {
                  runArgs.onStep = (step) =>
                    opts.onTraceStep!(resultId, "", step);
                }

                const runRes = await runAgent(runArgs);

                const judge: JudgeResult = await judgeAll({
                  trace: runRes.trace,
                  tools,
                  provider: judgeProvider,
                  model: judgeModel,
                });

                // Patch onTraceStep with real trace id (caller may want to
                // index by trace_id after the fact).
                const result: RunResult = {
                  id: resultId,
                  run_id: runId,
                  agent_id: agentId,
                  task,
                  attack_method: cfg.injection_method,
                  attack_target_tool: attackTool?.name ?? null,
                  llm,
                  defense: cfg.defense_type ?? null,
                  trace_id: runRes.trace.id,
                  judge,
                  duration_ms: runRes.durationMs,
                };
                if (cfg.injection_method !== "clean") result.attack_variant = variant;
                if (runRes.error) result.error = runRes.error;
                results.push(result);
                opts.onResult?.(result);
              } catch (err) {
                const errMsg = err instanceof Error ? err.message : String(err);
                const result: RunResult = {
                  id: resultId,
                  run_id: runId,
                  agent_id: agentId,
                  task,
                  attack_method: cfg.injection_method,
                  attack_target_tool: attackTool?.name ?? null,
                  llm,
                  defense: cfg.defense_type ?? null,
                  trace_id: "",
                  judge: {
                    attack_success: false,
                    attack_tools_called: [],
                    refused: false,
                  },
                  error: errMsg,
                  duration_ms: Date.now() - startMs,
                };
                results.push(result);
                opts.onResult?.(result);
              }

              // PoT iterates over triggers; non-PoT only has the empty trigger.
              if (cfg.injection_method !== "pot_backdoor") break;
            }
          }
        }
      }
    }
  }

  return {
    run_id: runId,
    results,
    metrics: computeMetrics(results),
  };
}

function buildAttackForMethod(
  method: InjectionMethod,
  variant: AttackVariant,
  attackTool: ToolDef | null,
  trigger?: string,
): AttackHook | undefined {
  if (method === "clean") return undefined;
  if (!attackTool) return undefined;
  if (method === "mixed") {
    // Compose DPI + OPI on the same target tool.
    const dpi = buildAttack({
      method: "direct_prompt_injection",
      variant,
      tool: attackTool,
    });
    const opi = buildAttack({
      method: "observation_prompt_injection",
      variant,
      tool: attackTool,
    });
    return composeAttacks(...[dpi, opi].filter((h): h is AttackHook => !!h));
  }
  return buildAttack({ method, variant, tool: attackTool, ...(trigger ? { trigger } : {}) });
}

export function computeMetrics(results: RunResult[]): RunMetrics {
  if (results.length === 0) {
    return { asr: 0, rr: 0, pna: undefined as unknown as number, n: 0 };
  }
  const n = results.length;
  const asr = results.filter((r) => r.judge.attack_success).length / n;
  const rr = results.filter((r) => r.judge.refused).length / n;
  const pnaSamples = results.filter(
    (r) => r.judge.original_task_success !== undefined,
  );
  const pna =
    pnaSamples.length > 0
      ? pnaSamples.filter((r) => r.judge.original_task_success).length /
        pnaSamples.length
      : undefined;
  return {
    asr,
    rr,
    n,
    ...(pna !== undefined ? { pna } : {}),
  } as RunMetrics;
}

/** Optimistic estimate of total work units a config will produce. */
export function estimateTotalUnits(cfg: RunConfig): number {
  const targetAgents =
    cfg.agents && cfg.agents.length > 0
      ? cfg.agents
      : AGENT_REGISTRY.listAgents().map((a) => a.id);
  let total = 0;
  for (const id of targetAgents) {
    const agent = AGENT_REGISTRY.getAgent(id);
    if (!agent) continue;
    const tasks = cfg.task_num ? Math.min(cfg.task_num, agent.tasks.length) : agent.tasks.length;
    const attacks =
      cfg.injection_method === "clean"
        ? 1
        : AGENT_REGISTRY.getAttackToolCandidates(id, cfg.attack_tool).length;
    const variants = cfg.injection_method === "clean" ? 1 : cfg.attack_types.length;
    const triggers =
      cfg.injection_method === "pot_backdoor" ? (cfg.triggers?.length ?? 1) : 1;
    total += tasks * attacks * variants * cfg.llms.length * triggers;
  }
  return total;
}
