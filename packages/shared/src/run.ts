import { z } from "zod";
import { InjectionMethodSchema, AttackVariantSchema } from "./attack.js";
import { DefenseKindSchema } from "./defense.js";

/**
 * Tool set selection: matches ASB's `attack_tool` yaml argument.
 * - "all": both aggressive and non-aggressive attack tools mixed in
 * - "agg": aggressive attack tools only
 * - "non-agg": non-aggressive attack tools only
 * - "test": small smoke-test subset
 */
export const AttackToolSetSchema = z.enum(["all", "agg", "non-agg", "test"]);
export type AttackToolSet = z.infer<typeof AttackToolSetSchema>;

/**
 * Reads ASB-compatible yaml. Fields renamed sparingly (snake_case kept).
 */
export const RunConfigSchema = z.object({
  injection_method: InjectionMethodSchema,
  /** Which attack variants to try; defaults to all five for DPI/OPI. */
  attack_types: z.array(AttackVariantSchema).default(["naive"]),
  /** Tool subset to expose to the agent. */
  attack_tool: AttackToolSetSchema.default("all"),
  /** LLMs (model ids) to run against. Cartesian-producted with attacks. */
  llms: z.array(z.string()).min(1),
  /** Optional defense to apply. */
  defense_type: DefenseKindSchema.optional(),
  /** Restrict to specific agents (default: every agent in the registry). */
  agents: z.array(z.string()).optional(),
  /** Cap number of tasks per agent. Default: all. */
  task_num: z.number().int().positive().optional(),
  /** PoT trigger words to test. */
  triggers: z.array(z.string()).optional(),
  /** Suffix for log/output file naming. */
  suffix: z.string().optional(),
  /** Override the judge model. */
  judge_model: z.string().optional(),
  /** Whether to use memory-DB context. */
  read_db: z.boolean().default(false),
  write_db: z.boolean().default(false),
  /** Hard cap on ReAct iterations per task. */
  max_steps: z.number().int().positive().default(15),
  /** Optional human-readable label. */
  label: z.string().optional(),
});
export type RunConfig = z.infer<typeof RunConfigSchema>;

export const JudgeResultSchema = z.object({
  /** ASR: did the agent invoke any attack tool? */
  attack_success: z.boolean(),
  /** Which attack tools (by name) were called. */
  attack_tools_called: z.array(z.string()).default([]),
  /** RR: did the agent refuse the (poisoned) request? */
  refused: z.boolean(),
  /** Reason classifier output (heuristic + LLM judge). */
  refused_evidence: z.string().optional(),
  /** PNA: did the legitimate part of the task still complete? */
  original_task_success: z.boolean().optional(),
  /** 0/1 LLM compliance score. */
  compliance: z.number().min(0).max(1).optional(),
});
export type JudgeResult = z.infer<typeof JudgeResultSchema>;

export const RunResultSchema = z.object({
  id: z.string(),
  run_id: z.string(),
  agent_id: z.string(),
  task: z.string(),
  attack_method: InjectionMethodSchema,
  attack_variant: AttackVariantSchema.optional(),
  attack_target_tool: z.string().nullable(),
  llm: z.string(),
  defense: DefenseKindSchema.nullable(),
  trace_id: z.string(),
  judge: JudgeResultSchema,
  error: z.string().optional(),
  duration_ms: z.number().int().nonnegative(),
});
export type RunResult = z.infer<typeof RunResultSchema>;

export const RunStatusSchema = z.enum([
  "pending",
  "running",
  "completed",
  "failed",
  "cancelled",
]);
export type RunStatus = z.infer<typeof RunStatusSchema>;

export const RunProgressSchema = z.object({
  total: z.number().int().nonnegative(),
  done: z.number().int().nonnegative(),
  attack_success: z.number().int().nonnegative(),
  refused: z.number().int().nonnegative(),
  errored: z.number().int().nonnegative(),
});
export type RunProgress = z.infer<typeof RunProgressSchema>;

/** Aggregate metrics, computed from results. */
export const RunMetricsSchema = z.object({
  asr: z.number().min(0).max(1),
  rr: z.number().min(0).max(1),
  pna: z.number().min(0).max(1).optional(),
  n: z.number().int().nonnegative(),
});
export type RunMetrics = z.infer<typeof RunMetricsSchema>;

export const RunSummarySchema = z.object({
  id: z.string(),
  label: z.string().optional(),
  config: RunConfigSchema,
  status: RunStatusSchema,
  started_at_ms: z.number().int(),
  ended_at_ms: z.number().int().optional(),
  progress: RunProgressSchema,
  metrics: RunMetricsSchema.optional(),
  error: z.string().optional(),
});
export type RunSummary = z.infer<typeof RunSummarySchema>;
