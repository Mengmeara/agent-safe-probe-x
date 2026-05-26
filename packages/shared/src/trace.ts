import { z } from "zod";
import { ToolCallSchema } from "./llm.js";
import { InjectionMethodSchema, AttackVariantSchema } from "./attack.js";

/**
 * Kinds of events that may appear in an agent execution trace.
 * Kept finer-grained than role= for visualization purposes.
 */
export const TraceStepKindSchema = z.enum([
  "system_prompt",   // initial system message
  "user_task",       // the (possibly poisoned) user task
  "memory_lookup",   // pseudo-step for memory retrieval context
  "assistant_thought", // assistant text without tool call
  "tool_call",       // assistant invoked a tool
  "observation",     // tool result returned to the agent
  "final_answer",    // assistant's terminating message
  "error",           // runtime/model error
]);
export type TraceStepKind = z.infer<typeof TraceStepKindSchema>;

/**
 * Description of an injection that touched this step.
 * Surfaced on whichever step carries the poisoned content.
 */
export const InjectionMarkSchema = z.object({
  method: InjectionMethodSchema,
  variant: AttackVariantSchema.optional(),
  target_tool: z.string(),
  payload: z.string(),
  /** PoT trigger phrase, when method === "pot_backdoor". */
  trigger: z.string().optional(),
});
export type InjectionMark = z.infer<typeof InjectionMarkSchema>;

export const TraceObservationSchema = z.object({
  tool_call_id: z.string(),
  tool_name: z.string(),
  content: z.string(),
  /** True if the framework substituted/augmented this observation. */
  injected: z.boolean().default(false),
  /** True if calling this tool counts as an ASR hit. */
  was_attack_tool: z.boolean().default(false),
});
export type TraceObservation = z.infer<typeof TraceObservationSchema>;

export const TraceStepSchema = z.object({
  index: z.number().int().nonnegative(),
  kind: TraceStepKindSchema,
  /** Plain-text content for system/user/thought/final/error. */
  content: z.string().optional(),
  /** For kind === "tool_call". */
  tool_call: ToolCallSchema.optional(),
  /** For kind === "observation". */
  observation: TraceObservationSchema.optional(),
  /** Optional injection annotation. */
  injection: InjectionMarkSchema.optional(),
  /** Milliseconds since trace start. */
  t_ms: z.number().int().nonnegative(),
});
export type TraceStep = z.infer<typeof TraceStepSchema>;

export const TraceSchema = z.object({
  id: z.string(),
  run_id: z.string(),
  /** Foreign key into RunResult.id for the unit-of-work this trace records. */
  result_id: z.string(),
  steps: z.array(TraceStepSchema),
  started_at_ms: z.number().int(),
  ended_at_ms: z.number().int().optional(),
});
export type Trace = z.infer<typeof TraceSchema>;
