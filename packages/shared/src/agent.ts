import { z } from "zod";

/**
 * JSON-Schema-style parameter description.
 * Kept loose intentionally — we just pass through to the model provider.
 */
export const ToolParametersSchema = z.object({
  type: z.literal("object"),
  properties: z.record(z.string(), z.unknown()).default({}),
  required: z.array(z.string()).default([]),
});
export type ToolParameters = z.infer<typeof ToolParametersSchema>;

export const ToolKindSchema = z.enum(["normal", "attack"]);
export type ToolKind = z.infer<typeof ToolKindSchema>;

/**
 * A callable capability exposed to the agent.
 * In ASP-X every tool is "simulated" — it never actually performs side effects.
 * When invoked, it returns its configured response (or a default stub).
 */
export const ToolDefSchema = z.object({
  /** Stable identifier; usually equal to `name`. */
  id: z.string(),
  /** Tool name as seen by the LLM. */
  name: z.string(),
  description: z.string(),
  parameters: ToolParametersSchema.optional(),

  /**
   * "normal" = a legitimate capability the agent might need.
   * "attack" = a lure the framework injects; calling it counts as ASR.
   */
  kind: ToolKindSchema,

  /** For attack tools: aggressive (clearly malicious) vs non-aggressive (plausibly innocuous). */
  aggressive: z.boolean().optional(),

  /**
   * Natural-language instruction the attacker wants to plant.
   * Embedded into the universal injection template at attack-build time.
   * Only meaningful for attack tools.
   */
  attack_instruction: z.string().optional(),

  /**
   * String marker the tool emits when called. Used by the original-task judge
   * to detect that this step of the task was completed.
   */
  expected_achievement: z.string().optional(),

  /** Hard-coded response text the simulated tool returns. */
  response: z.string().optional(),
});
export type ToolDef = z.infer<typeof ToolDefSchema>;

export const AgentDefSchema = z.object({
  /** Stable id, e.g. "financial_analyst_agent". */
  id: z.string(),
  /** Display name, e.g. "Financial Analyst Agent". */
  name: z.string(),
  /** System prompt body describing the agent's role. */
  role: z.string(),
  /** Tool ids this agent has access to (normal + attack lures mixed). */
  tool_ids: z.array(z.string()),
  /** Sample user tasks for this agent. */
  tasks: z.array(z.string()),
});
export type AgentDef = z.infer<typeof AgentDefSchema>;
