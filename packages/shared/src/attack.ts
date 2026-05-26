import { z } from "zod";

/**
 * High-level family of injection. Maps to one of the four attack vectors
 * formalized in the ASB paper, plus "clean" and "mixed" for orchestration.
 */
export const InjectionMethodSchema = z.enum([
  "direct_prompt_injection",
  "observation_prompt_injection",
  "memory_attack",
  "pot_backdoor",
  "clean",
  "mixed",
]);
export type InjectionMethod = z.infer<typeof InjectionMethodSchema>;

/**
 * Sub-variants of an attack — different phrasings of the malicious instruction.
 * Same names as the ASB Python implementation.
 */
export const AttackVariantSchema = z.enum([
  "naive",
  "fake_completion",
  "escape_characters",
  "context_ignoring",
  "combined_attack",
]);
export type AttackVariant = z.infer<typeof AttackVariantSchema>;

/**
 * One injection candidate built at runtime from a (method, variant, target_tool).
 * The `payload` is the actual string the framework will splice into the agent's
 * inputs at the appropriate channel.
 */
export const AttackPayloadSchema = z.object({
  method: InjectionMethodSchema,
  variant: AttackVariantSchema.optional(),
  target_tool: z.string(),
  target_args: z.record(z.string(), z.unknown()).default({}),
  /** Optional trigger phrase for PoT backdoor. */
  trigger: z.string().optional(),
  /** The fully rendered malicious string. */
  payload: z.string(),
});
export type AttackPayload = z.infer<typeof AttackPayloadSchema>;
