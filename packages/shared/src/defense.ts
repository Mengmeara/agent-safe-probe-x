import { z } from "zod";

/**
 * Defense methods supported. Names match ASB's yaml argument values.
 */
export const DefenseKindSchema = z.enum([
  "none",
  "delimiters_defense",
  "ob_sandwich_defense",
  "instructional_prevention",
  "direct_paraphrase_defense",
  "pot_paraphrase_defense",
  "pot_shuffling_defense",
  "dynamic_prompt_rewriting",
]);
export type DefenseKind = z.infer<typeof DefenseKindSchema>;
