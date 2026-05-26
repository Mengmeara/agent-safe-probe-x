import type { DefenseKind } from "@asp-x/shared";
import type { LLMProvider } from "../llm/types.js";
import type { DefenseHook } from "../runner/types.js";
import { buildDelimitersDefense } from "./delimiters.js";
import { buildInstructionalPreventionDefense } from "./instructional.js";
import { buildSandwichDefense } from "./sandwich.js";
import { buildParaphraseDefense } from "./paraphrase.js";
import { buildDynamicRewritingDefense } from "./dynamic_rewriting.js";
import { buildPoTShufflingDefense } from "./pot_shuffling.js";

export * from "./delimiters.js";
export * from "./instructional.js";
export * from "./sandwich.js";
export * from "./paraphrase.js";
export * from "./dynamic_rewriting.js";
export * from "./pot_shuffling.js";

export interface BuildDefenseArgs {
  kind: DefenseKind;
  /** Original user task (needed for sandwich). */
  task?: string;
  /** Required for LLM-based defenses (paraphrase / dynamic_rewriting). */
  provider?: LLMProvider;
  model?: string;
}

/**
 * Build a DefenseHook for the given DefenseKind. Throws if required
 * dependencies (e.g. an LLM provider for paraphrase) are missing.
 *
 * For ASB compatibility we treat `pot_paraphrase_defense` as the same as
 * `direct_paraphrase_defense` — both rephrase the user task.
 */
export function buildDefense(args: BuildDefenseArgs): DefenseHook | undefined {
  switch (args.kind) {
    case "none":
      return undefined;
    case "delimiters_defense":
      return buildDelimitersDefense();
    case "instructional_prevention":
      return buildInstructionalPreventionDefense();
    case "ob_sandwich_defense": {
      if (!args.task) {
        throw new Error("ob_sandwich_defense requires the original task text");
      }
      return buildSandwichDefense({ task: args.task });
    }
    case "direct_paraphrase_defense":
    case "pot_paraphrase_defense": {
      if (!args.provider || !args.model) {
        throw new Error(
          `${args.kind} requires { provider, model } to call the paraphrasing LLM`,
        );
      }
      return buildParaphraseDefense({
        provider: args.provider,
        model: args.model,
      });
    }
    case "dynamic_prompt_rewriting": {
      if (!args.provider || !args.model) {
        throw new Error(
          "dynamic_prompt_rewriting requires { provider, model } for the rewriter LLM",
        );
      }
      return buildDynamicRewritingDefense({
        provider: args.provider,
        model: args.model,
      });
    }
    case "pot_shuffling_defense":
      return buildPoTShufflingDefense();
  }
}
