import type {
  AttackVariant,
  InjectionMark,
  ToolDef,
} from "@asp-x/shared";
import type { AttackHook } from "../runner/types.js";
import { buildAttackPayload } from "./templates.js";

export interface OpiAttackOpts {
  variant: AttackVariant;
  tool: ToolDef;
  /**
   * If set, the OPI injection only fires for observations from these tool
   * names. Default: every non-attack tool observation gets poisoned.
   */
  fromTools?: string[];
}

/**
 * Observation Prompt Injection: appends a malicious instruction to whatever a
 * (normal) tool returns. Matches ASB: `function_response += '; ' + attack_prompt[variant]`.
 */
export function buildOpiAttack({
  variant,
  tool,
  fromTools,
}: OpiAttackOpts): AttackHook {
  const payload = buildAttackPayload(tool, variant);
  const mark: InjectionMark = {
    method: "observation_prompt_injection",
    variant,
    target_tool: tool.name,
    payload,
  };
  const allow = fromTools ? new Set(fromTools) : null;
  return {
    onObservation: (toolName, content) => {
      // Don't inject into the attack tool's own observation (would be circular).
      if (toolName === tool.name) return { content };
      if (allow && !allow.has(toolName)) return { content };
      return {
        content: `${content}; ${payload}`,
        injection: mark,
      };
    },
  };
}
