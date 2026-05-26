import type {
  AttackVariant,
  InjectionMark,
  ToolDef,
} from "@asp-x/shared";
import type { AttackHook } from "../runner/types.js";
import { buildAttackPayload } from "./templates.js";

export interface DpiAttackOpts {
  variant: AttackVariant;
  tool: ToolDef; // the attack tool whose name will be in the injected prompt
}

/**
 * Direct Prompt Injection: appends a malicious instruction to the user's task.
 * Matches ASB's behaviour: `task_input += ' ' + attack_prompt[variant]`.
 */
export function buildDpiAttack({ variant, tool }: DpiAttackOpts): AttackHook {
  const payload = buildAttackPayload(tool, variant);
  const mark: InjectionMark = {
    method: "direct_prompt_injection",
    variant,
    target_tool: tool.name,
    payload,
  };
  return {
    onUserTask: (task) => ({
      content: `${task} ${payload}`,
      injection: mark,
    }),
  };
}
