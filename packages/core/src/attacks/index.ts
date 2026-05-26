import type {
  AttackVariant,
  InjectionMethod,
  ToolDef,
} from "@asp-x/shared";
import type { AttackHook } from "../runner/types.js";
import { buildDpiAttack } from "./dpi.js";
import { buildOpiAttack } from "./opi.js";
import { buildMemoryAttack } from "./memory.js";
import { buildPoTBackdoorAttack } from "./pot.js";

export * from "./templates.js";
export * from "./dpi.js";
export * from "./opi.js";
export * from "./memory.js";
export * from "./pot.js";
export * from "./compose.js";

export interface BuildAttackArgs {
  method: InjectionMethod;
  variant: AttackVariant;
  tool: ToolDef;
  trigger?: string; // required for pot_backdoor
}

/**
 * Construct the AttackHook for a single (method, variant, tool) tuple.
 * Returns `undefined` for `method === "clean"`.
 *
 * For `method === "mixed"`, use composeAttacks() with multiple buildAttack calls.
 */
export function buildAttack(args: BuildAttackArgs): AttackHook | undefined {
  switch (args.method) {
    case "direct_prompt_injection":
      return buildDpiAttack({ variant: args.variant, tool: args.tool });
    case "observation_prompt_injection":
      return buildOpiAttack({ variant: args.variant, tool: args.tool });
    case "memory_attack":
      return buildMemoryAttack({ variant: args.variant, tool: args.tool });
    case "pot_backdoor": {
      if (!args.trigger) {
        throw new Error("pot_backdoor requires a trigger phrase");
      }
      return buildPoTBackdoorAttack({
        variant: args.variant,
        tool: args.tool,
        trigger: args.trigger,
      });
    }
    case "clean":
      return undefined;
    case "mixed":
      throw new Error(
        "method=mixed: use composeAttacks() with multiple buildAttack() calls",
      );
  }
}
