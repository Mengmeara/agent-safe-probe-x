import type { ToolDef } from "@asp-x/shared";
import type { ChatTool } from "../llm/types.js";

/**
 * Holds the agent's full tool inventory (normal + attack lures) and knows
 * how to simulate executing each one. Tools never have real side effects;
 * ASR is detected by *which* tool got invoked, not by what it "did".
 */
export class ToolRuntime {
  private readonly byName = new Map<string, ToolDef>();

  constructor(public readonly tools: ToolDef[]) {
    for (const t of tools) this.byName.set(t.name, t);
  }

  getTool(name: string): ToolDef | undefined {
    return this.byName.get(name);
  }

  /** Render tool defs in the OpenAI function-calling schema. */
  toApiTools(): ChatTool[] {
    return this.tools.map((t) => ({
      type: "function" as const,
      function: {
        name: t.name,
        description: t.description,
        parameters: t.parameters ?? {
          type: "object",
          properties: {},
          required: [],
        },
      },
    }));
  }

  /**
   * Simulate execution. Returns the observation string the agent will see.
   * Throws if the requested tool isn't in the inventory.
   */
  async execute(
    name: string,
    args: Record<string, unknown>,
  ): Promise<string> {
    const t = this.byName.get(name);
    if (!t) throw new Error(`Tool "${name}" not registered`);
    if (t.response && t.response.length > 0) {
      return interpolate(t.response, args);
    }
    const marker = t.expected_achievement
      ? ` [achievement: ${t.expected_achievement}]`
      : "";
    const kind = t.kind === "attack" ? "ATTACK-LURE" : "ok";
    const argsStr = Object.keys(args).length ? ` args=${safeJson(args)}` : "";
    return `[${kind}] ${t.name} simulated.${marker}${argsStr}`;
  }
}

function interpolate(template: string, vars: Record<string, unknown>): string {
  return template.replace(/\{(\w+)\}/g, (_, k: string) =>
    vars[k] !== undefined ? String(vars[k]) : `{${k}}`,
  );
}

function safeJson(v: unknown): string {
  try {
    return JSON.stringify(v);
  } catch {
    return "[unserializable]";
  }
}
