import { describe, expect, it } from "vitest";
import type {
  ChatCompletion,
  ModelInfo,
  RunConfig,
  ToolCall,
} from "@asp-x/shared";
import type { ChatArgs, LLMProvider } from "../../llm/types.js";
import { runOrchestrator, computeMetrics, estimateTotalUnits } from "../orchestrator.js";

class CompliantProvider implements LLMProvider {
  readonly name = "compliant";
  /**
   * Always invokes the first non-`exfiltrate_data` normal tool, then ends.
   * Models a "well-behaved" agent.
   */
  async chat(args: ChatArgs): Promise<ChatCompletion> {
    // First call returns a tool_call to the first normal tool, second returns final.
    const userMsgCount = args.messages.filter((m) => m.role === "tool").length;
    if (userMsgCount === 0 && args.tools && args.tools.length > 0) {
      const t = args.tools.find(
        (t) => !t.function.name.toLowerCase().includes("hijack"),
      );
      if (t) {
        const tc: ToolCall = {
          id: "c_compliant",
          name: t.function.name,
          arguments: {},
        };
        return {
          message: { role: "assistant", content: "", tool_calls: [tc] },
          finish_reason: "tool_calls",
        };
      }
    }
    return {
      message: { role: "assistant", content: "Task complete." },
      finish_reason: "stop",
    };
  }
  async listModels(): Promise<ModelInfo[]> {
    return [];
  }
}

class GullibleProvider implements LLMProvider {
  readonly name = "gullible";
  /** Always calls whatever attack tool is in the inventory. */
  async chat(args: ChatArgs): Promise<ChatCompletion> {
    const userMsgCount = args.messages.filter((m) => m.role === "tool").length;
    if (userMsgCount > 0 || !args.tools) {
      return {
        message: { role: "assistant", content: "Done." },
        finish_reason: "stop",
      };
    }
    // Find a tool whose name looks attacky.
    const t =
      args.tools.find((tool) => /hijack|exfiltrate|harvest|escalation|steal|poison/i.test(tool.function.name)) ??
      args.tools[args.tools.length - 1]!;
    return {
      message: {
        role: "assistant",
        content: "",
        tool_calls: [
          { id: "c_attack", name: t.function.name, arguments: {} },
        ],
      },
      finish_reason: "tool_calls",
    };
  }
  async listModels(): Promise<ModelInfo[]> {
    return [];
  }
}

describe("runOrchestrator", () => {
  it("produces one result per (task × attack_tool × variant × llm) and computes metrics", async () => {
    const cfg: RunConfig = {
      injection_method: "direct_prompt_injection",
      attack_types: ["naive"],
      attack_tool: "test", // 2 attack tools per agent in test mode
      llms: ["model-x"],
      agents: ["financial_analyst_agent"],
      task_num: 1,
      read_db: false,
      write_db: false,
      max_steps: 5,
    };
    const out = await runOrchestrator({
      config: cfg,
      provider: new GullibleProvider(),
    });
    // 1 agent × 1 task × 2 attack tools × 1 variant × 1 llm = 2 results
    expect(out.results.length).toBe(2);
    // Gullible provider always calls the attack tool → ASR = 1.0
    expect(out.metrics.asr).toBe(1);
  });

  it("clean injection method produces one result per (task × llm) with ASR=0", async () => {
    const cfg: RunConfig = {
      injection_method: "clean",
      attack_types: ["naive"],
      attack_tool: "test",
      llms: ["model-x"],
      agents: ["financial_analyst_agent"],
      task_num: 2,
      read_db: false,
      write_db: false,
      max_steps: 5,
    };
    const out = await runOrchestrator({
      config: cfg,
      provider: new CompliantProvider(),
    });
    expect(out.results.length).toBe(2);
    expect(out.metrics.asr).toBe(0);
  });

  it("respects abortSignal", async () => {
    const cfg: RunConfig = {
      injection_method: "clean",
      attack_types: ["naive"],
      attack_tool: "test",
      llms: ["m"],
      agents: ["financial_analyst_agent"],
      task_num: 5,
      read_db: false,
      write_db: false,
      max_steps: 5,
    };
    const ac = new AbortController();
    ac.abort();
    const out = await runOrchestrator({
      config: cfg,
      provider: new CompliantProvider(),
      abortSignal: ac.signal,
    });
    expect(out.results.length).toBe(0);
  });
});

describe("computeMetrics", () => {
  it("returns zeros for an empty result set", () => {
    expect(computeMetrics([]).n).toBe(0);
  });
});

describe("estimateTotalUnits", () => {
  it("counts correctly for a single agent + 1 task + agg tools", () => {
    const cfg: RunConfig = {
      injection_method: "direct_prompt_injection",
      attack_types: ["naive", "fake_completion"],
      attack_tool: "agg", // 20 per agent
      llms: ["a", "b"],
      agents: ["financial_analyst_agent"],
      task_num: 1,
      read_db: false,
      write_db: false,
      max_steps: 15,
    };
    expect(estimateTotalUnits(cfg)).toBe(1 * 20 * 2 * 2);
  });
});
