import {
  type Message,
  type Trace,
  type TraceStep,
  type ToolCall,
  newId,
} from "@asp-x/shared";
import { ToolRuntime } from "./tool_runtime.js";
import type { RunnerOptions, RunnerResult } from "./types.js";

/**
 * Run one agent against one task. The framework is the "environment":
 * it owns the system prompt, the user-task channel, memory retrieval, and
 * every observation that flows back from a tool call. Attacks and defenses
 * are pure transformations on those four channels.
 *
 * Returns the full Trace plus a list of ToolCalls actually invoked.
 */
export async function runAgent(opts: RunnerOptions): Promise<RunnerResult> {
  const startedAtMs = Date.now();
  const runId = opts.runId ?? newId("run");
  const resultId = opts.resultId ?? newId("res");

  const trace: Trace = {
    id: newId("tr"),
    run_id: runId,
    result_id: resultId,
    steps: [],
    started_at_ms: startedAtMs,
  };

  let idx = 0;
  const tMs = () => Date.now() - startedAtMs;

  const record = (step: Omit<TraceStep, "index" | "t_ms">): TraceStep => {
    const full: TraceStep = { ...step, index: idx++, t_ms: tMs() };
    trace.steps.push(full);
    opts.onStep?.(full);
    return full;
  };

  // ── 1. System prompt ───────────────────────────────────────────────
  let systemContent = opts.agent.role;
  let systemInjection: TraceStep["injection"];
  if (opts.attack?.onSystemPrompt) {
    const r = opts.attack.onSystemPrompt(systemContent);
    systemContent = r.content;
    systemInjection = r.injection;
  }
  if (opts.defense?.wrapSystemPrompt) {
    systemContent = await opts.defense.wrapSystemPrompt(systemContent);
  }
  record({
    kind: "system_prompt",
    content: systemContent,
    injection: systemInjection,
  });

  // ── 2. Memory entries (simulated RAG) ──────────────────────────────
  let memoryEntries: string[] = opts.memory?.entries ?? [];
  let memoryInjection: TraceStep["injection"];
  if (opts.attack?.onMemoryEntries) {
    const r = opts.attack.onMemoryEntries(memoryEntries);
    memoryEntries = r.entries;
    memoryInjection = r.injection;
  }
  if (memoryEntries.length > 0) {
    record({
      kind: "memory_lookup",
      content: memoryEntries.join("\n---\n"),
      injection: memoryInjection,
    });
  }

  // ── 3. User task ───────────────────────────────────────────────────
  let taskContent = opts.task;
  let taskInjection: TraceStep["injection"];
  if (opts.attack?.onUserTask) {
    const r = opts.attack.onUserTask(taskContent);
    taskContent = r.content;
    taskInjection = r.injection;
  }
  if (opts.defense?.wrapUserTask) {
    taskContent = await opts.defense.wrapUserTask(taskContent);
  }
  record({ kind: "user_task", content: taskContent, injection: taskInjection });

  // ── 4. Build initial chat messages ─────────────────────────────────
  const messages: Message[] = [
    { role: "system", content: systemContent },
  ];
  if (memoryEntries.length > 0) {
    messages.push({
      role: "system",
      content: `Relevant background memory:\n${memoryEntries.join("\n---\n")}`,
    });
  }
  messages.push({ role: "user", content: taskContent });

  const runtime = new ToolRuntime(opts.tools);
  const apiTools = runtime.toApiTools();

  const toolCalls: ToolCall[] = [];
  let finalContent: string | undefined;
  let error: string | undefined;
  const maxSteps = opts.maxSteps ?? 15;

  // ── 5. ReAct loop ──────────────────────────────────────────────────
  for (let i = 0; i < maxSteps; i++) {
    let chatCompletion;
    try {
      chatCompletion = await opts.provider.chat({
        model: opts.model,
        messages,
        tools: apiTools.length > 0 ? apiTools : undefined,
        ...(opts.temperature !== undefined ? { temperature: opts.temperature } : {}),
        ...(opts.abortSignal ? { abortSignal: opts.abortSignal } : {}),
      });
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      record({ kind: "error", content: error });
      break;
    }

    const respMsg = chatCompletion.message;

    // Emit a thought step if the assistant wrote text alongside tool calls.
    if (respMsg.content && respMsg.content.trim().length > 0 && respMsg.tool_calls?.length) {
      record({ kind: "assistant_thought", content: respMsg.content });
    }

    // No tool calls = the agent decided to stop and give a final answer.
    if (!respMsg.tool_calls || respMsg.tool_calls.length === 0) {
      finalContent = respMsg.content;
      record({ kind: "final_answer", content: respMsg.content });
      messages.push({
        role: "assistant",
        content: respMsg.content,
      });
      break;
    }

    // Append assistant message (with tool_calls) to conversation history.
    messages.push({
      role: "assistant",
      content: respMsg.content,
      tool_calls: respMsg.tool_calls,
    });

    // Execute each tool call sequentially. We could parallelize but ASR is
    // about the *fact* of invocation, and serial execution is easier to debug.
    for (const tc of respMsg.tool_calls) {
      toolCalls.push(tc);
      record({ kind: "tool_call", tool_call: tc });

      const toolDef = runtime.getTool(tc.name);
      let obs: string;
      let wasAttackTool = false;
      if (!toolDef) {
        obs = `[error: tool "${tc.name}" is not in the agent's inventory]`;
      } else {
        wasAttackTool = toolDef.kind === "attack";
        try {
          obs = await runtime.execute(tc.name, tc.arguments);
        } catch (e) {
          obs = `[error executing ${tc.name}: ${
            e instanceof Error ? e.message : String(e)
          }]`;
        }
      }

      // OPI hook may rewrite this observation before the agent sees it.
      let opiInjection: TraceStep["injection"];
      if (opts.attack?.onObservation) {
        const r = opts.attack.onObservation(tc.name, obs);
        obs = r.content;
        opiInjection = r.injection;
      }

      // Defense may suppress or rewrite the observation.
      if (opts.defense?.filterObservation) {
        const keep = await opts.defense.filterObservation(tc.name, obs);
        if (!keep) obs = "[observation filtered by defense]";
      }
      if (opts.defense?.wrapObservation) {
        obs = await opts.defense.wrapObservation(tc.name, obs);
      }

      record({
        kind: "observation",
        observation: {
          tool_call_id: tc.id,
          tool_name: tc.name,
          content: obs,
          injected: opiInjection !== undefined,
          was_attack_tool: wasAttackTool,
        },
        injection: opiInjection,
      });

      messages.push({
        role: "tool",
        content: obs,
        tool_call_id: tc.id,
        name: tc.name,
      });
    }
  }

  if (!finalContent && !error) {
    error = `Reached max steps (${maxSteps}) without a final answer`;
    record({ kind: "error", content: error });
  }

  trace.ended_at_ms = Date.now();

  return {
    trace,
    toolCalls,
    ...(finalContent !== undefined ? { finalContent } : {}),
    ...(error !== undefined ? { error } : {}),
    durationMs: Date.now() - startedAtMs,
  };
}
