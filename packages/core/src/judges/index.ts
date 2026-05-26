import type { JudgeResult, ToolDef, Trace } from "@asp-x/shared";
import type { LLMProvider } from "../llm/types.js";
import { judgeAttackSuccess } from "./attack_success.js";
import { judgeRefusalHeuristic, judgeRefusalWithLLM } from "./refusal.js";
import { judgeOriginalTaskSuccess } from "./original_success.js";

export * from "./attack_success.js";
export * from "./refusal.js";
export * from "./original_success.js";

export interface JudgeOpts {
  trace: Trace;
  tools: ToolDef[];
  /**
   * If both `provider` and `model` are supplied, the refusal judge uses the
   * LLM. Otherwise it falls back to the heuristic.
   */
  provider?: LLMProvider;
  model?: string;
}

/** Run all three judges and assemble a JudgeResult. */
export async function judgeAll(opts: JudgeOpts): Promise<JudgeResult> {
  const asr = judgeAttackSuccess(opts.trace);
  const pna = judgeOriginalTaskSuccess(opts.trace, opts.tools);

  let refusal: { refused: boolean; compliance?: number; evidence?: string };
  if (opts.provider && opts.model) {
    const llm = await judgeRefusalWithLLM(opts.trace, opts.provider, opts.model);
    refusal = {
      refused: llm.refused,
      ...(llm.compliance !== null ? { compliance: llm.compliance } : {}),
      ...(llm.evidence ? { evidence: llm.evidence } : {}),
    };
  } else {
    const h = judgeRefusalHeuristic(opts.trace);
    refusal = {
      refused: h.refused,
      ...(h.matched ? { evidence: `heuristic match: ${h.matched}` } : {}),
    };
  }

  const result: JudgeResult = {
    attack_success: asr.attack_success,
    attack_tools_called: asr.attack_tools_called,
    refused: refusal.refused,
    original_task_success: pna.original_task_success,
  };
  if (refusal.evidence) result.refused_evidence = refusal.evidence;
  if (refusal.compliance !== undefined) result.compliance = refusal.compliance;
  return result;
}
