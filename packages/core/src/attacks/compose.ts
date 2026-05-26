import type { AttackHook } from "../runner/types.js";

/**
 * Compose multiple attack hooks into one. Same-channel hooks chain: later
 * hook receives the output of the earlier hook. Injection annotations from
 * the latest hook on each channel win (this is fine — mixed attacks usually
 * use a single hook per channel).
 *
 * No-op when given an empty list.
 */
export function composeAttacks(...hooks: AttackHook[]): AttackHook | undefined {
  if (hooks.length === 0) return undefined;
  if (hooks.length === 1) return hooks[0]!;

  return {
    onSystemPrompt(prompt) {
      let content = prompt;
      let injection;
      for (const h of hooks) {
        if (!h.onSystemPrompt) continue;
        const r = h.onSystemPrompt(content);
        content = r.content;
        if (r.injection) injection = r.injection;
      }
      return injection ? { content, injection } : { content };
    },
    onUserTask(task) {
      let content = task;
      let injection;
      for (const h of hooks) {
        if (!h.onUserTask) continue;
        const r = h.onUserTask(content);
        content = r.content;
        if (r.injection) injection = r.injection;
      }
      return injection ? { content, injection } : { content };
    },
    onMemoryEntries(entries) {
      let current = entries;
      let injection;
      for (const h of hooks) {
        if (!h.onMemoryEntries) continue;
        const r = h.onMemoryEntries(current);
        current = r.entries;
        if (r.injection) injection = r.injection;
      }
      return injection ? { entries: current, injection } : { entries: current };
    },
    onObservation(toolName, content) {
      let cur = content;
      let injection;
      for (const h of hooks) {
        if (!h.onObservation) continue;
        const r = h.onObservation(toolName, cur);
        cur = r.content;
        if (r.injection) injection = r.injection;
      }
      return injection ? { content: cur, injection } : { content: cur };
    },
  };
}
