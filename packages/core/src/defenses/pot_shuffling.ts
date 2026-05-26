import type { DefenseHook } from "../runner/types.js";

/**
 * Marker the PoT attack emits around its few-shot example list, so this
 * defense can find and shuffle them deterministically.
 */
export const POT_EXAMPLES_OPEN = "<<<POT_EXAMPLES>>>";
export const POT_EXAMPLES_CLOSE = "<<<END_POT_EXAMPLES>>>";

/**
 * Deterministic shuffler with a fixed seed (mirrors ASB's `random.seed(0)`
 * before its few-shot shuffle).
 */
function shuffleDeterministic<T>(arr: T[], seed = 0): T[] {
  const out = [...arr];
  // Mulberry32 PRNG for reproducibility across runtimes
  let s = seed | 0;
  const rand = () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [out[i]!, out[j]!] = [out[j]!, out[i]!];
  }
  return out;
}

export interface PoTShufflingOpts {
  seed?: number;
}

/**
 * PoT Shuffling Defense: locates the few-shot example list planted by the
 * PoT attack (delimited by POT_EXAMPLES_OPEN/CLOSE) and shuffles those
 * examples with a fixed seed. Disrupts the trigger→tool association the
 * backdoor relies on.
 */
export function buildPoTShufflingDefense(opts: PoTShufflingOpts = {}): DefenseHook {
  const seed = opts.seed ?? 0;
  return {
    wrapSystemPrompt: (prompt) => {
      const open = prompt.indexOf(POT_EXAMPLES_OPEN);
      const close = prompt.indexOf(POT_EXAMPLES_CLOSE);
      if (open === -1 || close === -1 || close <= open) return prompt;
      const before = prompt.slice(0, open + POT_EXAMPLES_OPEN.length);
      const block = prompt.slice(open + POT_EXAMPLES_OPEN.length, close);
      const after = prompt.slice(close);
      const lines = block
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      const shuffled = shuffleDeterministic(lines, seed);
      return `${before}\n${shuffled.join("\n")}\n${after}`;
    },
  };
}
