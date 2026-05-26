import type { DefenseHook } from "../runner/types.js";

/**
 * Delimiters defense: wrap the user task in `<start>...<end>` markers,
 * relying on the model to honour the brackets as a trust boundary.
 * Mirrors ASB's `task_input = f"<start>{task_input}<end>"`.
 */
export function buildDelimitersDefense(): DefenseHook {
  return {
    wrapUserTask: (task) => `<start>${task}<end>`,
  };
}
