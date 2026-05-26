import type { LLMProvider } from "./types.js";

/**
 * Maps a model id to a provider instance. Useful when one process talks
 * to multiple backends — for ASP-X dev we only have one (moyunsec).
 */
export class ProviderRegistry {
  private readonly map = new Map<string, LLMProvider>();

  /** Register a provider with the model ids it can serve. */
  register(provider: LLMProvider, modelIds: string[] | "*" = "*"): void {
    if (modelIds === "*") {
      this.map.set("*", provider);
    } else {
      for (const id of modelIds) this.map.set(id, provider);
    }
  }

  resolve(modelId: string): LLMProvider {
    const direct = this.map.get(modelId);
    if (direct) return direct;
    const wildcard = this.map.get("*");
    if (wildcard) return wildcard;
    throw new Error(
      `No provider registered for model "${modelId}" and no wildcard provider set`,
    );
  }
}
