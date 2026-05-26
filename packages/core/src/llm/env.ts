import { OpenAICompatProvider } from "./openai_compat.js";
import { ProviderRegistry } from "./registry.js";

export interface AspXLLMEnv {
  baseUrl: string;
  apiKey: string;
  defaultModel: string;
  judgeModel: string;
}

/**
 * Read LLM config from environment variables.
 * Throws if the API key or base URL is missing.
 */
export function readLLMEnv(env: NodeJS.ProcessEnv = process.env): AspXLLMEnv {
  const baseUrl = env["ASP_X_LLM_BASE_URL"];
  const apiKey = env["ASP_X_LLM_API_KEY"];
  const defaultModel = env["ASP_X_DEFAULT_MODEL"] ?? "gpt-4o-mini";
  const judgeModel = env["ASP_X_JUDGE_MODEL"] ?? defaultModel;
  if (!baseUrl) throw new Error("ASP_X_LLM_BASE_URL is not set");
  if (!apiKey) throw new Error("ASP_X_LLM_API_KEY is not set");
  return { baseUrl, apiKey, defaultModel, judgeModel };
}

/**
 * Build a ProviderRegistry from env: one OpenAI-compat provider serving all models.
 */
export function buildDefaultRegistry(env: AspXLLMEnv = readLLMEnv()): ProviderRegistry {
  const reg = new ProviderRegistry();
  reg.register(
    new OpenAICompatProvider({
      baseUrl: env.baseUrl,
      apiKey: env.apiKey,
      name: "default",
    }),
    "*",
  );
  return reg;
}
