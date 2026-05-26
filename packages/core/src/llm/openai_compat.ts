import type { ChatCompletion, Message, ModelInfo, ToolCall } from "@asp-x/shared";
import { ChatCompletionSchema } from "@asp-x/shared";
import {
  type ChatArgs,
  type ChatTool,
  type LLMProvider,
  LLMError,
} from "./types.js";

export interface OpenAICompatOpts {
  baseUrl: string;
  apiKey: string;
  /** Display name for this provider (e.g. "moyunsec"). */
  name?: string;
  /** Optional default headers (e.g. for API gateways). */
  headers?: Record<string, string>;
  /** Per-request timeout in ms. Default 60_000. */
  timeoutMs?: number;
}

/**
 * Provider that speaks the OpenAI /v1/chat/completions and /v1/models protocol.
 * Works with: OpenAI, Anthropic-via-proxy, Together, Groq, Ollama, vLLM,
 * and the moyunsec gateway we use for development.
 */
export class OpenAICompatProvider implements LLMProvider {
  readonly name: string;
  constructor(private readonly opts: OpenAICompatOpts) {
    this.name = opts.name ?? "openai-compat";
  }

  async chat(args: ChatArgs): Promise<ChatCompletion> {
    const body: Record<string, unknown> = {
      model: args.model,
      messages: args.messages.map(toApiMessage),
    };
    if (args.tools && args.tools.length > 0) body["tools"] = args.tools;
    if (args.tool_choice !== undefined) body["tool_choice"] = args.tool_choice;
    if (args.temperature !== undefined) body["temperature"] = args.temperature;
    if (args.max_tokens !== undefined) body["max_tokens"] = args.max_tokens;

    return this.requestWithRetry(
      "/chat/completions",
      body,
      args.abortSignal,
      args.retries ?? 2,
    ).then(parseChatResponse);
  }

  async listModels(): Promise<ModelInfo[]> {
    const json = await this.requestWithRetry("/models", undefined, undefined, 1);
    const data = (json as { data?: unknown }).data;
    if (!Array.isArray(data)) return [];
    return data.flatMap((m): ModelInfo[] => {
      if (!m || typeof m !== "object" || !("id" in m) || typeof m.id !== "string") {
        return [];
      }
      const provider =
        "owned_by" in m && typeof m.owned_by === "string" ? m.owned_by : undefined;
      return [
        {
          id: m.id,
          provider,
          supports_tool_use: true,
          labels: [],
        },
      ];
    });
  }

  private async requestWithRetry(
    path: string,
    body: unknown,
    signal: AbortSignal | undefined,
    retries: number,
  ): Promise<unknown> {
    const url = joinUrl(this.opts.baseUrl, path);
    const method = body === undefined ? "GET" : "POST";
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.opts.apiKey}`,
      "Content-Type": "application/json",
      Accept: "application/json",
      ...(this.opts.headers ?? {}),
    };

    let attempt = 0;
    let lastError: unknown;
    while (attempt <= retries) {
      const controller = new AbortController();
      const onAbort = () => controller.abort();
      signal?.addEventListener("abort", onAbort);
      const timeout = setTimeout(
        () => controller.abort(),
        this.opts.timeoutMs ?? 60_000,
      );
      try {
        const res = await fetch(url, {
          method,
          headers,
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: controller.signal,
        });
        if (res.ok) {
          return await res.json();
        }
        const text = await res.text().catch(() => "");
        // 429 + 5xx → retry with backoff
        if ((res.status === 429 || res.status >= 500) && attempt < retries) {
          await sleep(backoffMs(attempt));
          attempt += 1;
          continue;
        }
        throw new LLMError(
          `LLM request ${method} ${path} failed: ${res.status}`,
          res.status,
          text.slice(0, 800),
        );
      } catch (err) {
        if (
          err instanceof DOMException && err.name === "AbortError" &&
          signal?.aborted
        ) {
          throw err; // user-cancelled
        }
        lastError = err;
        if (attempt < retries) {
          await sleep(backoffMs(attempt));
          attempt += 1;
          continue;
        }
        throw err;
      } finally {
        clearTimeout(timeout);
        signal?.removeEventListener("abort", onAbort);
      }
    }
    throw lastError ?? new LLMError("LLM request failed after retries");
  }
}

function backoffMs(attempt: number): number {
  // 400ms, 1.2s, 3.6s
  return 400 * Math.pow(3, attempt);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function joinUrl(base: string, path: string): string {
  const b = base.endsWith("/") ? base.slice(0, -1) : base;
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${b}${p}`;
}

/** Convert our internal Message shape → OpenAI request shape. */
function toApiMessage(m: Message): Record<string, unknown> {
  const out: Record<string, unknown> = { role: m.role, content: m.content };
  if (m.tool_calls && m.tool_calls.length > 0) {
    out["tool_calls"] = m.tool_calls.map((tc) => ({
      id: tc.id,
      type: "function",
      function: {
        name: tc.name,
        arguments: JSON.stringify(tc.arguments ?? {}),
      },
    }));
    // OpenAI requires content to be null when only tool_calls are emitted.
    if (!m.content || m.content.length === 0) out["content"] = null;
  }
  if (m.tool_call_id) out["tool_call_id"] = m.tool_call_id;
  if (m.name) out["name"] = m.name;
  return out;
}

/** Convert OpenAI chat completion response → our internal ChatCompletion. */
function parseChatResponse(raw: unknown): ChatCompletion {
  const root = raw as {
    choices?: Array<{
      message?: {
        role?: string;
        content?: string | null;
        tool_calls?: Array<{
          id?: string;
          type?: string;
          function?: { name?: string; arguments?: string };
        }>;
      };
      finish_reason?: string;
    }>;
    usage?: {
      prompt_tokens?: number;
      completion_tokens?: number;
      total_tokens?: number;
    };
  };

  const choice = root.choices?.[0];
  if (!choice || !choice.message) {
    throw new LLMError(
      "LLM response missing choices[0].message",
      undefined,
      JSON.stringify(raw).slice(0, 500),
    );
  }

  const apiMsg = choice.message;
  const tool_calls: ToolCall[] = (apiMsg.tool_calls ?? []).flatMap((tc) => {
    if (!tc.id || !tc.function?.name) return [];
    let args: Record<string, unknown> = {};
    if (tc.function.arguments) {
      try {
        const parsed = JSON.parse(tc.function.arguments);
        if (parsed && typeof parsed === "object") args = parsed as Record<string, unknown>;
      } catch {
        args = { _raw: tc.function.arguments };
      }
    }
    return [{ id: tc.id, name: tc.function.name, arguments: args }];
  });

  const message = {
    role: (apiMsg.role ?? "assistant") as "assistant",
    content: typeof apiMsg.content === "string" ? apiMsg.content : "",
    ...(tool_calls.length > 0 ? { tool_calls } : {}),
  };

  const completion: Record<string, unknown> = { message };
  if (choice.finish_reason) completion["finish_reason"] = choice.finish_reason;
  if (root.usage) completion["usage"] = root.usage;

  return ChatCompletionSchema.parse(completion);
}
