import type {
  ChatCompletion,
  Message,
  ModelInfo,
  ToolCall,
} from "@asp-x/shared";

/**
 * OpenAI-style function tool definition.
 * `parameters` is JSON Schema (passed through to the model verbatim).
 */
export interface ChatTool {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: object;
  };
}

export type ToolChoice =
  | "auto"
  | "required"
  | "none"
  | { type: "function"; function: { name: string } };

export interface ChatArgs {
  model: string;
  messages: Message[];
  tools?: ChatTool[];
  tool_choice?: ToolChoice;
  temperature?: number;
  max_tokens?: number;
  abortSignal?: AbortSignal;
  /** Number of automatic retries on 429/5xx (default 2). */
  retries?: number;
}

export interface LLMProvider {
  readonly name: string;
  chat(args: ChatArgs): Promise<ChatCompletion>;
  listModels(): Promise<ModelInfo[]>;
}

export class LLMError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly body?: string,
  ) {
    super(message);
    this.name = "LLMError";
  }
}

/** Re-export for convenience. */
export type { ChatCompletion, Message, ModelInfo, ToolCall };
