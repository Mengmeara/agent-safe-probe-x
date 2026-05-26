import { z } from "zod";

/**
 * One participant role in a chat conversation.
 * `tool` is the OpenAI-style role for messages carrying tool-call results.
 */
export const RoleSchema = z.enum(["system", "user", "assistant", "tool"]);
export type Role = z.infer<typeof RoleSchema>;

/**
 * A single tool invocation requested by the assistant.
 * Mirrors the OpenAI tool_calls[] item.
 */
export const ToolCallSchema = z.object({
  id: z.string(),
  name: z.string(),
  arguments: z.record(z.string(), z.unknown()).default({}),
});
export type ToolCall = z.infer<typeof ToolCallSchema>;

export const MessageSchema = z.object({
  role: RoleSchema,
  /** Free-form text. Empty when the assistant only emits tool_calls. */
  content: z.string().default(""),
  /** Set when role === "assistant" and the model invoked tools. */
  tool_calls: z.array(ToolCallSchema).optional(),
  /** Set when role === "tool" — links back to the assistant's tool_call. */
  tool_call_id: z.string().optional(),
  /** OpenAI legacy; used for tool name in role==="tool" responses. */
  name: z.string().optional(),
});
export type Message = z.infer<typeof MessageSchema>;

export const ModelInfoSchema = z.object({
  id: z.string(),
  provider: z.string().optional(),
  /** Whether this model supports OpenAI-style tool/function calling. */
  supports_tool_use: z.boolean().default(true),
  context_window: z.number().int().positive().optional(),
  /** Free-form labels (e.g. "cheap", "vision"). */
  labels: z.array(z.string()).default([]),
});
export type ModelInfo = z.infer<typeof ModelInfoSchema>;

/** Result of one chat completion call. */
export const ChatCompletionSchema = z.object({
  message: MessageSchema,
  finish_reason: z
    .enum(["stop", "length", "tool_calls", "content_filter", "error"])
    .optional(),
  usage: z
    .object({
      prompt_tokens: z.number().int().nonnegative().optional(),
      completion_tokens: z.number().int().nonnegative().optional(),
      total_tokens: z.number().int().nonnegative().optional(),
    })
    .optional(),
});
export type ChatCompletion = z.infer<typeof ChatCompletionSchema>;
