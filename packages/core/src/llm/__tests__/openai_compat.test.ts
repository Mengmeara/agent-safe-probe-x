import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OpenAICompatProvider } from "../openai_compat.js";

const ORIGINAL_FETCH = globalThis.fetch;

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });
}

describe("OpenAICompatProvider", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    // @ts-expect-error global mock
    globalThis.fetch = fetchMock;
  });

  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
  });

  it("posts to /chat/completions with bearer token and parses response", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        choices: [
          {
            message: { role: "assistant", content: "hi there" },
            finish_reason: "stop",
          },
        ],
        usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
      }),
    );

    const p = new OpenAICompatProvider({
      baseUrl: "https://api.example.com/v1",
      apiKey: "sk-test",
    });
    const out = await p.chat({
      model: "qwen-flash",
      messages: [{ role: "user", content: "say hi" }],
    });
    expect(out.message.content).toBe("hi there");
    expect(out.usage?.total_tokens).toBe(5);

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("https://api.example.com/v1/chat/completions");
    expect((init as RequestInit).method).toBe("POST");
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer sk-test");
  });

  it("parses tool_calls and decodes JSON-stringified arguments", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        choices: [
          {
            message: {
              role: "assistant",
              content: null,
              tool_calls: [
                {
                  id: "call_1",
                  type: "function",
                  function: {
                    name: "search_web",
                    arguments: '{"q":"hello world"}',
                  },
                },
              ],
            },
            finish_reason: "tool_calls",
          },
        ],
      }),
    );

    const p = new OpenAICompatProvider({
      baseUrl: "https://api.example.com/v1",
      apiKey: "k",
    });
    const out = await p.chat({
      model: "qwen-flash",
      messages: [{ role: "user", content: "?" }],
      tools: [
        {
          type: "function",
          function: { name: "search_web", description: "", parameters: {} },
        },
      ],
    });
    expect(out.message.tool_calls?.[0]?.name).toBe("search_web");
    expect(out.message.tool_calls?.[0]?.arguments).toEqual({ q: "hello world" });
  });

  it("serializes assistant tool_calls correctly on outbound requests", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        choices: [{ message: { role: "assistant", content: "ok" } }],
      }),
    );
    const p = new OpenAICompatProvider({ baseUrl: "https://x/v1", apiKey: "k" });
    await p.chat({
      model: "m",
      messages: [
        { role: "system", content: "sys" },
        { role: "user", content: "do x" },
        {
          role: "assistant",
          content: "",
          tool_calls: [
            { id: "c1", name: "f", arguments: { a: 1 } },
          ],
        },
        { role: "tool", content: "result", tool_call_id: "c1", name: "f" },
      ],
    });
    const body = JSON.parse((fetchMock.mock.calls[0]![1] as RequestInit).body as string);
    expect(body.messages[2].tool_calls[0].function.arguments).toBe('{"a":1}');
    expect(body.messages[2].content).toBeNull();
    expect(body.messages[3].tool_call_id).toBe("c1");
  });

  it("retries on 429 and eventually succeeds", async () => {
    fetchMock
      .mockResolvedValueOnce(new Response("rate limit", { status: 429 }))
      .mockResolvedValueOnce(
        jsonResponse({ choices: [{ message: { role: "assistant", content: "ok" } }] }),
      );
    const p = new OpenAICompatProvider({
      baseUrl: "https://x/v1",
      apiKey: "k",
    });
    const out = await p.chat({
      model: "m",
      messages: [{ role: "user", content: "?" }],
      retries: 2,
    });
    expect(out.message.content).toBe("ok");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("lists models", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        data: [
          { id: "qwen-flash", owned_by: "custom" },
          { id: "gpt-5", owned_by: "openai" },
          { object: "garbage" }, // ignored
        ],
      }),
    );
    const p = new OpenAICompatProvider({ baseUrl: "https://x/v1", apiKey: "k" });
    const models = await p.listModels();
    expect(models).toHaveLength(2);
    expect(models[0]?.id).toBe("qwen-flash");
    expect(models[0]?.provider).toBe("custom");
  });
});
