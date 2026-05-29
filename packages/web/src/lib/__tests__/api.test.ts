import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RunConfig } from "@asp-x/shared";
import { api, subscribeRunEvents } from "../api";

function jsonResponse(body: unknown, init?: { ok?: boolean; status?: number }) {
  return {
    ok: init?.ok ?? true,
    status: init?.status ?? 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as Response;
}

describe("api client", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("listAgents unwraps the agents array", async () => {
    const agents = [{ id: "a", normal_tool_count: 2, attack_tool_count: 1 }];
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ agents }));

    const result = await api.listAgents();

    expect(result).toEqual(agents);
    expect(fetch).toHaveBeenCalledWith("/api/agents", expect.any(Object));
  });

  it("getRun targets the run path and unwraps the run", async () => {
    const run = { id: "run_123" };
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ run }));

    const result = await api.getRun("run_123");

    expect(result).toEqual(run);
    expect(fetch).toHaveBeenCalledWith("/api/runs/run_123", expect.any(Object));
  });

  it("createRun POSTs the config and label as JSON", async () => {
    const run = { id: "run_new" };
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ run }));
    const config = { model: "gpt", agents: [] } as unknown as RunConfig;

    const result = await api.createRun(config, "my-label");

    expect(result).toEqual(run);
    const [path, init] = vi.mocked(fetch).mock.calls[0]!;
    expect(path).toBe("/api/runs");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(init?.body as string)).toEqual({
      config,
      label: "my-label",
    });
    expect((init?.headers as Record<string, string>)["Content-Type"]).toBe(
      "application/json",
    );
  });

  it("cancelRun issues a DELETE", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ cancelled: true }));

    const result = await api.cancelRun("run_123");

    expect(result).toEqual({ cancelled: true });
    const [path, init] = vi.mocked(fetch).mock.calls[0]!;
    expect(path).toBe("/api/runs/run_123");
    expect(init?.method).toBe("DELETE");
  });

  it("throws with status and path on a non-ok response", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ error: "boom" }, { ok: false, status: 500 }),
    );

    await expect(api.health()).rejects.toThrow(/HTTP 500 on \/api\/health/);
  });
});

class MockEventSource {
  static last: MockEventSource | undefined;
  listeners = new Map<string, (event: { data: string }) => void>();
  close = vi.fn();

  constructor(public url: string) {
    MockEventSource.last = this;
  }

  addEventListener(type: string, fn: (event: { data: string }) => void) {
    this.listeners.set(type, fn);
  }

  emit(type: string, data: string) {
    this.listeners.get(type)?.({ data });
  }
}

describe("subscribeRunEvents", () => {
  beforeEach(() => {
    MockEventSource.last = undefined;
    vi.stubGlobal("EventSource", MockEventSource);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("opens the run stream and registers all event types", () => {
    subscribeRunEvents("run_1", () => {});
    const es = MockEventSource.last!;

    expect(es.url).toBe("/sse/runs/run_1");
    expect([...es.listeners.keys()]).toEqual([
      "run.started",
      "run.progress",
      "result.completed",
      "trace.step",
      "run.completed",
      "run.failed",
    ]);
  });

  it("parses event data and forwards it to the callback", () => {
    const onEvent = vi.fn();
    subscribeRunEvents("run_1", onEvent);
    const payload = { type: "run.progress", completed: 1 };

    MockEventSource.last!.emit("run.progress", JSON.stringify(payload));

    expect(onEvent).toHaveBeenCalledWith(payload);
  });

  it("ignores malformed event data without throwing", () => {
    const onEvent = vi.fn();
    subscribeRunEvents("run_1", onEvent);

    expect(() =>
      MockEventSource.last!.emit("run.progress", "not json{"),
    ).not.toThrow();
    expect(onEvent).not.toHaveBeenCalled();
  });

  it("closes the stream on unsubscribe", () => {
    const unsubscribe = subscribeRunEvents("run_1", () => {});
    const es = MockEventSource.last!;

    unsubscribe();

    expect(es.close).toHaveBeenCalledOnce();
  });
});
