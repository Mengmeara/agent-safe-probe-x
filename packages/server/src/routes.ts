import { Hono } from "hono";
import { cors } from "hono/cors";
import { streamSSE } from "hono/streaming";
import {
  AGENT_REGISTRY,
  buildDefaultRegistry,
  readLLMEnv,
} from "@asp-x/core";
import {
  AttackVariantSchema,
  DefenseKindSchema,
  InjectionMethodSchema,
  RunConfigSchema,
  type RunEvent,
} from "@asp-x/shared";
import { RunManager } from "./run_manager.js";

export interface RoutesDeps {
  manager: RunManager;
}

export function buildApp({ manager }: RoutesDeps): Hono {
  const app = new Hono();
  app.use("/api/*", cors());

  app.get("/api/health", (c) =>
    c.json({ ok: true, time: new Date().toISOString() }),
  );

  app.get("/api/agents", (c) => {
    const agents = AGENT_REGISTRY.listAgents().map((a) => ({
      ...a,
      normal_tool_count: AGENT_REGISTRY.getNormalToolsFor(a.id).length,
      attack_tool_count: AGENT_REGISTRY.getAttackToolCandidates(a.id, "all").length,
    }));
    return c.json({ agents });
  });

  app.get("/api/agents/:id/tools", (c) => {
    const id = c.req.param("id");
    const agent = AGENT_REGISTRY.getAgent(id);
    if (!agent) return c.json({ error: "not found" }, 404);
    return c.json({
      normal: AGENT_REGISTRY.getNormalToolsFor(id),
      attack_all: AGENT_REGISTRY.getAttackToolCandidates(id, "all"),
      attack_agg: AGENT_REGISTRY.getAttackToolCandidates(id, "agg"),
      attack_non_agg: AGENT_REGISTRY.getAttackToolCandidates(id, "non-agg"),
    });
  });

  app.get("/api/attacks", (c) =>
    c.json({
      methods: InjectionMethodSchema.options,
      variants: AttackVariantSchema.options,
    }),
  );

  app.get("/api/defenses", (c) =>
    c.json({ defenses: DefenseKindSchema.options }),
  );

  app.get("/api/models", async (c) => {
    try {
      const env = readLLMEnv();
      const registry = buildDefaultRegistry(env);
      const provider = registry.resolve("*");
      const models = await provider.listModels();
      return c.json({ models, default: env.defaultModel });
    } catch (e) {
      return c.json(
        { error: e instanceof Error ? e.message : String(e) },
        500,
      );
    }
  });

  app.post("/api/runs", async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body || typeof body !== "object")
      return c.json({ error: "expected JSON body" }, 400);
    const parsed = RunConfigSchema.safeParse((body as { config?: unknown }).config ?? body);
    if (!parsed.success) {
      return c.json(
        { error: "invalid config", issues: parsed.error.issues },
        400,
      );
    }
    const label = typeof (body as { label?: unknown }).label === "string"
      ? (body as { label: string }).label
      : undefined;
    const summary = manager.startRun(parsed.data, label);
    return c.json({ run: summary }, 201);
  });

  app.get("/api/runs", (c) => {
    return c.json({ runs: manager.store.listRuns() });
  });

  app.get("/api/runs/:id", (c) => {
    const run = manager.store.getRun(c.req.param("id"));
    if (!run) return c.json({ error: "not found" }, 404);
    return c.json({ run });
  });

  app.get("/api/runs/:id/results", (c) => {
    const id = c.req.param("id");
    const run = manager.store.getRun(id);
    if (!run) return c.json({ error: "not found" }, 404);
    return c.json({ results: manager.store.listResults(id) });
  });

  app.get("/api/runs/:id/results/:resultId/trace", (c) => {
    const trace = manager.store.getTraceByResult(c.req.param("resultId"));
    if (!trace) return c.json({ error: "not found" }, 404);
    return c.json({ trace });
  });

  app.get("/api/traces/:id", (c) => {
    const trace = manager.store.getTrace(c.req.param("id"));
    if (!trace) return c.json({ error: "not found" }, 404);
    return c.json({ trace });
  });

  app.delete("/api/runs/:id", (c) => {
    const ok = manager.cancel(c.req.param("id"));
    return c.json({ cancelled: ok });
  });

  // SSE event stream for one run.
  app.get("/sse/runs/:id", (c) => {
    const runId = c.req.param("id");
    const run = manager.store.getRun(runId);
    if (!run) return c.json({ error: "not found" }, 404);

    return streamSSE(c, async (stream) => {
      // Replay current snapshot so a late subscriber gets the latest state.
      await stream.writeSSE({
        event: "run.started",
        data: JSON.stringify({ type: "run.started", run_id: runId, summary: run }),
      });
      for (const r of manager.store.listResults(runId)) {
        await stream.writeSSE({
          event: "result.completed",
          data: JSON.stringify({ type: "result.completed", run_id: runId, result: r }),
        });
      }

      const queue: RunEvent[] = [];
      let resolve: (() => void) | undefined;
      const wait = () => new Promise<void>((r) => (resolve = r));
      const unsubscribe = manager.subscribe(runId, (ev) => {
        queue.push(ev);
        resolve?.();
        resolve = undefined;
      });

      try {
        // Drain the queue, then await new events. Exit when run is terminal.
        // eslint-disable-next-line no-constant-condition
        while (true) {
          while (queue.length > 0) {
            const ev = queue.shift()!;
            await stream.writeSSE({
              event: ev.type,
              data: JSON.stringify(ev),
            });
            if (
              ev.type === "run.completed" ||
              ev.type === "run.failed"
            ) {
              unsubscribe();
              return;
            }
          }
          const current = manager.store.getRun(runId);
          if (current && current.status !== "running") {
            unsubscribe();
            return;
          }
          await Promise.race([
            wait(),
            new Promise<void>((r) => setTimeout(r, 15_000)), // keep-alive
          ]);
          // Heartbeat to keep proxies from closing the connection.
          await stream.writeSSE({ event: "ping", data: "{}" });
        }
      } catch {
        unsubscribe();
      }
    });
  });

  return app;
}
