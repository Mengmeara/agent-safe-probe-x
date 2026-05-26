import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Store } from "../db.js";
import { RunManager } from "../run_manager.js";
import { buildApp } from "../routes.js";

let store: Store;
let manager: RunManager;
let app: ReturnType<typeof buildApp>;

beforeEach(() => {
  const dir = mkdtempSync(path.join(tmpdir(), "aspx-routes-"));
  store = new Store(path.join(dir, "runs.db"));
  manager = new RunManager(store);
  app = buildApp({ manager });
});

afterEach(() => {
  store.close();
});

async function fetchApp(path: string, init?: RequestInit): Promise<Response> {
  return app.fetch(new Request(`http://test${path}`, init));
}

describe("HTTP routes", () => {
  it("GET /api/health returns ok", async () => {
    const res = await fetchApp("/api/health");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  it("GET /api/agents lists the 10 built-in agents with counts", async () => {
    const res = await fetchApp("/api/agents");
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      agents: Array<{ id: string; normal_tool_count: number }>;
    };
    expect(body.agents).toHaveLength(10);
    expect(body.agents[0]?.normal_tool_count).toBeGreaterThan(0);
  });

  it("GET /api/agents/:id/tools returns tool partition for agent", async () => {
    const res = await fetchApp("/api/agents/financial_analyst_agent/tools");
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      normal: unknown[];
      attack_all: unknown[];
      attack_agg: unknown[];
      attack_non_agg: unknown[];
    };
    expect(body.normal.length).toBeGreaterThan(0);
    expect(body.attack_all.length).toBe(40);
    expect(body.attack_agg.length).toBe(20);
    expect(body.attack_non_agg.length).toBe(20);
  });

  it("GET /api/attacks lists methods and variants", async () => {
    const res = await fetchApp("/api/attacks");
    const body = (await res.json()) as { methods: string[]; variants: string[] };
    expect(body.methods).toContain("direct_prompt_injection");
    expect(body.variants).toContain("naive");
  });

  it("GET /api/defenses lists supported defenses", async () => {
    const res = await fetchApp("/api/defenses");
    const body = (await res.json()) as { defenses: string[] };
    expect(body.defenses).toContain("delimiters_defense");
  });

  it("POST /api/runs with invalid config returns 400", async () => {
    const res = await fetchApp("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ config: { llms: [] } }),
    });
    expect(res.status).toBe(400);
  });

  it("GET /api/runs returns empty list initially", async () => {
    const res = await fetchApp("/api/runs");
    const body = (await res.json()) as { runs: unknown[] };
    expect(body.runs).toHaveLength(0);
  });

  it("GET /api/runs/:id returns 404 for missing id", async () => {
    const res = await fetchApp("/api/runs/nonexistent");
    expect(res.status).toBe(404);
  });
});
