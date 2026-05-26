import type {
  AgentDef,
  RunConfig,
  RunEvent,
  RunResult,
  RunSummary,
  Trace,
} from "@asp-x/shared";

const API_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "";

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    let detail = "";
    try {
      detail = await res.text();
    } catch {
      // ignore
    }
    throw new Error(`HTTP ${res.status} on ${path}: ${detail.slice(0, 200)}`);
  }
  return (await res.json()) as T;
}

export interface AgentEntry extends AgentDef {
  normal_tool_count: number;
  attack_tool_count: number;
}

export const api = {
  async health(): Promise<{ ok: boolean }> {
    return fetchJson("/api/health");
  },

  async listAgents(): Promise<AgentEntry[]> {
    const { agents } = await fetchJson<{ agents: AgentEntry[] }>("/api/agents");
    return agents;
  },

  async listAttacks(): Promise<{ methods: string[]; variants: string[] }> {
    return fetchJson("/api/attacks");
  },

  async listDefenses(): Promise<{ defenses: string[] }> {
    return fetchJson("/api/defenses");
  },

  async listModels(): Promise<{ models: { id: string }[]; default: string }> {
    return fetchJson("/api/models");
  },

  async listRuns(): Promise<RunSummary[]> {
    const { runs } = await fetchJson<{ runs: RunSummary[] }>("/api/runs");
    return runs;
  },

  async getRun(id: string): Promise<RunSummary> {
    const { run } = await fetchJson<{ run: RunSummary }>(`/api/runs/${id}`);
    return run;
  },

  async listResults(runId: string): Promise<RunResult[]> {
    const { results } = await fetchJson<{ results: RunResult[] }>(
      `/api/runs/${runId}/results`,
    );
    return results;
  },

  async getTrace(runId: string, resultId: string): Promise<Trace> {
    const { trace } = await fetchJson<{ trace: Trace }>(
      `/api/runs/${runId}/results/${resultId}/trace`,
    );
    return trace;
  },

  async createRun(config: RunConfig, label?: string): Promise<RunSummary> {
    const { run } = await fetchJson<{ run: RunSummary }>("/api/runs", {
      method: "POST",
      body: JSON.stringify({ config, label }),
    });
    return run;
  },

  async cancelRun(id: string): Promise<{ cancelled: boolean }> {
    return fetchJson(`/api/runs/${id}`, { method: "DELETE" });
  },
};

/**
 * Subscribe to a run's event stream. Calls `onEvent` for each parsed RunEvent.
 * Returns an unsubscribe function that closes the EventSource.
 */
export function subscribeRunEvents(
  runId: string,
  onEvent: (ev: RunEvent) => void,
): () => void {
  const es = new EventSource(`${API_BASE}/sse/runs/${runId}`);

  const handle = (event: MessageEvent) => {
    try {
      const parsed = JSON.parse(event.data) as RunEvent;
      onEvent(parsed);
    } catch {
      // Ignore malformed event data.
    }
  };

  for (const type of [
    "run.started",
    "run.progress",
    "result.completed",
    "trace.step",
    "run.completed",
    "run.failed",
  ] as const) {
    es.addEventListener(type, handle as EventListener);
  }
  return () => es.close();
}
