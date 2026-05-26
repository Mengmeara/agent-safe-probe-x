import {
  type RunConfig,
  type RunEvent,
  type RunProgress,
  type RunSummary,
  type Trace,
  newId,
} from "@asp-x/shared";
import {
  buildDefaultRegistry,
  computeMetrics,
  estimateTotalUnits,
  readLLMEnv,
  runOrchestrator,
} from "@asp-x/core";
import { Store } from "./db.js";

type Listener = (ev: RunEvent) => void;

/**
 * Owns active and historical runs. Persists to SQLite, broadcasts SSE events,
 * and lets us cancel a running benchmark via its AbortController.
 */
export class RunManager {
  private readonly listeners = new Map<string, Set<Listener>>();
  private readonly controllers = new Map<string, AbortController>();
  /** Buffer of trace steps captured during a run, keyed by result_id. */
  private readonly traceBuffers = new Map<string, Trace>();

  constructor(public readonly store: Store) {}

  subscribe(runId: string, fn: Listener): () => void {
    let set = this.listeners.get(runId);
    if (!set) {
      set = new Set();
      this.listeners.set(runId, set);
    }
    set.add(fn);
    return () => {
      set!.delete(fn);
      if (set!.size === 0) this.listeners.delete(runId);
    };
  }

  private emit(runId: string, ev: RunEvent): void {
    const set = this.listeners.get(runId);
    if (!set) return;
    for (const fn of set) {
      try {
        fn(ev);
      } catch {
        /* drop listener errors */
      }
    }
  }

  cancel(runId: string): boolean {
    const ctl = this.controllers.get(runId);
    if (!ctl) return false;
    ctl.abort();
    return true;
  }

  /**
   * Start a new run in the background. Returns immediately with the new
   * RunSummary so the caller can hand back a run_id to the client.
   */
  startRun(config: RunConfig, label?: string): RunSummary {
    const runId = newId("run");
    const total = estimateTotalUnits(config);
    const progress: RunProgress = {
      total,
      done: 0,
      attack_success: 0,
      refused: 0,
      errored: 0,
    };
    const summary: RunSummary = {
      id: runId,
      config,
      status: "running",
      started_at_ms: Date.now(),
      progress,
    };
    if (label) summary.label = label;
    this.store.insertRun(summary);

    const ac = new AbortController();
    this.controllers.set(runId, ac);

    // Fire-and-forget; errors are caught and emitted as run.failed.
    void this.executeRun(runId, summary, ac.signal);
    return summary;
  }

  private async executeRun(
    runId: string,
    summary: RunSummary,
    signal: AbortSignal,
  ): Promise<void> {
    this.emit(runId, { type: "run.started", run_id: runId, summary });
    try {
      const env = readLLMEnv();
      const registry = buildDefaultRegistry(env);
      const provider = registry.resolve(summary.config.llms[0]!);
      const judgeProvider = provider;
      const judgeModel =
        summary.config.judge_model ?? env.judgeModel ?? summary.config.llms[0]!;

      const progress: RunProgress = { ...summary.progress };

      const out = await runOrchestrator({
        config: summary.config,
        provider,
        judgeProvider,
        judgeModel,
        runId,
        abortSignal: signal,
        onTraceStep: (resultId, _traceIdUnused, step) => {
          // Buffer steps so we can persist the full trace once the result lands.
          let buf = this.traceBuffers.get(resultId);
          if (!buf) {
            buf = {
              id: "", // filled when result.completed
              run_id: runId,
              result_id: resultId,
              steps: [],
              started_at_ms: Date.now(),
            };
            this.traceBuffers.set(resultId, buf);
          }
          buf.steps.push(step);
          this.emit(runId, {
            type: "trace.step",
            run_id: runId,
            result_id: resultId,
            trace_id: buf.id,
            step,
          });
        },
        onResult: (r) => {
          // Insert the result first, then the trace — the trace row has
          // an FK to results.id, so the order matters.
          this.store.insertResult(r);
          const buf = this.traceBuffers.get(r.id);
          if (buf) {
            buf.id = r.trace_id;
            buf.ended_at_ms = Date.now();
            this.store.insertTrace(buf);
            this.traceBuffers.delete(r.id);
          }
          progress.done += 1;
          if (r.judge.attack_success) progress.attack_success += 1;
          if (r.judge.refused) progress.refused += 1;
          if (r.error) progress.errored += 1;
          this.store.updateRunProgress(runId, progress);
          this.emit(runId, {
            type: "result.completed",
            run_id: runId,
            result: r,
          });
          this.emit(runId, {
            type: "run.progress",
            run_id: runId,
            progress: { ...progress },
          });
        },
      });

      const metrics = computeMetrics(out.results);
      const finalStatus = signal.aborted ? "cancelled" : "completed";
      this.store.updateRunStatus(runId, finalStatus, {
        ended_at_ms: Date.now(),
        metrics,
      });
      const final = this.store.getRun(runId)!;
      this.emit(runId, {
        type: "run.completed",
        run_id: runId,
        summary: final,
        metrics,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.store.updateRunStatus(runId, "failed", {
        ended_at_ms: Date.now(),
        error: msg,
      });
      this.emit(runId, { type: "run.failed", run_id: runId, error: msg });
    } finally {
      this.controllers.delete(runId);
    }
  }
}
