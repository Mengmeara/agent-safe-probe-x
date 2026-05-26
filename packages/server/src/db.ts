import Database from "better-sqlite3";
import {
  type RunConfig,
  type RunMetrics,
  type RunProgress,
  type RunResult,
  type RunStatus,
  type RunSummary,
  type Trace,
} from "@asp-x/shared";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  label TEXT,
  config_json TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at_ms INTEGER NOT NULL,
  ended_at_ms INTEGER,
  error TEXT,
  progress_json TEXT,
  metrics_json TEXT
);

CREATE TABLE IF NOT EXISTS results (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  task TEXT NOT NULL,
  attack_method TEXT NOT NULL,
  attack_variant TEXT,
  attack_target_tool TEXT,
  llm TEXT NOT NULL,
  defense TEXT,
  trace_id TEXT NOT NULL,
  judge_json TEXT NOT NULL,
  error TEXT,
  duration_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE INDEX IF NOT EXISTS results_run_id_idx ON results(run_id);

CREATE TABLE IF NOT EXISTS traces (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  result_id TEXT NOT NULL,
  steps_json TEXT NOT NULL,
  started_at_ms INTEGER NOT NULL,
  ended_at_ms INTEGER,
  FOREIGN KEY (run_id) REFERENCES runs(id),
  FOREIGN KEY (result_id) REFERENCES results(id)
);

CREATE INDEX IF NOT EXISTS traces_run_id_idx ON traces(run_id);
CREATE INDEX IF NOT EXISTS traces_result_id_idx ON traces(result_id);
`;

export class Store {
  readonly db: Database.Database;

  constructor(path: string) {
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.db.exec(SCHEMA);
  }

  close(): void {
    this.db.close();
  }

  insertRun(s: RunSummary): void {
    this.db
      .prepare(
        `INSERT INTO runs (id, label, config_json, status, started_at_ms, ended_at_ms, error, progress_json, metrics_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        s.id,
        s.label ?? null,
        JSON.stringify(s.config),
        s.status,
        s.started_at_ms,
        s.ended_at_ms ?? null,
        s.error ?? null,
        JSON.stringify(s.progress),
        s.metrics ? JSON.stringify(s.metrics) : null,
      );
  }

  updateRunStatus(
    id: string,
    status: RunStatus,
    extras: Partial<{
      ended_at_ms: number;
      error: string;
      metrics: RunMetrics;
    }> = {},
  ): void {
    this.db
      .prepare(
        `UPDATE runs SET status = ?, ended_at_ms = COALESCE(?, ended_at_ms),
         error = COALESCE(?, error), metrics_json = COALESCE(?, metrics_json) WHERE id = ?`,
      )
      .run(
        status,
        extras.ended_at_ms ?? null,
        extras.error ?? null,
        extras.metrics ? JSON.stringify(extras.metrics) : null,
        id,
      );
  }

  updateRunProgress(id: string, progress: RunProgress): void {
    this.db
      .prepare(`UPDATE runs SET progress_json = ? WHERE id = ?`)
      .run(JSON.stringify(progress), id);
  }

  listRuns(): RunSummary[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM runs ORDER BY started_at_ms DESC LIMIT 200`,
      )
      .all() as RunRow[];
    return rows.map(rowToSummary);
  }

  getRun(id: string): RunSummary | undefined {
    const row = this.db
      .prepare(`SELECT * FROM runs WHERE id = ?`)
      .get(id) as RunRow | undefined;
    return row ? rowToSummary(row) : undefined;
  }

  insertResult(r: RunResult): void {
    this.db
      .prepare(
        `INSERT INTO results (id, run_id, agent_id, task, attack_method, attack_variant, attack_target_tool, llm, defense, trace_id, judge_json, error, duration_ms, created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        r.id,
        r.run_id,
        r.agent_id,
        r.task,
        r.attack_method,
        r.attack_variant ?? null,
        r.attack_target_tool,
        r.llm,
        r.defense,
        r.trace_id,
        JSON.stringify(r.judge),
        r.error ?? null,
        r.duration_ms,
        Date.now(),
      );
  }

  listResults(runId: string): RunResult[] {
    const rows = this.db
      .prepare(`SELECT * FROM results WHERE run_id = ? ORDER BY created_at_ms ASC`)
      .all(runId) as ResultRow[];
    return rows.map(rowToResult);
  }

  insertTrace(t: Trace): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO traces (id, run_id, result_id, steps_json, started_at_ms, ended_at_ms)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        t.id,
        t.run_id,
        t.result_id,
        JSON.stringify(t.steps),
        t.started_at_ms,
        t.ended_at_ms ?? null,
      );
  }

  getTrace(id: string): Trace | undefined {
    const row = this.db
      .prepare(`SELECT * FROM traces WHERE id = ?`)
      .get(id) as TraceRow | undefined;
    return row ? rowToTrace(row) : undefined;
  }

  getTraceByResult(resultId: string): Trace | undefined {
    const row = this.db
      .prepare(`SELECT * FROM traces WHERE result_id = ? ORDER BY started_at_ms DESC LIMIT 1`)
      .get(resultId) as TraceRow | undefined;
    return row ? rowToTrace(row) : undefined;
  }
}

interface RunRow {
  id: string;
  label: string | null;
  config_json: string;
  status: string;
  started_at_ms: number;
  ended_at_ms: number | null;
  error: string | null;
  progress_json: string | null;
  metrics_json: string | null;
}

interface ResultRow {
  id: string;
  run_id: string;
  agent_id: string;
  task: string;
  attack_method: string;
  attack_variant: string | null;
  attack_target_tool: string | null;
  llm: string;
  defense: string | null;
  trace_id: string;
  judge_json: string;
  error: string | null;
  duration_ms: number;
  created_at_ms: number;
}

interface TraceRow {
  id: string;
  run_id: string;
  result_id: string;
  steps_json: string;
  started_at_ms: number;
  ended_at_ms: number | null;
}

function rowToSummary(row: RunRow): RunSummary {
  const config = JSON.parse(row.config_json) as RunConfig;
  const progress: RunProgress = row.progress_json
    ? (JSON.parse(row.progress_json) as RunProgress)
    : {
        total: 0,
        done: 0,
        attack_success: 0,
        refused: 0,
        errored: 0,
      };
  const s: RunSummary = {
    id: row.id,
    config,
    status: row.status as RunStatus,
    started_at_ms: row.started_at_ms,
    progress,
  };
  if (row.label) s.label = row.label;
  if (row.ended_at_ms !== null) s.ended_at_ms = row.ended_at_ms;
  if (row.error) s.error = row.error;
  if (row.metrics_json) s.metrics = JSON.parse(row.metrics_json) as RunMetrics;
  return s;
}

function rowToResult(row: ResultRow): RunResult {
  const r: RunResult = {
    id: row.id,
    run_id: row.run_id,
    agent_id: row.agent_id,
    task: row.task,
    attack_method: row.attack_method as RunResult["attack_method"],
    attack_target_tool: row.attack_target_tool,
    llm: row.llm,
    defense: row.defense as RunResult["defense"],
    trace_id: row.trace_id,
    judge: JSON.parse(row.judge_json) as RunResult["judge"],
    duration_ms: row.duration_ms,
  };
  if (row.attack_variant) r.attack_variant = row.attack_variant as RunResult["attack_variant"];
  if (row.error) r.error = row.error;
  return r;
}

function rowToTrace(row: TraceRow): Trace {
  const t: Trace = {
    id: row.id,
    run_id: row.run_id,
    result_id: row.result_id,
    steps: JSON.parse(row.steps_json) as Trace["steps"],
    started_at_ms: row.started_at_ms,
  };
  if (row.ended_at_ms !== null) t.ended_at_ms = row.ended_at_ms;
  return t;
}
