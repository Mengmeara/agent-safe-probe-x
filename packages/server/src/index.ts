export interface StartServerOpts {
  port?: number;
  /** Where to persist the SQLite DB. Defaults to `./data/runs.db`. */
  dbPath?: string;
}

/**
 * Placeholder kept to satisfy the CLI's dynamic import.
 * The full Hono + SQLite + SSE implementation lands in the server task.
 */
export async function startServer(opts: StartServerOpts = {}): Promise<void> {
  throw new Error(
    `startServer not yet implemented (port=${opts.port ?? 4399}, dbPath=${opts.dbPath ?? "default"})`,
  );
}
