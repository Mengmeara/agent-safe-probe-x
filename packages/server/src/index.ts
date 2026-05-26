import { mkdirSync } from "node:fs";
import path from "node:path";
import { serve } from "@hono/node-server";
import { Store } from "./db.js";
import { RunManager } from "./run_manager.js";
import { buildApp } from "./routes.js";
import { mountStatic } from "./static.js";

export interface StartServerOpts {
  port?: number;
  dbPath?: string;
}

/**
 * Boot the HTTP backend. Routes are mounted in this order so that API routes
 * win over the static SPA fallback.
 */
export async function startServer(opts: StartServerOpts = {}): Promise<void> {
  const port = opts.port ?? Number(process.env["ASP_X_SERVER_PORT"] ?? 4399);
  const dbPath = opts.dbPath ?? path.resolve(process.cwd(), "data/runs.db");
  mkdirSync(path.dirname(dbPath), { recursive: true });

  const store = new Store(dbPath);
  const manager = new RunManager(store);
  const app = buildApp({ manager });
  mountStatic(app);

  await new Promise<void>((resolve) => {
    serve(
      {
        fetch: app.fetch,
        port,
      },
      (info) => {
        console.log(
          `ASP-X server listening on http://localhost:${info.port} (db: ${dbPath})`,
        );
        resolve();
      },
    );
  });
}

export { Store } from "./db.js";
export { RunManager } from "./run_manager.js";
export { buildApp } from "./routes.js";
