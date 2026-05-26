import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Hono } from "hono";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".ico": "image/x-icon",
  ".map": "application/json",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

/**
 * Locate the built frontend's dist directory. Walks up from the server's
 * own dist/ in case it's installed via npm.
 */
function findWebDist(): string | null {
  const candidates = [
    path.resolve(__dirname, "../../web/dist"),
    path.resolve(__dirname, "../../../web/dist"),
    path.resolve(process.cwd(), "packages/web/dist"),
    path.resolve(process.cwd(), "node_modules/@asp-x/web/dist"),
  ];
  for (const c of candidates) {
    if (existsSync(path.join(c, "index.html"))) return c;
  }
  return null;
}

export function mountStatic(app: Hono): void {
  const dist = findWebDist();
  if (!dist) {
    app.get("/", (c) =>
      c.text(
        "Backend up — but no built frontend found. Run `pnpm --filter @asp-x/web build` first.",
      ),
    );
    return;
  }

  app.get("*", (c) => {
    const url = new URL(c.req.url);
    // Don't intercept API/SSE — they have their own handlers higher up.
    if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/sse/")) {
      return c.notFound();
    }

    let relPath = decodeURIComponent(url.pathname);
    if (relPath.endsWith("/")) relPath += "index.html";
    const filePath = path.join(dist, relPath);
    // Prevent directory traversal.
    if (!filePath.startsWith(dist)) return c.notFound();

    if (existsSync(filePath) && statSync(filePath).isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      const ct = MIME[ext] ?? "application/octet-stream";
      const data = readFileSync(filePath);
      return c.body(new Uint8Array(data), 200, { "Content-Type": ct });
    }

    // SPA fallback: serve index.html for any unknown route.
    const indexPath = path.join(dist, "index.html");
    if (existsSync(indexPath)) {
      const html = readFileSync(indexPath, "utf8");
      return c.html(html);
    }
    return c.notFound();
  });
}
