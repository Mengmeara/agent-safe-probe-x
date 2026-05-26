import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api.js";

/**
 * Placeholder for the result/trace detail view. The interactive trace
 * timeline lands as the next commit's centerpiece.
 */
export function ResultPage() {
  const { id = "", resultId = "" } = useParams<{ id: string; resultId: string }>();
  const traceQ = useQuery({
    queryKey: ["trace", id, resultId],
    queryFn: () => api.getTrace(id, resultId),
  });

  return (
    <div className="max-w-6xl mx-auto px-6 py-8 space-y-4">
      <Link to={`/runs/${id}`} className="text-sm text-ink-500 hover:text-ink-700">
        ← back to run
      </Link>
      <h1 className="text-xl font-semibold">Trace · {resultId.slice(0, 12)}</h1>
      {traceQ.isLoading && <div className="text-ink-500">Loading trace…</div>}
      {traceQ.error && (
        <div className="text-accent-attack">
          Failed to load: {(traceQ.error as Error).message}
        </div>
      )}
      {traceQ.data && (
        <pre className="border border-bg-600 rounded-lg bg-bg-800 p-4 text-xs overflow-auto max-h-[60vh]">
          {JSON.stringify(traceQ.data, null, 2)}
        </pre>
      )}
    </div>
  );
}
