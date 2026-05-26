import { z } from "zod";
import { RunSummarySchema, RunResultSchema, RunProgressSchema, RunMetricsSchema } from "./run.js";
import { TraceStepSchema } from "./trace.js";

/**
 * Event payloads streamed from the server to a frontend client subscribed
 * to a run via SSE. Discriminated by `type`.
 */
export const RunEventSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("run.started"),
    run_id: z.string(),
    summary: RunSummarySchema,
  }),
  z.object({
    type: z.literal("run.progress"),
    run_id: z.string(),
    progress: RunProgressSchema,
  }),
  z.object({
    type: z.literal("result.completed"),
    run_id: z.string(),
    result: RunResultSchema,
  }),
  z.object({
    type: z.literal("trace.step"),
    run_id: z.string(),
    result_id: z.string(),
    trace_id: z.string(),
    step: TraceStepSchema,
  }),
  z.object({
    type: z.literal("run.completed"),
    run_id: z.string(),
    summary: RunSummarySchema,
    metrics: RunMetricsSchema,
  }),
  z.object({
    type: z.literal("run.failed"),
    run_id: z.string(),
    error: z.string(),
  }),
]);
export type RunEvent = z.infer<typeof RunEventSchema>;
