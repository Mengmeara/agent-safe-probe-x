# ASP-X architecture

## Mental model: framework = environment

The original ASB Python codebase IS the agent — the ReAct loop, the message
list, the tool dispatch all live inside the `ReactAgentAttack` class. That's
fine for batch experiments but makes "test someone else's agent" structurally
impossible.

ASP-X inverts that. The framework is the **environment** the agent operates
in, and the agent's information inputs travel through four channels the
environment owns:

| Channel | Attack that targets it | Defense knob |
|---|---|---|
| System prompt | PoT Backdoor (`onSystemPrompt`) | wrapSystemPrompt |
| User task | DPI (`onUserTask`) | wrapUserTask |
| Memory retrieval | Memory Poisoning (`onMemoryEntries`) | — |
| Tool observation | OPI (`onObservation`) | wrapObservation / filterObservation |

For the bundled 10 ASB agents, the framework still drives the ReAct loop
itself (single-process, in-memory). The hook architecture is what makes a
future BYOA (bring-your-own-agent) variant cleanly possible.

## Package map

```
shared/    ── zod schemas + TS types for everything that crosses a boundary
              (Message, Trace, AttackPayload, RunConfig, RunResult, RunEvent…)

core/      ── pure-logic engine
  llm/         OpenAI-compatible HTTP client + provider registry
  runner/      ReAct loop + tool runtime + matrix orchestrator
  attacks/     DPI/OPI/Memory/PoT hook factories + compose helper
  defenses/    Delimiters, Sandwich, Instructional, Paraphrase,
               Dynamic Rewriting, PoT Shuffling wrapper factories
  judges/      ASR (tool-call scan), RR (heuristic + LLM judge), PNA
  data/        Ported ASB agents (10) and tools (20 normal + 400 attack)

server/    ── HTTP backend (Hono)
  db.ts        better-sqlite3 schema + queries
  run_manager  background execution + SSE pub/sub
  routes       REST API (/api/...) + SSE (/sse/runs/:id)
  static       SPA fallback serving packages/web/dist

cli/       ── npx entrypoint (commander)
  commands/run.ts      execute a config end-to-end, write logs/<run>/results.json
  commands/list.ts     list-models, list-agents, list-attacks, list-defenses
  index.ts             also: serve (lazy-imports server)

web/       ── Vite + React + Tailwind UI
  pages/RunsPage           dashboard, polled list of runs
  pages/NewRunPage         schema-driven config form
  pages/RunDetailPage      live progress + result table + SSE event tail
  pages/ResultPage         single result + TraceTimeline
  components/TraceTimeline interactive step-by-step view (the centerpiece)
```

## Data flow for one run

1. User POSTs config → `POST /api/runs`
2. `RunManager.startRun` allocates run_id, persists row, returns 201
3. In background: `runOrchestrator` walks the config matrix
4. For each (agent, task, attack_variant, attack_tool, llm, defense):
   - Build `AttackHook` from `attacks/`
   - Build `DefenseHook` from `defenses/`
   - Compose toolset (normal + chosen attack lure)
   - `runAgent` runs the ReAct loop with both hooks wired in
   - `judgeAll` runs ASR + RR + PNA judges
5. Each step is streamed to subscribed SSE clients via `RunEvent`
6. Result is persisted to `results` table, trace to `traces` table
7. On run completion: `RunSummary` updated with final `RunMetrics`
8. Frontend's TanStack Query refetches and the UI converges

## Why these choices

- **TypeScript everywhere**: cross-platform install, single language across
  full stack, ergonomic type sharing via `@asp-x/shared`.
- **Hono**: small, modern HTTP server with first-class SSE primitive.
- **better-sqlite3**: synchronous API simplifies the persistence layer for
  what is single-process workload, and zero ops.
- **Vite + React + Tailwind**: standard stack; no design system framework
  means the UI is custom (matches the tailored visual style).
- **TanStack Query**: lets the UI auto-refetch while a run is in flight
  without bespoke websocket state machines.

## Compatibility with ASB yaml

`RunConfigSchema` in `shared/` accepts ASB's original field names verbatim
(`injection_method`, `attack_tool`, `attack_types`, `llms`, `defense_type`,
`task_num`, `triggers`, etc.). The CLI's `loadRunConfig` reads `.yml` or
`.json` and applies the schema.

The semantic translations from ASB are intentionally small:
- Attack templates: strings copied byte-for-byte from ASB's `react_agent_attack.py`
- ASR detection: ASB scans for a goal string in messages; we record
  `was_attack_tool` on each observation step (functionally equivalent,
  more explicit)
- Refusal detection: identical compliance-judge prompt as ASB
- Original task success: identical "every normal tool's expected_achievement
  must appear in the trace" semantics
