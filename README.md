# ASP-X — Agent Safe Probe

A TypeScript rewrite of [ASB — Agent Security Bench (ICLR 2025)](https://github.com/agiresearch/ASB), packaged as a developer tool: one-command install, web UI for configuration, real-time progress, and an **interactive trajectory visualization** that replaces ASB's CSV-and-stare workflow.

The benchmark evaluates how often LLM-based agents get fooled into invoking dangerous tools when their inputs are poisoned with prompt-injection attacks.

![Runs list](docs/screenshots/runs-list.png)

## Why this exists

ASB's Python implementation is research code: conda environment, heavy ML dependencies, `nohup` background processes, CSVs in `logs/`. It does the job for paper authors but is painful for anyone who wants to actually use it on their own model or defense.

ASP-X preserves ASB's evaluation semantics exactly (same four attack families, same agents, same metric definitions) and changes everything around them.

| | Original ASB | ASP-X |
|---|---|---|
| Language | Python | TypeScript |
| Install | conda + pip + torch | `pnpm install` |
| Configure | hand-edit yaml | web form **or** yaml |
| Add a new model | write a Python class | fill a form |
| Watch progress | tail logs, grep | live UI + SSE stream |
| See results | parse CSV | interactive trace timeline |
| Eval semantics | — | **preserved** |

## What's in the box

- **Four attack families** ported byte-for-byte from ASB:
  - **DPI** — Direct Prompt Injection (poison the user task)
  - **OPI** — Observation Prompt Injection (poison a tool result)
  - **Memory Poisoning** — poison the agent's retrieved memory context
  - **PoT Backdoor** — trigger-activated injection in the system prompt
- **Five attack variants**: `naive`, `fake_completion`, `escape_characters`, `context_ignoring`, `combined_attack`
- **Seven defense methods**: delimiters, instructional prevention, observation sandwich, paraphrase, dynamic rewriting, PoT shuffling
- **10 built-in industry agents** (financial, legal, medical, academic, sysadmin, ecommerce, education, autonomous driving, aerospace, psychological counseling) with their original tasks and tools
- **400 attack lures** (200 aggressive + 200 non-aggressive) attached to the right agents
- **Three judges**: attack success rate (ASR), refusal rate (RR), original task success (PNA)
- **OpenAI-compatible LLM provider** that works with OpenAI, ollama, Together, Groq, vLLM, and any gateway speaking the same protocol

## Quick start

```bash
git clone <repo> asp-x && cd asp-x
pnpm install
pnpm -r --filter "./packages/*" build

cp .env.example .env
# edit .env: set ASP_X_LLM_BASE_URL and ASP_X_LLM_API_KEY for any
# OpenAI-compatible endpoint (OpenAI, ollama, moyunsec, etc.)

# CLI
node packages/cli/dist/index.js list-models
node packages/cli/dist/index.js run --config configs/smoke.yml --verbose

# Web UI
node packages/cli/dist/index.js serve
# open http://localhost:4399
```

## Screenshots

### Configure a run

![New run form](docs/screenshots/new-run.png)

### Watch it execute

![Run detail with metrics](docs/screenshots/run-detail.png)

### Inspect any trajectory

The centerpiece: every step the agent took — system prompt, the (possibly poisoned) user task, every tool call, every observation, the final answer — laid out as a timeline. Injected steps are flagged in red, attack-tool invocations have an "ATTACK HIT" badge, and any step can be expanded inline.

![Trace timeline](docs/screenshots/trace-view.png)

## Layout

```
packages/
  shared/      Zod-defined types shared front/back
  core/        ReAct loop, attacks, defenses, judges, agent registry
  server/      Hono HTTP API + SSE + SQLite persistence
  cli/         npx entry: run, serve, list-models, list-agents, list-attacks
  web/         React + Tailwind frontend
configs/       Sample ASB-style yaml configs (DPI, OPI, clean, smoke)
scripts/       One-off porting scripts
docs/          Screenshots and notes
```

## Configuration

Both CLI and web UI consume the same `RunConfig` schema. ASB-style yaml works as-is:

```yaml
injection_method: direct_prompt_injection
attack_tool: agg
attack_types:
  - naive
  - combined_attack
llms:
  - qwen-flash
agents:
  - financial_analyst_agent
task_num: 1
max_steps: 8
defense_type: delimiters_defense   # optional
triggers:                          # only for pot_backdoor
  - strawberry
```

Run with `node packages/cli/dist/index.js run --config configs/dpi.yml`.

## Architecture

The framework treats itself as the **environment** the agent lives in.
Four channels into that environment can be hooked:

```
        ┌─────────────────────────┐
        │      User's agent       │
        │ (LLM + tool runtime)    │
        └────────┬─────┬──────────┘
                 │     │
   system_prompt │     │ observation     ← OPI hook lives here
    user_task    │     │                 ← DPI hook lives here
   memory_lookup │     │                 ← Memory poisoning lives here
                 ↓     ↑
        ┌─────────────────────────┐
        │   ASP-X runner (env)    │
        │  attack + defense hooks │
        └─────────────────────────┘
```

`packages/core/src/runner/runner.ts` implements the ReAct loop and exposes
`AttackHook` / `DefenseHook` interfaces over each channel. The orchestrator
walks the `{agent × task × variant × tool × llm × defense}` matrix and produces
a `RunResult` per cell.

## Testing

```bash
pnpm -r --filter "./packages/*" test
```

93 unit + integration tests at the time of the initial rewrite (shared schemas,
LLM provider, ReAct loop, attack hooks, defense wrappers, ASB-data registry,
judges, orchestrator, config loader, HTTP routes).

End-to-end verification with a real model is done via:

```bash
node packages/cli/dist/index.js serve &
curl -X POST http://localhost:4399/api/runs \
  -H 'Content-Type: application/json' \
  -d @configs/smoke.yml.json
```

## What's deliberately not here

- **Bring-your-own-agent**: would require defining an external agent
  integration protocol; the integration cost is real, not the kind of
  free-lunch headline this kind of rewrite usually promises.
- **MCP server wrapper**: not yet — easy add once the agent-integration
  story is settled.
- **New attacks/defenses beyond ASB's**: research work, out of scope for
  this rewrite.
- **Distributed scheduling**: not needed; single-machine LLM-bound workload.

## License

MIT. See [LICENSE](LICENSE).

## Citation

If you use ASP-X for research, please cite the original ASB paper which
defined the benchmark this implementation evaluates:

```bibtex
@inproceedings{zhang2025agent,
  title={Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents},
  author={Hanrong Zhang and Jingyuan Huang and Kai Mei and Yifei Yao and Zhenting Wang and Chenlu Zhan and Hongwei Wang and Yongfeng Zhang},
  booktitle={The Thirteenth International Conference on Learning Representations},
  year={2025}
}
```
