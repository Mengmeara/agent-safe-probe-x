<div align="center">

# ASP-X &nbsp;·&nbsp; Agent Safe Probe

**A TypeScript rewrite of [ASB — Agent Security Bench (ICLR 2025)](https://github.com/agiresearch/ASB), reborn as a developer tool.**

One-command install · web UI for configuration · real-time progress · an **interactive trajectory visualization** that retires ASB's CSV-and-stare workflow.

[![license](https://img.shields.io/badge/license-MIT-34d399)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-60a5fa)](https://www.typescriptlang.org/)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-60a5fa)](https://nodejs.org/)
[![tests](https://img.shields.io/badge/tests-93%20passing-34d399)](#testing)
[![based on ASB](https://img.shields.io/badge/benchmark-ASB%20ICLR%202025-a78bfa)](https://github.com/agiresearch/ASB)

</div>

The benchmark measures how often LLM-based agents get fooled into invoking dangerous tools when their inputs are poisoned with prompt-injection attacks. ASP-X preserves ASB's evaluation semantics **exactly** — same four attack families, same agents, same metric definitions — and rebuilds everything around them.

![ASP-X architecture](docs/screenshots/architecture.png)

---

## Why this exists

ASB's Python implementation is research code: a conda environment, heavy ML dependencies, `nohup` background processes, CSVs dumped into `logs/`. It does the job for paper authors but is painful for anyone who wants to run it on their *own* model or defense.

| | Original ASB | ASP-X |
|---|---|---|
| Language | Python | TypeScript |
| Install | conda + pip + torch (**7.4 GB**) | `pnpm install` (**137 MB**, zero ML deps) |
| Configure | hand-edit YAML | web form **or** YAML |
| Add a new model | write a Python class | fill a form |
| Watch progress | `tail` logs, `grep` | live UI + SSE stream |
| See results | parse CSV | **interactive trace timeline** |
| Eval semantics | — | **preserved byte-for-byte** |

---

## What's in the box

- **Four attack families**, ported byte-for-byte from ASB:
  | | channel poisoned |
  |---|---|
  | **DPI** — Direct Prompt Injection | the user task |
  | **OPI** — Observation Prompt Injection | a tool result |
  | **Memory Poisoning** | the agent's retrieved memory |
  | **PoT Backdoor** | trigger-activated, in the system prompt |
- **Five attack variants** — `naive`, `fake_completion`, `escape_characters`, `context_ignoring`, `combined_attack`
- **Seven defenses** — delimiters, instructional prevention, observation sandwich, paraphrase, dynamic rewriting, PoT shuffling
- **10 built-in industry agents** (financial, legal, medical, academic, sysadmin, ecommerce, education, autonomous-driving, aerospace, psychological-counseling) with their original tasks and tools
- **400 attack lures** (200 aggressive + 200 non-aggressive) attached to the right agents
- **Three judges** — attack success rate (ASR), refusal rate (RR), original-task success (PNA)
- **OpenAI-compatible provider** — works with OpenAI, ollama, Together, Groq, vLLM, and any gateway speaking the same protocol

---

## Quick start

```bash
git clone <repo> asp-x && cd asp-x
pnpm install
pnpm -r --filter "./packages/*" build

cp .env.example .env
# edit .env: set ASP_X_LLM_BASE_URL and ASP_X_LLM_API_KEY for any
# OpenAI-compatible endpoint (OpenAI, ollama, vLLM, a gateway, …)
```

```bash
# ── CLI ──────────────────────────────────────────────
node packages/cli/dist/index.js list-models        # list available models
node packages/cli/dist/index.js list-agents         # list the 10 built-in agents
node packages/cli/dist/index.js run --config configs/smoke.yml --verbose

# ── Web UI ───────────────────────────────────────────
node packages/cli/dist/index.js serve               # → http://localhost:4399
```

---

## Screenshots

#### Configure a run
Pick injection method, variants, defense, model, agents and task count — no code.

![New run form](docs/screenshots/new-run.png)

#### Watch it execute
Live ASR / RR / PNA metric cards stream in over SSE as each matrix cell finishes.

![Run detail with metrics](docs/screenshots/run-detail.png)

#### Inspect any trajectory — *the centerpiece*
Every step the agent took — system prompt, the (possibly poisoned) user task, every tool call, every observation, the final answer — laid out as a timeline. Injected steps are flagged red, attack-tool invocations get an **ATTACK HIT** badge, and any step expands inline.

![Trace timeline](docs/screenshots/trace-view.png)

---

## Architecture

ASP-X treats itself as the **environment** the agent lives in. The ReAct loop exposes four channels, and an `AttackHook` / `DefenseHook` pair can be installed on each:

| channel | attack that poisons it |
|---|---|
| `system_prompt` | PoT Backdoor |
| `user_task` | DPI |
| `memory_lookup` | Memory Poisoning |
| `observation` | OPI |

`packages/core/src/runner/runner.ts` implements the loop; the orchestrator walks the `{agent × task × variant × tool × llm × defense}` matrix and emits one `RunResult` per cell. See the diagram above.

```
packages/
  shared/    Zod-defined types shared front ⇄ back
  core/      ReAct loop · attacks · defenses · judges · agent registry · orchestrator
  server/    Hono HTTP API + SSE + SQLite persistence
  cli/       entry point: run · serve · list-models · list-agents · list-attacks
  web/        React + Tailwind frontend (interactive trace timeline)
configs/      Sample ASB-style YAML configs (DPI, OPI, clean, smoke)
scripts/      One-off ASB-data porting scripts
docs/         Screenshots and notes
```

---

## Configuration

CLI and web UI consume the same `RunConfig` schema. ASB-style YAML works as-is:

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

```bash
node packages/cli/dist/index.js run --config configs/dpi.yml
```

---

## Testing

```bash
pnpm -r --filter "./packages/*" test
```

**93 unit + integration tests** across 10 files / 25 suites — shared schemas, LLM provider, ReAct loop, attack hooks, defense wrappers, ASB-data registry, the three judges, orchestrator, config loader, and HTTP routes. Every tool runs in a **simulated** runtime (`runner/tool_runtime.ts`): no real side effects, no outbound connections. "Attack success" is purely the fact that the agent *called* a tool flagged as `attack`.

---

## What's deliberately not here

- **Bring-your-own-agent** — would need an external agent-integration protocol; the cost is real, not the free-lunch headline this kind of rewrite usually promises.
- **MCP server wrapper** — an easy add once the agent-integration story is settled.
- **New attacks/defenses beyond ASB's** — research work, out of scope for a rewrite.
- **Distributed scheduling** — unnecessary for a single-machine, LLM-bound workload.

---

## License

[MIT](LICENSE) © 2025 ASP-X contributors. All third-party dependencies are permissively licensed (MIT / ISC / BSD-2) — no copyleft.

## Citation

ASP-X is a re-implementation. If you use it for research, please cite the original ASB paper that defined the benchmark it evaluates:

```bibtex
@inproceedings{zhang2025agent,
  title={Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents},
  author={Hanrong Zhang and Jingyuan Huang and Kai Mei and Yifei Yao and Zhenting Wang and Chenlu Zhan and Hongwei Wang and Yongfeng Zhang},
  booktitle={The Thirteenth International Conference on Learning Representations},
  year={2025}
}
```
