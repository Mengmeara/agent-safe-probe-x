# ASP-X — Agent Safe Probe X

TypeScript rewrite of [ASB (Agent Security Bench, ICLR 2025)](https://github.com/agiresearch/ASB), packaged as a developer-friendly tool with a web UI, interactive trace visualization, and zero-conda installation.

## What it does

ASP-X runs prompt-injection attacks against LLM agents and measures how often the agent gets fooled into invoking dangerous tools. It supports four attack families from the original ASB paper:

- **DPI** — Direct Prompt Injection (poison the user task)
- **OPI** — Observation Prompt Injection (poison a tool result)
- **Memory Poisoning** — poison the agent's retrieved memory context
- **PoT Backdoor** — trigger-activated injection in the system prompt

…and defense methods like delimiters, sandwich prevention, instructional prevention, paraphrasing, shuffling.

## Quick start

```bash
# clone, then
pnpm install
pnpm build

# copy .env.example to .env and add your LLM API key
cp .env.example .env

# run one attack
node packages/cli/dist/index.js run --config configs/dpi.yml

# or start the web UI
node packages/cli/dist/index.js serve
# then open http://localhost:4399
```

The CLI accepts the same yaml configs as the original ASB.

## Layout

```
packages/
  shared/   # Zod-defined types shared front/back
  core/     # ReAct loop, attacks, defenses, judges, agent definitions
  server/   # HTTP API + SSE + SQLite persistence
  cli/      # npx entry: run, serve, list-models, list-agents
  web/      # React + Tailwind frontend
```

## What's different from the original ASB

| | Original ASB | ASP-X |
|---|---|---|
| Language | Python | TypeScript |
| Install | conda + heavy ML deps | one `pnpm install` |
| Config | hand-edited yaml | web form or yaml |
| Add a new model API | write Python class | fill a form |
| Watch progress | tail logs | live UI |
| See results | CSV | interactive trace timeline |
| Eval capability | — | preserved |

Original ASB's evaluation semantics are preserved: same four attack families, same agents, same defense methods, same ASR/RR metric definitions.

## License

MIT.
