# LegalConsultantAgent Service

This folder hosts a self-contained micro-service that exposes the existing `LegalConsultantAgent`
through a lightweight Flask API. It does not modify, patch, or depend on `main_attacker.py` so it
can run side-by-side with the rest of the framework.

## Features
- Keeps all service-specific code inside `services/legal_consultant_service`.
- Reuses the production agent stack (`FIFOScheduler`, `AgentFactory`, `LLMKernel`) under the hood.
- Provides a `/run` endpoint that triggers a single task for the legal consultant with optional
  attack-mode toggles.
- Loads attacker-tool metadata automatically from `data/all_attack_tools_non_aggressive.jsonl`.

## Usage
Run the API (defaults to port `5055`):

```
python -m services.legal_consultant_service.app
```

Sample request:

```
curl -X POST http://localhost:5055/run \
  -H "Content-Type: application/json" \
  -d '{
        "task": "Review the attached contract draft for compliance gaps.",
        "attack_mode": "direct",
        "attacker_tool": "LegalDocumentAccessTool",
        "workflow_mode": "manual"
      }'
```

Structured tasks (same shape as `agent_attack.py`) are also accepted:

```
curl -X POST http://localhost:5055/run \
  -H "Content-Type: application/json" \
  -d '{
        "task": {
          "target": "generic_target",
          "task_params": {"objective": "评估合同合法性"}
        }
      }'
```

## Configuration
Environment variables (all optional):

| Variable | Default | Description |
| --- | --- | --- |
| `LEGAL_AGENT_LLM` | `ollama/llama3:8b` | LLM name passed to `LLMKernel` |
| `LEGAL_AGENT_BACKEND` | `ollama` | Backend flag for the kernel |
| `LEGAL_AGENT_WORKFLOW` | `manual` | Default workflow mode |
| `LEGAL_AGENT_AGENT_LOG` | `console` | Destination for agent logs |
| `LEGAL_AGENT_SCHEDULER_LOG` | `console` | Destination for scheduler logs |
| `LEGAL_AGENT_LLM_LOG` | `console` | Destination for LLM kernel logs |
| `LEGAL_AGENT_MAX_TOKENS` | `256` | Max new tokens per generation |

Any path-level configuration (tools, attacker tools) defaults to the project-level `data` folder but
can be pointed elsewhere by editing `config.py` or overriding the dataclass on construction.

