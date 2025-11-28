from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


@dataclass
class ServiceConfig:
    """
    Centralized configuration for the detached LegalConsultantAgent service.

    The defaults intentionally mirror the ones used by `main_attacker.py` so
    behaviour stays consistent unless explicitly overridden.
    """

    project_root: Path = field(default_factory=_project_root)
    agent_path: str = "example/legal_consultant_agent"
    llm_name: str = os.getenv("LEGAL_AGENT_LLM", "ollama/llama3:8b")
    use_backend: str | None = os.getenv("LEGAL_AGENT_BACKEND", "ollama")
    max_new_tokens: int = int(os.getenv("LEGAL_AGENT_MAX_TOKENS", "256"))
    scheduler_log_mode: str = os.getenv("LEGAL_AGENT_SCHEDULER_LOG", "console")
    agent_log_mode: str = os.getenv("LEGAL_AGENT_AGENT_LOG", "console")
    llm_kernel_log_mode: str = os.getenv("LEGAL_AGENT_LLM_LOG", "console")
    workflow_mode: str = os.getenv("LEGAL_AGENT_WORKFLOW", "manual")
    tools_info_path: Path = field(
        default_factory=lambda: _project_root() / "data" / "all_normal_tools.jsonl"
    )
    attacker_tools_path: Path = field(
        default_factory=lambda: _project_root()
        / "data"
        / "all_attack_tools_non_aggressive.jsonl"
    )
    result_dir: Path = field(default_factory=lambda: _project_root() / "results")

    def tools_info(self) -> str:
        return str(self.tools_info_path)

    def attacker_tools(self) -> str:
        return str(self.attacker_tools_path)

    def ensure_dirs(self) -> None:
        self.result_dir.mkdir(parents=True, exist_ok=True)

