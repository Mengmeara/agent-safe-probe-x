from __future__ import annotations

import copy
import json
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional

from aios.llm_core import llms
from aios.scheduler.fifo_scheduler import FIFOScheduler
from aios.utils.utils import parse_global_args
from pyopenagi.agents.agent_factory import AgentFactory
from pyopenagi.agents.agent_process import AgentProcessFactory

from .config import ServiceConfig


class LegalConsultantServiceError(RuntimeError):
    """Raised when the detached service cannot fulfil a request."""


class LegalConsultantService:
    """
    Bootstraps the minimum runtime needed to execute the LegalConsultantAgent.

    The class hides all heavy initialisation so callers only need to provide a task
    description and (optionally) which attacker tool or injection type they want
    to evaluate.
    """

    def __init__(self, config: Optional[ServiceConfig] = None):
        self.config = config or ServiceConfig()
        self.config.ensure_dirs()

        self._args_template = self._build_args_template()
        self._scheduler = self._build_scheduler()
        self._agent_factory = self._build_agent_factory(self._scheduler)
        self._attacker_tools = self._load_attacker_tools()
        if not self._attacker_tools:
            raise LegalConsultantServiceError(
                "No attacker tools found for legal_consultant_agent."
            )

        self._default_tool = next(iter(self._attacker_tools.values()))
        self._lock = Lock()

    def _build_args_template(self):
        parser = parse_global_args()
        args = parser.parse_args([])
        args.llm_name = self.config.llm_name
        args.max_new_tokens = self.config.max_new_tokens
        args.scheduler_log_mode = self.config.scheduler_log_mode
        args.agent_log_mode = self.config.agent_log_mode
        args.llm_kernel_log_mode = self.config.llm_kernel_log_mode
        args.use_backend = self.config.use_backend
        args.workflow_mode = self.config.workflow_mode
        args.attacker_tools_path = self.config.attacker_tools()
        args.tools_info_path = self.config.tools_info()
        args.direct_prompt_injection = False
        args.observation_prompt_injection = False
        args.attack_type = "naive"
        args.defense_type = None
        args.pot_backdoor = False
        args.pot_clean = False
        args.memory_attack = False
        args.clean = False
        args.write_db = False
        args.read_db = False
        args.database = str(self.config.project_root / "memory_db" / "chroma_db")
        args.single_agent = self.config.agent_path
        return args

    def _build_scheduler(self):
        llm = llms.LLMKernel(
            llm_name=self.config.llm_name,
            max_gpu_memory=None,
            eval_device=None,
            max_new_tokens=self.config.max_new_tokens,
            log_mode=self.config.llm_kernel_log_mode,
            use_backend=self.config.use_backend,
        )
        scheduler = FIFOScheduler(llm=llm, log_mode=self.config.scheduler_log_mode)
        scheduler.start()
        return scheduler

    def _build_agent_factory(self, scheduler: FIFOScheduler) -> AgentFactory:
        agent_process_factory = AgentProcessFactory()
        return AgentFactory(
            agent_process_queue=scheduler.agent_process_queue,
            agent_process_factory=agent_process_factory,
            agent_log_mode=self.config.agent_log_mode,
        )

    def _load_attacker_tools(self) -> Dict[str, Dict[str, Any]]:
        path = Path(self.config.attacker_tools())
        if not path.exists():
            raise LegalConsultantServiceError(
                f"Attacker tools file not found: {path}"
            )

        tool_index: Dict[str, Dict[str, Any]] = {}
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                payload = json.loads(line)
                if payload.get("Corresponding Agent") != "legal_consultant_agent":
                    continue
                name = payload["Attacker Tool"]
                tool_index[name] = payload
        return tool_index

    def _select_attack_tool(self, tool_name: Optional[str]) -> Dict[str, Any]:
        if tool_name is None:
            return self._default_tool
        if tool_name not in self._attacker_tools:
            raise LegalConsultantServiceError(
                f"Unknown attacker tool '{tool_name}'. "
                f"Available options: {list(self._attacker_tools)}"
            )
        return self._attacker_tools[tool_name]

    def run_task(
        self,
        task: Any,
        *,
        attacker_tool: Optional[str] = None,
        workflow_mode: Optional[str] = None,
        attack_mode: str = "none",
    ) -> Dict[str, Any]:
        """
        Execute a single task with the LegalConsultantAgent.

        Args:
            task: Plain language instruction for the agent.
            attacker_tool: Optional attacker tool name (defaults to the first entry
                found in the metadata file).
            workflow_mode: Override for manual/automatic workflows.
            attack_mode: 'none', 'direct', or 'observation'.
        """
        task_prompt = self._coerce_task_prompt(task)

        tool_payload = self._select_attack_tool(attacker_tool)
        args = copy.deepcopy(self._args_template)
        args.workflow_mode = workflow_mode or self.config.workflow_mode
        args.direct_prompt_injection = attack_mode == "direct"
        args.observation_prompt_injection = attack_mode == "observation"

        # Reuse the aggressive flag if present
        agg_raw = tool_payload.get("Aggressive", False)
        agg_flag = (
            agg_raw
            if isinstance(agg_raw, bool)
            else str(agg_raw).lower() == "true"
        )

        with self._lock:
            result = self._agent_factory.run_agent(
                self.config.agent_path,
                task_prompt,
                args,
                tool_payload,
                vector_db=None,
                agg=agg_flag,
            )

        return self._sanitize_result(result, task_prompt, attack_mode)

    def _coerce_task_prompt(self, task_payload: Any) -> str:
        """
        Normalise various task payload formats into a single prompt string.

        The detached service is often called with the same JSON structure used by
        `agent_attack.py`, where `task` is a dict containing items such as
        `target` and `task_params.objective`. This helper keeps backward
        compatibility with plain string prompts while supporting the structured
        layout.
        """
        if isinstance(task_payload, str):
            prompt = task_payload.strip()
            if not prompt:
                raise LegalConsultantServiceError(
                    "Task prompt must be a non-empty string."
                )
            return prompt

        if isinstance(task_payload, dict):
            task_params = task_payload.get("task_params") or {}
            candidate_fields = [
                task_payload.get("objective"),
                task_payload.get("prompt"),
                task_payload.get("description"),
                task_payload.get("instructions"),
                task_params.get("objective"),
                task_params.get("prompt"),
                task_params.get("description"),
                task_params.get("instructions"),
            ]

            prompt = next(
                (
                    str(value).strip()
                    for value in candidate_fields
                    if isinstance(value, str) and value.strip()
                ),
                None,
            )

            if prompt:
                prefix_parts = []
                target = task_payload.get("target")
                if isinstance(target, str) and target.strip():
                    prefix_parts.append(f"Target: {target.strip()}")
                context = task_params.get("context")
                if isinstance(context, str) and context.strip():
                    prefix_parts.append(f"Context: {context.strip()}")
                if prefix_parts:
                    prefix_parts.append(prompt)
                    return "\n".join(prefix_parts)
                return prompt

            # Fall back to a JSON dump if we cannot infer a clean prompt.
            try:
                return json.dumps(task_payload, ensure_ascii=False)
            except Exception as exc:  # pragma: no cover - best effort
                raise LegalConsultantServiceError(
                    "Task payload could not be interpreted as a string."
                ) from exc

        raise LegalConsultantServiceError(
            "Task payload must be either a string or an object with task metadata."
        )

    @staticmethod
    def _sanitize_result(raw: Dict[str, Any], task: str, attack_mode: str) -> Dict[str, Any]:
        """Drop non-serialisable objects before returning to API consumers."""
        return {
            "agent_name": raw.get("agent_name"),
            "task": task,
            "attack_mode": attack_mode,
            "workflow_failure": raw.get("workflow_failure"),
            "tool_call_success": raw.get("tool_call_success"),
            "attacker_tool": raw.get("attacker_tool"),
            "messages": raw.get("messages", []),
            "result": raw.get("result"),
        }

