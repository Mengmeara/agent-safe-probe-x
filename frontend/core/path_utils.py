# frontend/app/core/path_utils.py
import os, sys

# ---------- 路径基准 ----------
# 当前文件: .../frontend/app/core/path_utils.py
CURRENT_FILE = os.path.abspath(__file__)

# app 层目录: .../frontend/app
APP_ROOT = os.path.dirname(os.path.dirname(CURRENT_FILE))

# frontend 根目录: .../frontend
FRONTEND_BASE = os.path.dirname(APP_ROOT)

# 项目根目录: .../agent-safe-probe-x
PROJECT_ROOT = os.path.dirname(FRONTEND_BASE)

# 确保 frontend 和项目根都能被 import 到
for p in (PROJECT_ROOT, FRONTEND_BASE):
    if p not in sys.path:
        sys.path.insert(0, p)
# ---------- 路径基准 ----------


def resolve_path(p: str) -> str:
    """把相对路径优先解析到 frontend，再回退到项目根；绝对路径原样返回"""
    if not p:
        return p
    if os.path.isabs(p):
        return p
    cand1 = os.path.join(FRONTEND_BASE, p)
    if os.path.exists(cand1):
        return cand1
    cand2 = os.path.join(PROJECT_ROOT, p)
    return cand2


def _logs_base(injection_method: str, llm_name: str) -> str:
    """
    返回 logs/<inj>/ollama:<llm>/no_memory/single 的绝对路径
    （优先项目根 logs 目录）
    """
    subdir = os.path.join("logs", injection_method, f"ollama:{llm_name}", "no_memory", "single")
    base1 = os.path.join(PROJECT_ROOT, subdir)
    base2 = os.path.join(FRONTEND_BASE, subdir)
    return base1 if os.path.isdir(base1) or not os.path.isdir(base2) else base2


def build_paths(injection_method: str, llm_name: str, attack_type: str, ts: str):
    """
    拼接标准化 CSV/LOG 路径（与 main_attacker.py 落盘一致）
    """
    base = _logs_base(injection_method, llm_name)
    csv_path = os.path.join(base, f"{attack_type}-single-{ts}.csv")
    log_path = os.path.join(base, f"{attack_type}-single-{ts}.log")
    return csv_path, log_path


__all__ = [
    "PROJECT_ROOT", "FRONTEND_BASE", "APP_ROOT",
    "resolve_path", "_logs_base", "build_paths",
]
