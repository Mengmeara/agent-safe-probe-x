# app/services/settings.py
# -*- coding: utf-8 -*-
"""
任务检测相关设置模块：
- 提供默认配置模板
- 校验前端提交的配置字段
- 合并用户配置与默认值
"""

from __future__ import annotations
from typing import Dict, Any, Tuple


def load_default_settings() -> Dict[str, Any]:
    """加载默认配置模板"""
    return {
        "injection_method": "observation_prompt_injection",
        "attack_tool": ["all"],
        "llms": ["ollama/llama3:8b"],
        "attack_types": ["clean_opi"],
        "task_num": 1,
        "defense_type": None,
        "write_db": False,
        "read_db": False
    }


def validate_settings_payload(settings: Dict[str, Any] | None) -> Tuple[Dict[str, Any], int]:
    """校验配置字段是否齐全；返回 (payload, http_code)"""
    try:
        data = settings or {}

        # External API mode: relaxed validation
        if data.get("agent_type") == "external_api":
            if not data.get("api_endpoint"):
                return {"valid": False, "error": "外部API模式需要提供 api_endpoint"}, 400
            if not isinstance(data.get("attack_types", []), (list, tuple)) or not data.get("attack_types"):
                return {"valid": False, "error": "attack_types 必须为非空列表"}, 400
            if "task_num" in data:
                try:
                    n = int(data["task_num"])
                    if n <= 0:
                        return {"valid": False, "error": "task_num 必须为正整数"}, 400
                except Exception:
                    return {"valid": False, "error": "task_num 必须为整数"}, 400
            # 多轮探测参数验证
            injection_mode = data.get("injection_mode", "opi")
            if injection_mode not in ("dpi", "opi", "dpi+opi"):
                return {"valid": False, "error": "injection_mode 必须为 dpi, opi 或 dpi+opi"}, 400
            if "max_turns" in data:
                try:
                    mt = int(data["max_turns"])
                    if mt < 1 or mt > 10:
                        return {"valid": False, "error": "max_turns 必须在 1-10 之间"}, 400
                except (ValueError, TypeError):
                    return {"valid": False, "error": "max_turns 必须为整数"}, 400
            return {"valid": True}, 200

        # Standard mode
        required = ["injection_method", "attack_tool", "llms", "attack_types"]
        for f in required:
            if f not in data:
                return {"valid": False, "error": f"缺少必需字段: {f}"}, 400

        if not isinstance(data["llms"], (list, tuple)) or not data["llms"]:
            return {"valid": False, "error": "llms 必须为非空列表"}, 400
        if not isinstance(data["attack_types"], (list, tuple)) or not data["attack_types"]:
            return {"valid": False, "error": "attack_types 必须为非空列表"}, 400

        if "task_num" in data:
            try:
                n = int(data["task_num"])
                if n <= 0:
                    return {"valid": False, "error": "task_num 必须为正整数"}, 400
            except Exception:
                return {"valid": False, "error": "task_num 必须为整数"}, 400

        return {"valid": True}, 200
    except Exception as e:
        return {"valid": False, "error": str(e)}, 400


def merge_with_defaults(user_settings: Dict[str, Any] | None) -> Dict[str, Any]:
    """将用户配置与默认值合并（attack_tool 强制默认）"""
    defaults = load_default_settings()
    us = user_settings or {}

    # External API mode: preserve API-specific fields, apply minimal defaults
    if us.get("agent_type") == "external_api":
        merged = {**defaults, **us}
        merged["injection_method"] = "direct_prompt_injection"
        # Preserve API fields from user input
        for key in ("agent_type", "api_endpoint", "api_key", "api_model", "custom_prompts",
                    "injection_mode", "max_turns", "agent_persona", "agent_system_prompt"):
            if key in us:
                merged[key] = us[key]
        return merged

    merged = {**defaults, **us}
    merged["attack_tool"] = defaults["attack_tool"]
    return merged
