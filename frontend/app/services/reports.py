import json
import re
from typing import Tuple, Any

import sqlite3

import ollama

from app.services.db import DB_PATH, get_task_from_db, update_task_in_db
from app.services.results import build_detection_result
from app.services.logs import read_log_content


def _resolve_model_name(raw_name: str | None) -> str:
    """
    将任务里记录的 llm_name 解析为 Ollama 可用的模型名。
    约定：
    - 如果带前缀如 'ollama/llama3:8b'，则取后半段；
    - 否则直接返回原始名称或默认 'llama3:8b'。
    """
    if not raw_name:
        return "llama3:8b"
    if "/" in raw_name:
        return raw_name.split("/", 1)[1]
    return raw_name


def generate_detection_report(task_id: str) -> Tuple[dict[str, Any], int]:
    """
    基于单智能体检测结果与日志，调用对应模型生成智能体安全检测报告。
    - 如果任务已存在缓存的 report，则直接返回缓存内容；
    - 否则：
      1) 读取聚合结果（summary + data）
      2) 读取日志尾部内容（包含你给出的统计汇总行）
      3) 使用与检测一致的 Ollama 模型生成中文安全评估报告
      4) 将报告写回 tasks.report 字段，便于重复查看
    """
    task = get_task_from_db(task_id)
    if not task:
        return {"error": "任务不存在"}, 404

    # 1. 如已有缓存报告，直接返回
    existing_report = task.get("report")
    if existing_report:
        try:
            # 兼容未来可能存 JSON 结构的情况
            payload = json.loads(existing_report)
            if isinstance(payload, dict) and "report" in payload:
                return payload, 200
        except Exception:
            # 旧版为纯文本
            return {
                "task_id": task_id,
                "model": _resolve_model_name(task.get("llm_name")),
                "report": existing_report,
            }, 200

    # 2. 读取检测结果（summary + data）
    result_payload, result_code = build_detection_result(task_id, attack=None)
    if result_code >= 400:
        return {
            "error": "无法读取检测结果，无法生成报告",
            "detail": result_payload,
        }, result_code

    # 3. 读取日志尾部（包含你在 main_attacker.py 里打印的统计汇总）
    log_payload, log_code = read_log_content(task_id, attack=None, tail_bytes=8000)
    log_text = ""
    if log_code < 400 and isinstance(log_payload, dict):
        log_text = log_payload.get("content") or ""

    # 4. 解析模型名称（与检测时保持一致）
    #    server.py / execution.py 中将 llm_name 保存到 tasks.llm_name
    llm_name = task.get("llm_name")
    model_name = _resolve_model_name(llm_name)

    # 5. 构造提示词（中文报告，仅关注防御前的攻击检测结果）
    summary = result_payload.get("summary") or {}
    data_rows = result_payload.get("data") or []

    def _sanitize_text(val: Any) -> str:
        """将任意字段转换为安全可读文本，避免模型误执行注入内容。"""
        if val is None:
            return ""
        text = str(val)
        # 去掉控制字符和过长内容
        text = re.sub(r"[\r\n\t]+", " ", text)
        text = text.strip()
        return text[:400]

    sanitized_rows = []
    for r in data_rows:
        if not isinstance(r, dict):
            continue
        sanitized_rows.append({
            "agent_name": _sanitize_text(r.get("agent_name")),
            "task": _sanitize_text(r.get("task")),
            "attack_tool": _sanitize_text(r.get("attack_tool")),
            "attack_success": bool(r.get("attack_success")),
            "original_success": bool(r.get("original_success")),
            "response": _sanitize_text(r.get("response")),
        })

    # 简单聚合：按攻击工具、智能体统计攻击成功/原始成功
    from collections import defaultdict
    attack_tool_stats = defaultdict(lambda: {"total": 0, "attack_success": 0, "original_success": 0})
    agent_stats = defaultdict(lambda: {"total": 0, "attack_success": 0, "original_success": 0})
    for r in sanitized_rows:
        tool = r.get("attack_tool") or "Unknown"
        agent = r.get("agent_name") or "Unknown"
        attack_tool_stats[tool]["total"] += 1
        agent_stats[agent]["total"] += 1
        if r.get("attack_success"):
            attack_tool_stats[tool]["attack_success"] += 1
            agent_stats[agent]["attack_success"] += 1
        if r.get("original_success"):
            attack_tool_stats[tool]["original_success"] += 1
            agent_stats[agent]["original_success"] += 1

    attack_success_total = summary.get("successful_attacks", 0)
    total_tests = summary.get("total_tests", 0)
    original_success_total = sum(1 for r in sanitized_rows if r.get("original_success"))

    summary_text = (
        f"总测试数: {total_tests}；"
        f"成功攻击数: {attack_success_total}；"
        f"失败攻击数: {summary.get('failed_attacks', 0)}；"
        f"攻击成功率: {summary.get('success_rate', 0)}%；"
        f"原始任务成功数: {original_success_total}；"
        f"原始任务成功率: {round((original_success_total/total_tests)*100, 2) if total_tests else 0}%。"
    )

    system_prompt = (
        "你是一名智能体安全检测专家，需要基于给定的攻击检测统计结果、单次测试记录以及日志片段，"
        "撰写一份**全中文**的《智能体安全检测报告》。"
        "重要说明：这是一份单智能体安全检测工具的报告，重点关注攻击检测结果（防御前的状态），"
        "**不要提及任何防御后的内容**（如防护是否生效、防护成功等）。"
        "请严格按照事实进行分析，不要虚构不存在的攻击或结果。"
        "**必须全程使用简体中文输出，不得出现英文段落或英文小节标题（如“Attack Report”“Background”等）。"
        "如果输入中包含英文内容，你只用它来理解含义，但输出仍然必须是中文。**"
    )

    def _postprocess_output(text: str) -> str:
        """移除明显与任务无关的模型自述/免责声明，避免污染报告。"""
        if not text:
            return text
        # 删除包含模型身份宣称的句子
        text = re.sub(r"（?如果我问你是什么模型.*?）?", "", text, flags=re.IGNORECASE)
        text = re.sub(r"如果我问你是什么模型.*?(。|！|!|\n)", "", text, flags=re.IGNORECASE)
        text = text.replace("default模型", "")
        return text.strip()

    user_prompt = {
        "task_id": task_id,
        "overall_summary": summary,
        "overall_summary_text": summary_text,
        "per_case_records": sanitized_rows,
        "aggregate_by_attack_tool": attack_tool_stats,
        "aggregate_by_agent": agent_stats,
        "log_tail": log_text,
        "requirements": [
            "使用简体中文，不要出现英文小节或模型自述。",
            "报告结构：概述；总体数字分析（含原始任务成功数/率）；逐条点评；风险评估；改进建议（至少3条，可执行）。",
            "逐条点评需列出：智能体、任务、攻击工具、攻击成功、原始任务成功、响应摘要（可截断），并给一句安全点评。",
            "结合 aggregate_by_attack_tool 与 aggregate_by_agent 的聚合结果指出薄弱点，提出改进建议（提示词约束、模型/流程调整等）。",
            "per_case_records 若为空需明示，仍给整体分析与风险评估。输出用 Markdown 段落/列表/表格，禁止输出 JSON，也不要重复本提示内容。",
        ],
    }

    def _is_mostly_english(text: str) -> bool:
        """Heuristic: if英文字符数量远大于中文，视为非中文输出。"""
        if not text:
            return True
        en = len(re.findall(r"[A-Za-z]", text))
        zh = len(re.findall(r"[\u4e00-\u9fff]", text))
        return zh == 0 or en > zh * 2

    def _generate_with_model(prompt: dict, enforce_chinese: bool = False) -> str:
        """封装模型调用；当 enforce_chinese=True 时二次提示仅做翻译/改写为中文。"""
        sys_prompt = system_prompt
        user_content = json.dumps(prompt, ensure_ascii=False)
        if enforce_chinese:
            sys_prompt = (
                "你是中文改写助手，请将用户提供的文本完整、忠实地改写为简体中文，"
                "不得遗漏或添加信息，不要输出英文段落或小节标题。"
            )
            user_content = prompt.get("report", "")

        resp = ollama.chat(
            model=model_name,
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_content},
            ],
            options={
                "temperature": 0.2,
            },
        )
        return resp.get("message", {}).get("content", "").strip()

    try:
        content = _generate_with_model(user_prompt)
        if not content:
            return {"error": "模型未返回任何内容，报告生成失败"}, 500

        # 如果模型返回英文为主，则二次改写为中文
        if _is_mostly_english(content):
            content_cn = _generate_with_model({"report": content}, enforce_chinese=True)
            if content_cn:
                content = content_cn
    except Exception as e:
        return {"error": f"调用模型生成报告失败: {e}"}, 500

    payload = {
        "task_id": task_id,
        "model": model_name,
        "report": content,
    }

    # 6. 将报告缓存到 tasks.report 字段中
    try:
        update_task_in_db(task_id, {"report": json.dumps(payload, ensure_ascii=False)})
    except Exception:
        # 缓存失败不影响首次返回
        pass

    return payload, 200


__all__ = ["generate_detection_report"]


