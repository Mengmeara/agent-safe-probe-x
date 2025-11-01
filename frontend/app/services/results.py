# app/services/results.py
import os, glob, sqlite3
from datetime import datetime

import pandas as pd

from core.path_utils import PROJECT_ROOT
from app.services.db import DB_PATH, get_task_from_db
from app.services.files import normalize_df  # 已在 files.py 中
# 说明：返回 (payload: dict, status_code: int)

def build_detection_result(task_id: str, attack: str | None):
    """
    聚合并返回某任务的结果：
      1) 优先从 detection_runs 取 result_path
      2) 没有则按 task 的 injection_method/llm/timestamp 兜底定位
      3) 读取 CSV -> normalize_df -> 汇总/records
    返回 (payload, http_status)
    """
    try:
        # 1) detection_runs 精确查找结果路径
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if attack:
            c.execute("""
              SELECT result_path FROM detection_runs
              WHERE task_id=? AND attack_type=? AND result_path IS NOT NULL AND result_path != ''
              ORDER BY id DESC LIMIT 1
            """, (task_id, attack))
        else:
            c.execute("""
              SELECT result_path FROM detection_runs
              WHERE task_id=? AND result_path IS NOT NULL AND result_path != ''
              ORDER BY id DESC LIMIT 1
            """, (task_id,))
        row = c.fetchone()
        conn.close()

        result_path = row[0] if row and row[0] else None
        if result_path and not os.path.exists(result_path):
            result_path = None  # 路径记录存在但文件不在 → 走兜底

        # 2) 兜底：从 tasks 推断路径
        if not result_path:
            task = get_task_from_db(task_id)
            if not task:
                return ({"error": "任务不存在，且无结果路径记录"}, 404)

            inj = (
                task.get("injection_method")
                or (task.get("config") or {}).get("injection_method")
                or "observation_prompt_injection"
            )
            llm = (
                task.get("llm_name")
                or ((task.get("config") or {}).get("llms") or ["llama3:8b"])[0]
            )
            base_dir = os.path.join(
                PROJECT_ROOT, "logs", inj, f"ollama:{llm}", "no_memory", "single"
            )

            ts = task.get("timestamp")
            candidates = []

            if attack:
                if ts:
                    candidates.append(os.path.join(base_dir, f"{attack}-single-{ts}.csv"))
                else:
                    all_files = glob.glob(os.path.join(base_dir, f"{attack}-single-*.csv"))
                    # 没有以 task_id 命名，保留时间最新
                    candidates = sorted(all_files, key=os.path.getmtime, reverse=True)
            else:
                if ts:
                    candidates = glob.glob(os.path.join(base_dir, f"*-single-{ts}.csv"))
                else:
                    all_files = glob.glob(os.path.join(base_dir, "*.csv"))
                    candidates = sorted(all_files, key=os.path.getmtime, reverse=True)

            for p in (candidates if isinstance(candidates, list) else [candidates]):
                if p and os.path.exists(p):
                    result_path = p
                    break

        if not result_path or not os.path.exists(result_path):
            return ({"error": "该任务还没有结果路径记录或文件尚未生成"}, 404)

        # 3) 读取并标准化
        df = pd.read_csv(result_path)
        if df.empty:
            return ({
                "task_id": task_id,
                "result_file": result_path,
                "summary": {"total_tests": 0, "successful_attacks": 0, "failed_attacks": 0, "success_rate": 0},
                "data": []
            }, 200)

        df = normalize_df(df)

        total = len(df)
        succ = int(df["attack_success"].sum()) if "attack_success" in df.columns else 0
        summary = {
            "total_tests": total,
            "successful_attacks": succ,
            "failed_attacks": total - succ,
            "success_rate": int(round((succ / total) * 100)) if total else 0,
        }

        # 统一输出记录（与原 server.py 对齐）
        data = []
        for _, r in df.iterrows():
            d = dict(r)
            data.append({
                "agent_name": d.get("agent_name"),
                "task": d.get("task"),
                "attack_tool": d.get("attack_tool"),
                "attack_success": d.get("attack_success"),
                "original_success": d.get("original_success"),
                "response": d.get("response"),
            })

        return ({
            "task_id": task_id,
            "result_file": result_path,
            "summary": summary,
            "data": data
        }, 200)

    except Exception as e:
        return ({"error": f"读取结果文件失败: {e}"}, 500)
