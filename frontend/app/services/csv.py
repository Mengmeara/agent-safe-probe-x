# app/services/csv.py
# -*- coding: utf-8 -*-
"""
CSV 结果读取与下载服务：
- 解析任务对应的 CSV 路径
- 分页读取（统一 normalize_df）
- 生成下载响应
"""

from __future__ import annotations
import os
from typing import Optional, Tuple, Dict, Any

import pandas as pd
from flask import send_file

from app.services.db import get_task_from_db
from app.services.files import normalize_df
from core.path_utils import resolve_path


def _resolve_csv_path_from_task(task: Dict[str, Any]) -> Optional[str]:
    """
    根据 task(dict) 推导 CSV 绝对路径：
      1) task.config.res_file
      2) task.config.log_file(若以 .log 结尾则替换为 .csv)
    """
    cfg = task.get("config") or {}
    res_file = cfg.get("res_file") or ""

    if not res_file:
        log_file = cfg.get("log_file") or ""
        if log_file.endswith(".log"):
            res_file = log_file[:-4] + ".csv"

    if not res_file:
        return None

    if not os.path.isabs(res_file):
        res_file = resolve_path(res_file)

    return res_file


def get_csv_page(task_id: str, page: int = 1, per_page: int = 20) -> Tuple[Dict[str, Any], int]:
    """
    返回分页后的 CSV 数据（已 normalize）。
    """
    task = get_task_from_db(task_id)
    if not task:
        return {"error": "任务不存在"}, 404

    csv_path = _resolve_csv_path_from_task(task)
    if not csv_path or not os.path.exists(csv_path):
        return {"error": "CSV文件不存在"}, 404

    try:
        df = pd.read_csv(csv_path)
        df = normalize_df(df)

        total = len(df)
        per_page = max(1, int(per_page))
        page = max(1, int(page))
        total_pages = max(1, (total + per_page - 1) // per_page)

        start_idx = min(total, (page - 1) * per_page)
        end_idx = min(total, start_idx + per_page)
        df_page = df.iloc[start_idx:end_idx]

        succ = int(df["attack_success"].sum()) if "attack_success" in df.columns else 0

        return {
            "task_id": task_id,
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
            "data": df_page.to_dict("records"),
            "summary": {
                "total_tests": total,
                "successful_attacks": succ,
                "failed_attacks": total - succ,
            },
        }, 200
    except Exception as e:
        return {"error": f"获取CSV数据失败: {e}"}, 500


def download_csv_response(task_id: str):
    """
    返回 send_file 响应；路由层直接 return。
    """
    task = get_task_from_db(task_id)
    if not task:
        from flask import abort
        abort(404, description="任务不存在")

    csv_path = _resolve_csv_path_from_task(task)
    if not csv_path or not os.path.exists(csv_path):
        from flask import abort
        abort(404, description=f"CSV文件不存在: {csv_path}")

    filename = os.path.basename(csv_path)
    return send_file(csv_path, as_attachment=True, download_name=filename, mimetype="text/csv")
