# app/services/logs.py
import os
import glob
import re
from datetime import datetime, timedelta

import sqlite3
from flask import send_file, jsonify

from core.path_utils import PROJECT_ROOT, resolve_path
from app.services.db import DB_PATH, get_task_from_db

# =============================
# 1. 辅助函数（保留原有 + 增强）
# =============================

def _safe_path(p):
    """确保路径安全、存在"""
    if not p:
        return None
    if not os.path.isabs(p):
        p = resolve_path(p)
    return p if os.path.exists(p) else None


def list_log_files(base_dir=None, days=None):
    if not base_dir:
        base_dir = os.path.join(PROJECT_ROOT, "logs")

    logs = []
    try:
        pattern = os.path.join(base_dir, "**/*.log")
        for path in glob.glob(pattern, recursive=True):
            stat = os.stat(path)
            mtime = datetime.fromtimestamp(stat.st_mtime)
            if days and (datetime.now() - mtime).days > days:
                continue
            logs.append({
                "path": path,
                "filename": os.path.basename(path),
                "size_kb": round(stat.st_size / 1024, 1),
                "modified": mtime.isoformat()
            })
        logs.sort(key=lambda x: x["modified"], reverse=True)
        return logs
    except Exception as e:
        return [{"error": str(e)}]


def delete_old_logs(base_dir=None, keep_days=7):
    if not base_dir:
        base_dir = os.path.join(PROJECT_ROOT, "logs")

    cutoff = datetime.now() - timedelta(days=keep_days)
    deleted = 0
    for path in glob.glob(os.path.join(base_dir, "**/*.log"), recursive=True):
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(path))
            if mtime < cutoff:
                os.remove(path)
                deleted += 1
        except Exception:
            continue
    return deleted


def clear_all_logs(base_dir=None):
    if not base_dir:
        base_dir = os.path.join(PROJECT_ROOT, "logs")

    if not os.path.exists(base_dir):
        return 0

    deleted = 0
    for root, _, files in os.walk(base_dir):
        for f in files:
            if f.endswith(".log"):
                try:
                    os.remove(os.path.join(root, f))
                    deleted += 1
                except Exception:
                    pass
    return deleted


# =============================
# 2. 日志路径解析（修复点：优先 detection_runs）
# =============================

def _find_log_from_detection_runs(task_id: str, attack: str | None):
    """优先从 detection_runs 表读取 log_path（与迁移前行为一致）"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if attack:
            c.execute("""
                SELECT log_path FROM detection_runs
                WHERE task_id=? AND attack_type=?
                ORDER BY id DESC LIMIT 1
            """, (task_id, attack))
        else:
            print(f"=================")
            c.execute("""
                SELECT log_path FROM detection_runs
                WHERE task_id=?
                ORDER BY id DESC LIMIT 1
            """, (task_id,))
        row = c.fetchone()
        conn.close()
        if row and row[0]:
            return _safe_path(row[0])
    except Exception:
        pass
    return None


def _find_log_from_task_config(task_id: str):
    """从 task.config 的 log_file 或 custom_command 里推断"""
    task = get_task_from_db(task_id) or {}
    cfg = task.get("config", {}) or {}

    # 1) 直接指定 log_file
    log_file = cfg.get("log_file")
    if log_file:
        p = _safe_path(log_file)
        if p:
            return p

    # 2) 从 custom_command 中的 shell 重定向解析
    cmd = cfg.get("custom_command", "")
    if cmd:
        m = re.search(r'>\s*([^\s]+\.log)', cmd)
        if m:
            p = _safe_path(m.group(1))
            if p:
                return p

    return None


def find_log_path(task_id: str, attack: str | None = None):
    """
    统一入口：先查 detection_runs，再回退 task.config/custom_command。
    """
    print(f"find_log_path: {task_id}, {attack}")

    p = _find_log_from_detection_runs(task_id, attack)
    print(f"p: {p}")
    if p:
        return p
    return _find_log_from_task_config(task_id)


# =============================
# 3. 读取/下载（兼容 tail_bytes 与原返回形状）
# =============================

def read_log_content(task_id: str, attack: str | None = None, tail_bytes: int | None = None):
    """
    返回 (payload, status_code)
    - payload 结构与迁移前 /api/detection/logs/<task_id> 保持一致：
      {
        "task_id": ...,
        "log_file": ...,
        "file_size": ...,
        "last_modified": ...,
        "is_tail": bool,
        "content": "..."
      }
    """
    log_path = find_log_path(task_id, attack)
    print(f"log_path: {log_path}")
    print(f"task_id: {task_id}")
    if not log_path or not os.path.exists(log_path):
        return ({"error": "未找到日志文件"}, 404)

    try:
        size = os.path.getsize(log_path)
        last_modified = datetime.fromtimestamp(os.path.getmtime(log_path)).isoformat()

        if tail_bytes is not None and tail_bytes >= 0 and tail_bytes < size:
            with open(log_path, "rb") as f:
                f.seek(size - tail_bytes)
                content_bytes = f.read()
            content = content_bytes.decode("utf-8", errors="replace")
            return ({
                "task_id": task_id,
                "log_file": log_path,
                "file_size": size,
                "last_modified": last_modified,
                "is_tail": True,
                "content": content
            }, 200)
        else:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return ({
                "task_id": task_id,
                "log_file": log_path,
                "file_size": size,
                "last_modified": last_modified,
                "is_tail": False,
                "content": content
            }, 200)
    except Exception as e:
        return ({"error": f"读取日志失败: {e}"}, 500)


def read_log_lines(log_file, max_lines=500):
    """（保留给其他用法）读取最后 N 行"""
    try:
        if not log_file or not os.path.exists(log_file):
            return {"error": "日志文件不存在"}
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            if len(lines) > max_lines:
                lines = lines[-max_lines:]
            return {
                "log_file": log_file,
                "lines": [ln.strip() for ln in lines if ln.strip()],
                "line_count": len(lines)
            }
    except Exception as e:
        return {"error": str(e)}


def download_log_file(log_file):
    if not log_file or not os.path.exists(log_file):
        return jsonify({"error": "日志文件不存在"}), 404
    return send_file(log_file, as_attachment=True)

# --- 兼容旧调用：server.py 里曾经 from app.services.logs import get_log_file_path ---

def get_log_file_path(task_or_task_id, attack: str | None = None):
    """
    兼容旧接口：
    - 传入 task_id(str) 时：走 detection_runs 优先的查找（推荐）
    - 传入 task(dict) 时：优先用 detection_runs（若有 id），否则 fallback 到 config/custom_command
    """
    # 字符串：直接按 task_id 查
    if isinstance(task_or_task_id, str):
        return find_log_path(task_or_task_id, attack)

    # 字典：尽量拿 id 先查 detection_runs
    task = task_or_task_id or {}
    tid = task.get("id")
    if tid:
        p = find_log_path(tid, attack)
        if p:
            return p

    # 没 id 或没查到 → 用 config/custom_command 兜底
    cfg = task.get("config", {}) or {}
    log_file = cfg.get("log_file")
    if log_file:
        p = _safe_path(log_file)
        if p:
            return p
    cmd = cfg.get("custom_command", "")
    if cmd:
        m = re.search(r'>\s*([^\s]+\.log)', cmd)
        if m:
            p = _safe_path(m.group(1))
            if p:
                return p
    return None
