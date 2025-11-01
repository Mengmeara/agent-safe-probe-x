# app/services/queries.py
import os, re, glob, sqlite3
from datetime import datetime

from core.path_utils import resolve_path, PROJECT_ROOT
from app.services.db import DB_PATH, load_tasks_from_db
from app.services.tasks import running_tasks

def _abs_path(p: str):
    if not p:
        return None
    if os.path.isabs(p):
        return p if os.path.exists(p) else None
    cand = resolve_path(p)
    return cand if os.path.exists(cand) else None

def sync_running_tasks_with_db():
    """
    把内存中的 running_tasks 与 DB 对齐：
    - DB 终止态 → 移除内存残留
    - DB 运行态 → 合并补齐到内存
    """
    try:
        db_tasks = load_tasks_from_db()
        terminal = {'completed', 'failed', 'cancelled'}
        for t in db_tasks:
            tid = t.get('id')
            if not tid:
                continue
            status = (t.get('status') or '').lower()
            if status in terminal:
                running_tasks.pop(tid, None)
            else:
                cur = running_tasks.get(tid, {})
                merged = {**t, **cur}
                if t.get('status'):
                    merged['status'] = t['status']
                if t.get('progress') is not None:
                    merged['progress'] = t['progress']
                running_tasks[tid] = merged
    except Exception as e:
        print(f"[sync_running_tasks_with_db] ignore error: {e}")

def collect_all_tasks_data():
    """
    汇总任务列表（内存 + DB + detection_runs 路径补齐）
    - 与 server.py 旧版 _collect_all_tasks_data 等价
    - 即使找不到结果/日志路径也照样展示该任务
    """
    db_tasks = load_tasks_from_db()
    task_map = {}

    # 1) 先放入内存任务
    for t in running_tasks.values():
        if not t or not t.get('id'):
            continue
        task_map[t['id']] = dict(t)

    # 2) 再合并 DB 任务（DB 终止态覆盖内存）
    terminal = {'completed', 'failed', 'cancelled'}
    for dt in db_tasks:
        tid = dt.get('id')
        if not tid:
            continue
        if tid not in task_map:
            task_map[tid] = dict(dt)
        else:
            if (dt.get('status') or '').lower() in terminal:
                task_map[tid].update(dt)
            else:
                for k, v in dt.items():
                    if v not in (None, '', []):
                        if task_map[tid].get(k) in (None, '', []):
                            task_map[tid][k] = v

    # 3) 为每个任务补齐 result/log 路径（优先 detection_runs 表）
    tasks_out = []
    for task in task_map.values():
        tid = task.get('id')
        cfg = task.get('config') or {}
        inj = task.get('injection_method') or cfg.get('injection_method') or "observation_prompt_injection"
        llm = task.get('llm_name') or ((cfg.get('llms') or ["llama3:8b"])[0] if isinstance(cfg.get('llms'), list) else cfg.get('llms', 'llama3:8b'))
        ts  = task.get('timestamp')

        # 3.1 detection_runs 查路径
        log_file = None
        res_file = None
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                SELECT result_path, log_path FROM detection_runs
                WHERE task_id=? ORDER BY id DESC LIMIT 1
            """, (tid,))
            row = c.fetchone()
            conn.close()
            if row:
                res_file, log_file = row[0], row[1]
        except Exception:
            pass

        # 3.2 兜底：从 config / custom_command 猜
        if not (res_file or log_file):
            if cfg.get('res_file'):
                res_file = cfg.get('res_file')
            elif cfg.get('log_file') and cfg.get('log_file', '').endswith('.log'):
                res_file = cfg.get('log_file').replace('.log', '.csv')
            if not log_file and cfg.get('log_file'):
                log_file = cfg.get('log_file')
            if not (res_file or log_file):
                cmd = cfg.get('custom_command', '')
                if cmd:
                    m = re.search(r'--res_file\s+([^\s>]+)', cmd)
                    if m:
                        res_file = m.group(1)
                    m2 = re.search(r'>\s+([^\s]+\.log)', cmd)
                    if m2:
                        log_file = m2.group(1)

        # 3.3 统一绝对路径（不存在则置 None）
        res_file = _abs_path(res_file)
        log_file = _abs_path(log_file)

        # 3.4 再兜底：按 timestamp 精确命名匹配
        if not (res_file and log_file) and ts:
            base_dir = os.path.join(PROJECT_ROOT, "logs", inj, f"ollama:{llm}", "no_memory", "single")
            if not res_file:
                cand = os.path.join(base_dir, f"*-single-{ts}.csv")
                matches = glob.glob(cand)
                if matches:
                    res_file = matches[0]
            if not log_file:
                cand = os.path.join(base_dir, f"*-single-{ts}.log")
                matches = glob.glob(cand)
                if matches:
                    log_file = matches[0]

        task_with_paths = dict(task)
        task_with_paths['res_path'] = res_file
        task_with_paths['log_path'] = log_file
        tasks_out.append(task_with_paths)

    # 4) 按创建时间倒序
    def _parse_time(x):
        ct = x.get('created_time')
        if not ct:
            return datetime(1970, 1, 1)
        try:
            if 'T' in ct or '+' in ct or ct.endswith('Z'):
                return datetime.fromisoformat(ct.replace('Z', '+00:00'))
            else:
                return datetime.strptime(ct, '%Y-%m-%d %H:%M:%S')
        except Exception:
            return datetime(1970, 1, 1)

    tasks_out.sort(key=_parse_time, reverse=True)
    return tasks_out
