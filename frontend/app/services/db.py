# frontend/app/services/db.py
import os, json, sqlite3
from datetime import datetime

# 放在 frontend 根的 tasks.db
THIS_FILE = os.path.abspath(__file__)
FRONTEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(THIS_FILE)))  # .../frontend/app
FRONTEND_ROOT = os.path.dirname(FRONTEND_ROOT)                                # .../frontend
DB_PATH = os.path.join(FRONTEND_ROOT, "tasks.db")

def ensure_schema():
    """一次性建表 + 幂等补列；只保留这一处对 schema 的定义。"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 基表（幂等）
    c.execute("""
    CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        config TEXT,
        created_time TEXT,
        start_time TEXT,
        end_time TEXT,
        progress INTEGER DEFAULT 0,
        current_step TEXT,
        results TEXT,
        error TEXT,
        injection_method TEXT,
        llm_name TEXT,
        attack_types TEXT,
        timestamp TEXT,
        updated_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS detection_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id TEXT NOT NULL,
      attack_type TEXT NOT NULL,
      injection_method TEXT,
      llm_name TEXT,
      timestamp TEXT,
      result_path TEXT,
      log_path TEXT,
      status TEXT DEFAULT 'queued',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT
    )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_runs_task ON detection_runs(task_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_runs_task_attack ON detection_runs(task_id, attack_type)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_runs_status ON detection_runs(status)")

    # 幂等补列（万一老库缺列）
    c.execute("PRAGMA table_info(tasks)")
    cols = {row[1] for row in c.fetchall()}
    need = {
        'status': "ALTER TABLE tasks ADD COLUMN status TEXT",
        'config': "ALTER TABLE tasks ADD COLUMN config TEXT",
        'created_time': "ALTER TABLE tasks ADD COLUMN created_time TEXT",
        'start_time': "ALTER TABLE tasks ADD COLUMN start_time TEXT",
        'end_time': "ALTER TABLE tasks ADD COLUMN end_time TEXT",
        'progress': "ALTER TABLE tasks ADD COLUMN progress INTEGER",
        'current_step': "ALTER TABLE tasks ADD COLUMN current_step TEXT",
        'results': "ALTER TABLE tasks ADD COLUMN results TEXT",
        'error': "ALTER TABLE tasks ADD COLUMN error TEXT",
        'updated_at': "ALTER TABLE tasks ADD COLUMN updated_at TEXT",
        'injection_method': "ALTER TABLE tasks ADD COLUMN injection_method TEXT",
        'llm_name': "ALTER TABLE tasks ADD COLUMN llm_name TEXT",
        'attack_types': "ALTER TABLE tasks ADD COLUMN attack_types TEXT",
        'timestamp': "ALTER TABLE tasks ADD COLUMN timestamp TEXT",
    }
    for col, ddl in need.items():
        if col not in cols:
            c.execute(ddl)

    conn.commit()
    conn.close()

def mark_task_status(task_id: str, status: str | None, start=None, end=None, progress=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    sets, vals = [], []
    if status is not None: sets.append("status=?"); vals.append(status)
    if start is not None:  sets.append("start_time=?"); vals.append(start)
    if end is not None:    sets.append("end_time=?"); vals.append(end)
    if progress is not None: sets.append("progress=?"); vals.append(progress)
    vals.append(task_id)
    if sets:
        c.execute(f"UPDATE tasks SET {', '.join(sets)} WHERE id=?", vals)
        conn.commit()
    conn.close()

def mark_run_status(task_id: str, attack_type: str, status: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
      UPDATE detection_runs SET status=?, updated_at=?
      WHERE task_id=? AND attack_type=?
    """, (status, datetime.now().isoformat(), task_id, attack_type))
    conn.commit()
    conn.close()

def save_task_to_db(task: dict):
    """
    task: dict，至少包含 id, status, created_time, progress
    可选包含：start_time, end_time, injection_method, llm_name, attack_types(JSON串), timestamp
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    INSERT INTO tasks (id, status, created_time, start_time, end_time, progress,
                       injection_method, llm_name, attack_types, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      status=excluded.status,
      created_time=COALESCE(excluded.created_time, tasks.created_time),
      start_time=COALESCE(excluded.start_time, tasks.start_time),
      end_time=COALESCE(excluded.end_time, tasks.end_time),
      progress=COALESCE(excluded.progress, tasks.progress),
      injection_method=COALESCE(excluded.injection_method, tasks.injection_method),
      llm_name=COALESCE(excluded.llm_name, tasks.llm_name),
      attack_types=COALESCE(excluded.attack_types, tasks.attack_types),
      timestamp=COALESCE(excluded.timestamp, tasks.timestamp)
    """, (
        task.get('id'),
        task.get('status'),
        task.get('created_time'),
        task.get('start_time'),
        task.get('end_time'),
        task.get('progress'),
        task.get('config', {}).get('injection_method') or task.get('injection_method'),
        (task.get('config', {}).get('llms') or [None])[0] if isinstance(task.get('config', {}).get('llms'), list) else task.get('llm_name'),
        json.dumps(task.get('config', {}).get('attack_types')) if task.get('config', {}).get('attack_types') else task.get('attack_types'),
        task.get('timestamp')
    ))
    conn.commit()
    conn.close()

def update_task_in_db(task_id: str, update_data: dict):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        update_fields, values = [], []
        for key, value in update_data.items():
            if key in ('config', 'results') and isinstance(value, dict):
                value = json.dumps(value, ensure_ascii=False)
            update_fields.append(f"{key} = ?")
            values.append(value)
        update_fields.append("updated_at = ?")
        values.append(datetime.now().isoformat())
        values.append(task_id)
        sql = f"UPDATE tasks SET {', '.join(update_fields)} WHERE id = ?"
        cursor.execute(sql, values)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] update_task_in_db 失败: {e}")

def load_tasks_from_db() -> list[dict]:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM tasks ORDER BY created_time DESC')
        rows = cursor.fetchall()
        tasks = []
        for row in rows:
            task = dict(row)
            if task.get('config'):
                try: task['config'] = json.loads(task['config'])
                except Exception: pass
            if task.get('results'):
                try: task['results'] = json.loads(task['results'])
                except Exception: pass
            tasks.append(task)
        conn.close()
        return tasks
    except Exception as e:
        print(f"[DB] load_tasks_from_db 失败: {e}")
        return []

def get_task_from_db(task_id: str) -> dict | None:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM tasks WHERE id = ?', (task_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            task = dict(row)
            if task.get('config'):
                try: task['config'] = json.loads(task['config'])
                except Exception: pass
            if task.get('results'):
                try: task['results'] = json.loads(task['results'])
                except Exception: pass
            return task
        return None
    except Exception as e:
        print(f"[DB] get_task_from_db 失败: {e}")
        return None

__all__ = [
    "DB_PATH", "ensure_schema",
    "mark_task_status", "mark_run_status",
    "save_task_to_db", "update_task_in_db",
    "load_tasks_from_db", "get_task_from_db",
]
