# app/services/sockets.py
import os
import sqlite3
from datetime import datetime

from flask_socketio import emit, join_room, leave_room
from app.services.db import DB_PATH
from app.services.tasks import running_tasks, log_monitors
from core.path_utils import build_paths

def register_socketio_handlers(socketio):
    """
    统一注册 socket.io 事件处理器，避免在 server.py 中塞大量装饰器。
    """
    @socketio.on('connect')
    def _connect():
        # request.sid 由 flask-socketio 注入，这里不直接引用 request 避免循环导入
        emit('connected', {'message': '已连接到服务器'})

    @socketio.on('disconnect')
    def _disconnect():
        # 可按需打印日志
        pass

    @socketio.on('join_task')
    def _join_task(data):
        """
        加入房间并推送历史日志内容（如存在）。
        原有逻辑保留：优先 log_monitors，再 running_tasks 构建路径，再 DB 检索。
        """
        try:
            task_id = data if isinstance(data, str) else (data or {}).get('task_id')
            if not task_id:
                return

            join_room(task_id)
            emit('joined_task', {'task_id': task_id, 'message': f'已加入任务 {task_id}'})

            def _send_all_logs(log_file: str, source='unknown') -> bool:
                if not (log_file and os.path.exists(log_file)):
                    return False
                file_size = os.path.getsize(log_file)
                if file_size <= 0:
                    return False
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if not content.strip():
                            return False
                        for line in content.strip().split('\n'):
                            line = line.strip()
                            if not line:
                                continue
                            emit('log_message', {
                                'task_id': task_id,
                                'message': line,
                                'timestamp': datetime.now().isoformat()
                            })
                    return True
                except Exception:
                    return False

            # 1) 来自监控器（最可靠）
            if task_id in log_monitors and len(log_monitors[task_id]) > 0:
                for m in log_monitors[task_id]:
                    log_file = m.get('log_path')
                    if log_file and _send_all_logs(log_file, 'log_monitors'):
                        return

            # 2) 根据 running_tasks 拼路径
            task_info = running_tasks.get(task_id)
            if task_info:
                cfg = task_info.get('config', {}) or {}
                inj = task_info.get('injection_method') or cfg.get('injection_method', 'observation_prompt_injection')
                llm = task_info.get('llm_name') or (cfg.get('llms') or ['llama3:8b'])[0]
                atks = task_info.get('attack_types') or cfg.get('attack_types', ['context_ignoring'])
                ts = task_info.get('timestamp')
                if not ts:
                    from datetime import datetime as _dt
                    ts = _dt.now().strftime('%Y%m%d_%H%M%S')
                if atks:
                    _, log_file = build_paths(inj, llm, atks[0], ts)
                    if _send_all_logs(log_file, 'running_tasks'):
                        return

            # 3) 数据库检索
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                SELECT log_path FROM detection_runs
                WHERE task_id=? ORDER BY id DESC LIMIT 1
            """, (task_id,))
            row = c.fetchone()
            conn.close()
            if row and row[0]:
                if _send_all_logs(row[0], 'database'):
                    return

            # 4) 如果还没有日志，提示前端
            from app.services.tasks import running_tasks as _rt
            if task_id in _rt and _rt[task_id].get('status') in ['running', 'queued']:
                emit('log_message', {
                    'task_id': task_id,
                    'message': '日志文件尚未创建，请等待...',
                    'timestamp': datetime.now().isoformat()
                })
        except Exception:
            # 静默失败即可，避免断开
            pass

    @socketio.on('leave_task')
    def _leave_task(data):
        try:
            task_id = data if isinstance(data, str) else (data or {}).get('task_id')
            if not task_id:
                return
            leave_room(task_id)
            emit('left_task', {'task_id': task_id, 'message': f'已离开任务 {task_id}'})
        except Exception:
            pass
