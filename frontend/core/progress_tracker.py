"""
Lightweight ProgressTracker for ASB frontend

Place this file under the `frontend/` directory and import it from `app.py` as:

    from progress_tracker import ProgressTracker

Usage (high level):
  - Create one tracker per run: `tracker = ProgressTracker(task_id, total_types)`
  - Pass `tracker.on_line` as the `on_line` callback to `monitor_process_output`

The class parses percentage patterns (e.g. "45%") and several configurable
keyword patterns. It maps parsed progress into the per-attack progress range
so the UI sees a monotonic progress between 0..100 across multiple attack types.

Do not duplicate this file's contents elsewhere — import it from here.

"""

import re
from typing import Optional
from datetime import datetime

# NOTE: this module references running_tasks, mark_task_status and socketio defined
# in your app.py. To avoid circular imports, import these objects at runtime inside
# methods or import app-level functions where you call the tracker.

class ProgressTracker:
    """Parse subprocess stdout lines and emit task progress updates.

    Behavior summary:
    - If a percentage like "37%" appears in a line, map it into the current
      attack_type's progress range.
    - Otherwise, match a set of human-friendly step keywords and map them to
      a heuristic local percentage.

    The tracker uses mark_task_status(...) to persist progress to DB and
    emits a SocketIO 'task_status' event to the task room.

    Initialization:
        tracker = ProgressTracker(task_id, total_types, socketio_ref, running_tasks_ref, mark_task_status_fn)

    To use with monitor_process_output, pass `tracker.on_line` as a callback:
        monitor_process_output(task_id, proc, log_file, on_line=tracker.on_line, idx_in_types=idx)
    """

    # Default keyword patterns. You can add more to better match main_attacker.py output.
    STEP_PATTERNS = [
        (re.compile(r'Attack started at', re.I), 0.15, '开始攻击测试…'),
        (re.compile(r'Preparing tasks|Loading tasks', re.I), 0.10, '准备任务…'),
        (re.compile(r'Running attack', re.I), 0.35, '执行攻击中…'),
        (re.compile(r'Writing results|Saved CSV|Result written', re.I), 0.85, '写入结果…'),
        (re.compile(r'Attack ended at|Task completed', re.I), 0.95, '收尾…'),
    ]

    PCT_RE = re.compile(r'(?<!\d)(\d{1,3})\s?%(?!\d)')

    def __init__(self, task_id: str, total_types: int, socketio_obj=None, running_tasks_obj=None, mark_task_status_fn=None):
        self.task_id = task_id
        self.total_types = max(1, int(total_types))
        self.last_progress = -1
        # injected references (set by caller to avoid circular import issues)
        self.socketio = socketio_obj
        self.running_tasks = running_tasks_obj
        self.mark_task_status = mark_task_status_fn

    def _base_range(self, idx: int):
        span = 100.0 / self.total_types
        low = span * (idx - 1)
        high = span * idx
        return low, high

    def _emit_status(self, message: str, progress: int):
        # Best-effort persistence + in-memory update + socket emit.
        try:
            # update in-memory if provided
            if self.running_tasks is not None:
                task = self.running_tasks.get(self.task_id)
                if task is not None:
                    task['progress'] = progress
                    task['current_step'] = message
            # persist
            if self.mark_task_status is not None:
                try:
                    self.mark_task_status(self.task_id, None, progress=progress)
                except Exception:
                    pass
            # socket emit
            if self.socketio is not None:
                try:
                    self.socketio.emit('task_status', {
                        'task_id': self.task_id,
                        'status': (self.running_tasks.get(self.task_id, {}).get('status') if self.running_tasks is not None else 'running'),
                        'progress': progress,
                        'current_step': message,
                        'timestamp': datetime.now().isoformat()
                    }, room=self.task_id)
                except Exception:
                    pass
        except Exception:
            # swallow all exceptions here — progress tracking must not break the runner
            pass

    def _maybe_update(self, message: str, progress: int):
        progress = int(max(0, min(99, progress)))
        if progress != self.last_progress:
            self.last_progress = progress
            self._emit_status(message, progress)

    def on_line(self, line: str, idx_in_types: int = 1):
        """Call on each stdout line. idx_in_types starts from 1.

        Keep this method cheap and exception-safe.
        """
        if not line:
            return
        low, high = self._base_range(idx_in_types)

        # 1) percentage match
        m = self.PCT_RE.search(line)
        if m:
            try:
                pct = int(m.group(1))
                pct = max(0, min(100, pct))
                mapped = int(low + (high - low) * (pct / 100.0))
                self._maybe_update(f'执行中 ({pct}%)', mapped)
                return
            except Exception:
                pass

        # 2) keyword match
        for regex, local_pct, msg in self.STEP_PATTERNS:
            try:
                if regex.search(line):
                    mapped = int(low + (high - low) * local_pct)
                    self._maybe_update(msg, mapped)
                    return
            except Exception:
                continue

        # otherwise: no update
        return
