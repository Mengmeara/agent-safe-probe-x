# app/services/execution.py
import os, threading, subprocess, sqlite3, shlex, base64
from datetime import datetime

from core.progress_tracker import ProgressTracker
from core.path_utils import build_paths, PROJECT_ROOT
from app.services.db import (
    DB_PATH, mark_task_status, mark_run_status, update_task_in_db
)
from app.services.tasks import (
    running_tasks, monitor_process_output
)
from app.services.files import extract_task_results

# 由 server.py 注入的 SocketIO（与 services.tasks 的注入分离，避免循环依赖）
_socketio = None
def set_socketio(io):
    global _socketio
    _socketio = io

def run_detection_task(task_id: str, config_data: dict, ts: str):
    """
    后台执行检测任务（解析标准输出以更新进度）：
    - 保持与 server.py 原逻辑一致
    - 通过 services.tasks 的 monitor_process_output 推流日志
    - 使用 core.progress_tracker.ProgressTracker 解析进度
    """
    try:
        # 进入 RUNNING 态（内存 + DB）
        now_iso = datetime.now().isoformat()
        if task_id in running_tasks:
            running_tasks[task_id]['status'] = 'running'
            running_tasks[task_id]['start_time'] = now_iso
            running_tasks[task_id]['progress'] = 0
            running_tasks[task_id]['current_step'] = '开始执行'
        mark_task_status(task_id, status='running', start=now_iso, progress=0)

        # 解析参数
        injection_method = config_data.get('injection_method') or 'observation_prompt_injection'
        llm_name = (config_data.get('llms') or ['llama3:8b'])[0]
        attack_types = config_data.get('attack_types') or ['context_ignoring']
        task_num = int(config_data.get('task_num') or 1)
        agent = config_data.get('agent')
        total = len(attack_types)

        # 进度跟踪器
        tracker = ProgressTracker(
            task_id,
            total_types=total,
            socketio_obj=_socketio,              # 用当前模块注入的 socketio
            running_tasks_obj=running_tasks,
            mark_task_status_fn=mark_task_status
        )

        # 逐个攻击类型执行
        for idx, atk in enumerate(attack_types, start=1):
            # detection_runs -> running
            mark_run_status(task_id, atk, 'running')

            # 初始进度提示
            base_progress_per_type = 100 / total
            start_progress = max(1, int((idx - 1) * base_progress_per_type))
            if task_id in running_tasks:
                running_tasks[task_id]['progress'] = start_progress
                running_tasks[task_id]['current_step'] = f'开始执行 {atk} ({idx}/{total})'
            mark_task_status(task_id, None, progress=start_progress)
            if _socketio:
                _socketio.emit('task_status', {
                    'task_id': task_id,
                    'status': 'running',
                    'progress': start_progress,
                    'current_step': running_tasks.get(task_id, {}).get('current_step', ''),
                    'timestamp': datetime.now().isoformat()
                }, room=task_id)

            # 生成 CSV/LOG 目标
            res_csv, log_file = build_paths(injection_method, llm_name, atk, ts)
            os.makedirs(os.path.dirname(res_csv), exist_ok=True)

            # 构造命令
            agent_type = config_data.get('agent_type')

            if agent_type == 'external_api':
                # ── External API Probe 模式（多轮智能体安全探测）──
                api_endpoint = config_data.get('api_endpoint', '')
                api_key = config_data.get('api_key', '')
                api_model = config_data.get('api_model', '')
                custom_prompts = config_data.get('custom_prompts', '')
                judge_model = llm_name.replace('ollama/', '') if llm_name.startswith('ollama/') else llm_name

                # 多轮探测参数
                injection_mode = config_data.get('injection_mode', 'opi')
                max_turns = int(config_data.get('max_turns', 3))
                agent_persona = config_data.get('agent_persona', '')
                agent_system_prompt = config_data.get('agent_system_prompt', '')

                prompts_b64 = ''
                if custom_prompts:
                    prompts_b64 = base64.b64encode(custom_prompts.encode('utf-8')).decode('utf-8')

                system_prompt_b64 = ''
                if agent_system_prompt:
                    system_prompt_b64 = base64.b64encode(agent_system_prompt.encode('utf-8')).decode('utf-8')

                cmd = [
                    "bash", "-lc",
                    (
                        f"cd {PROJECT_ROOT} && "
                        f"source /home/flowteam/miniconda3/etc/profile.d/conda.sh && "
                        f"conda activate ASB && "
                        f"python main_api_probe.py "
                        f"--api_endpoint {shlex.quote(api_endpoint)} "
                        f"--api_key {shlex.quote(api_key)} "
                        f"{'--api_model ' + shlex.quote(api_model) + ' ' if api_model else ''}"
                        f"--attack_types {shlex.quote(atk)} "
                        f"--task_num {task_num} "
                        f"--judge_model {shlex.quote(judge_model)} "
                        f"--injection_mode {shlex.quote(injection_mode)} "
                        f"--max_turns {max_turns} "
                        f"{'--persona ' + shlex.quote(agent_persona) + ' ' if agent_persona else ''}"
                        f"{'--system_prompt_b64 ' + system_prompt_b64 + ' ' if system_prompt_b64 else ''}"
                        f"--timestamp {ts} "
                        f"--single "
                        f"--res_file {res_csv} "
                        f"{'--custom_prompts_b64 ' + prompts_b64 + ' ' if prompts_b64 else ''}"
                    )
                ]
            else:
                # ── 标准 main_attacker.py 模式 ──
                cmd = [
                    "bash", "-lc",
                    (
                        f"cd {PROJECT_ROOT} && "
                        f"source /home/flowteam/miniconda3/etc/profile.d/conda.sh && "
                        f"conda activate ASB && "
                        f"python main_attacker.py "
                        f"--llm_name ollama/{llm_name} "
                        f"--attack_type {atk} "
                        f"--use_backend ollama "
                        f"--attacker_tools_path data/all_attack_tools.jsonl "
                        f"--tasks_path data/agent_task_pot.jsonl "
                        f"--task_num {task_num} "
                        f"--single_agent {agent} "
                        f"--workflow_mode manual "
                        f"--single "
                        f"--timestamp {ts} "
                        f"--{injection_method} "
                        f"--res_file {res_csv}"
                    )
                ]

            # 启动子进程（直连 stdout/stderr）
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            # 记录 PID（用于取消）
            if task_id in running_tasks:
                running_tasks[task_id]['process_id'] = proc.pid

            # 输出监控线程（实时写日志 + 推流 + 进度解析）
            log_thread = threading.Thread(
                target=monitor_process_output,
                args=(task_id, proc, log_file),
                kwargs={'on_line': tracker.on_line, 'idx_in_types': idx},
                daemon=True
            )
            log_thread.start()

            # 等待进程结束
            proc.wait()
            try:
                log_thread.join(timeout=3)
            except Exception:
                pass

            # 判定结果
            if os.path.exists(res_csv) and os.path.getsize(res_csv) > 0:
                mark_run_status(task_id, atk, 'completed')
            else:
                mark_run_status(task_id, atk, 'failed')

            # 更新任务整体进度
            prog = int(idx * 100 / total)
            mark_task_status(task_id, None, progress=prog)
            if task_id in running_tasks:
                running_tasks[task_id]['progress'] = prog
                running_tasks[task_id]['current_step'] = f'{atk} 完成({idx}/{total})'
                if _socketio:
                    _socketio.emit('task_status', {
                        'task_id': task_id,
                        'status': running_tasks[task_id]['status'],
                        'progress': prog,
                        'current_step': running_tasks[task_id]['current_step'],
                        'timestamp': datetime.now().isoformat()
                    }, room=task_id)

        # —— 所有 attack 完成：根据 detection_runs 状态汇总任务结果 ——
        end_ts = datetime.now().isoformat()

        # 统计 detection_runs 中该任务的状态，避免所有子任务失败但总任务仍标记为 completed
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                "SELECT status FROM detection_runs WHERE task_id=?",
                (task_id,)
            )
            rows = c.fetchall()
            conn.close()
            statuses = [ (r[0] or '').lower() for r in rows ] if rows else []
        except Exception:
            statuses = []

        has_success = any(s == 'completed' for s in statuses)
        has_failed  = any(s == 'failed' for s in statuses)

        final_status = 'completed' if has_success else ('failed' if has_failed else 'completed')

        if task_id in running_tasks:
            running_tasks[task_id]['status'] = final_status
            running_tasks[task_id]['end_time'] = end_ts
            running_tasks[task_id]['progress'] = 100
            running_tasks[task_id]['current_step'] = '检测完成' if final_status == 'completed' else '任务失败'

        mark_task_status(task_id, status=final_status, end=end_ts, progress=100)

        payload = {
            'task_id': task_id,
            'status': final_status,
            'progress': 100,
            'timestamp': end_ts
        }
        if _socketio:
            _socketio.emit('task_status', payload, room=task_id)
            _socketio.emit('task_complete', payload, room=task_id)
            _socketio.emit('task_status', payload)

    except Exception as e:
        # 失败态
        err_ts = datetime.now().isoformat()
        if task_id in running_tasks:
            running_tasks[task_id]['status'] = 'failed'
            running_tasks[task_id]['end_time'] = err_ts
            running_tasks[task_id]['error'] = str(e)
        mark_task_status(task_id, status='failed', end=err_ts)

        payload = {
            'task_id': task_id,
            'status': 'failed',
            'progress': running_tasks.get(task_id, {}).get('progress', 0),
            'timestamp': err_ts,
            'error': str(e)
        }
        if _socketio:
            _socketio.emit('task_status', payload, room=task_id)
            _socketio.emit('task_status', payload)
        # 这里不记录 logger，保持与原 server.py 行为一致（由上层记录）
