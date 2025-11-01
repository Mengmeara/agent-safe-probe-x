# app/services/tasks.py
import os, re, time, threading, subprocess, sqlite3
from datetime import datetime

from core.path_utils import resolve_path, build_paths, PROJECT_ROOT
from app.services.db import (
    DB_PATH, update_task_in_db, mark_task_status, mark_run_status, get_task_from_db
)
from app.services.files import extract_task_results

# --------- 进程内共享状态（从 server.py 挪入）---------
running_tasks      = {}   # 运行中的任务
task_results_cache = {}   # 结果缓存
log_monitors       = {}   # 日志监控状态

# SocketIO 句柄由 server 注入，避免循环依赖
_socketio = None
def set_socketio(io):
    """由 server.py 在创建好 SocketIO 后注入。"""
    global _socketio
    _socketio = io

# --------- 工具函数（从 server.py 挪入）---------
def get_local_ip():
    """获取本机IP地址"""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def parse_log_path_from_command(cmd_str):
    """从命令字符串中解析日志文件路径"""
    log_pattern = r'>\s*([^\s]+\.log)\s+2>&1'
    m = re.search(log_pattern, cmd_str)
    if m:
        log_path = m.group(1)
        return resolve_path(log_path) if not os.path.isabs(log_path) else log_path

    csv_pattern = r'--res_file\s+([^\s]+\.csv)'
    m2 = re.search(csv_pattern, cmd_str)
    if m2:
        csv_path = m2.group(1)
        if not os.path.isabs(csv_path):
            csv_path = resolve_path(csv_path)
        return csv_path.replace('.csv', '.log')
    return None

# --------- 日志/进度 监控（从 server.py 挪入）---------
def monitor_process_output(task_id, process, log_path, on_line: callable = None, idx_in_types: int = 1):
    """
    从 subprocess 的 stdout 实时读取，写入日志文件并通过 SocketIO 推送。
    """
    try:
        if log_path and not os.path.isabs(log_path):
            log_path = resolve_path(log_path)
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        with open(log_path, 'a', encoding='utf-8', errors='replace') as log_file:
            while True:
                if task_id not in running_tasks:
                    break
                status = running_tasks[task_id].get('status')
                if status not in ['running', 'queued']:
                    break

                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    time.sleep(0.05)
                    continue

                msg = line.rstrip('\n')
                if msg:
                    log_file.write(msg + '\n')
                    log_file.flush()
                    if _socketio:
                        _socketio.emit('log_message', {
                            'task_id': task_id,
                            'message': msg,
                            'timestamp': datetime.now().isoformat()
                        }, room=task_id)

                    if on_line is not None:
                        try:
                            on_line(msg, idx_in_types)
                        except Exception:
                            pass

    except Exception as e:
        if _socketio:
            _socketio.emit('log_message', {
                'task_id': task_id,
                'message': f'监控进程输出时出错: {e}',
                'timestamp': datetime.now().isoformat()
            }, room=task_id)

def monitor_log_file(task_id, log_path):
    """监控日志文件变化并实时推送（从 server.py 挪入，接口不变）"""
    if _socketio is None:
        return

    print(f"[日志监控] 启动监控任务 {task_id}, 日志文件: {log_path}")

    if task_id not in log_monitors:
        log_monitors[task_id] = []
    log_monitors[task_id].append({'log_path': log_path, 'last_size': 0})

    MAX_CREATE_WAIT = 60
    waited = 0

    if log_path and not os.path.isabs(log_path):
        log_path = resolve_path(log_path)

    while not os.path.exists(log_path):
        if task_id not in running_tasks or running_tasks[task_id].get('status') not in ['running', 'queued']:
            _socketio.emit('log_message', {
                'task_id': task_id,
                'message': '任务已结束，停止日志监控（日志未创建）',
                'timestamp': datetime.now().isoformat()
            }, room=task_id)
            return
        if waited == 0:
            _socketio.emit('log_message', {
                'task_id': task_id,
                'message': f'等待日志文件创建: {log_path}',
                'timestamp': datetime.now().isoformat()
            }, room=task_id)
        time.sleep(1); waited += 1
        if waited >= MAX_CREATE_WAIT:
            _socketio.emit('log_message', {
                'task_id': task_id,
                'message': f'日志文件未在 {MAX_CREATE_WAIT}s 内创建，停止监控',
                'timestamp': datetime.now().isoformat()
            }, room=task_id)
            return

    try:
        last_size = os.path.getsize(log_path)
    except Exception:
        last_size = 0

    _socketio.emit('log_message', {
        'task_id': task_id,
        'message': f'开始监控日志文件: {log_path}',
        'timestamp': datetime.now().isoformat()
    }, room=task_id)

    INACTIVITY_TIMEOUT = 300
    inactivity = 0
    POLL_INTERVAL = 0.5

    while task_id in running_tasks and running_tasks[task_id].get('status') in ['running', 'queued']:
        try:
            if not os.path.exists(log_path):
                _socketio.emit('log_message', {
                    'task_id': task_id,
                    'message': '日志文件暂不可用（可能被移动/删除），等待重试…',
                    'timestamp': datetime.now().isoformat()
                }, room=task_id)
                time.sleep(1)
                inactivity += 1
                if inactivity >= INACTIVITY_TIMEOUT:
                    break
                continue

            current_size = os.path.getsize(log_path)
            if current_size > last_size:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_size)
                    new_content = f.read()

                if new_content:
                    lines = [ln.strip() for ln in new_content.splitlines() if ln.strip()]
                    MAX_LINES_PER_TICK = 200
                    if len(lines) > MAX_LINES_PER_TICK:
                        head = lines[:MAX_LINES_PER_TICK]
                        tail = len(lines) - MAX_LINES_PER_TICK
                        for ln in head:
                            _socketio.emit('log_message', {
                                'task_id': task_id, 'message': ln,
                                'timestamp': datetime.now().isoformat()
                            }, room=task_id)
                        _socketio.emit('log_message', {
                            'task_id': task_id,
                            'message': f'……其余 {tail} 行已省略（请使用下载或专门查看接口获取完整日志）',
                            'timestamp': datetime.now().isoformat()
                        }, room=task_id)
                    else:
                        for ln in lines:
                            _socketio.emit('log_message', {
                                'task_id': task_id, 'message': ln,
                                'timestamp': datetime.now().isoformat()
                            }, room=task_id)

                    last_size = current_size
                    inactivity = 0
                else:
                    inactivity += POLL_INTERVAL
            else:
                inactivity += POLL_INTERVAL

            if inactivity >= INACTIVITY_TIMEOUT:
                _socketio.emit('log_message', {
                    'task_id': task_id,
                    'message': f'超过 {INACTIVITY_TIMEOUT}s 未见新日志，自动停止监控',
                    'timestamp': datetime.now().isoformat()
                }, room=task_id)
                break

        except Exception as e:
            _socketio.emit('log_message', {
                'task_id': task_id,
                'message': f'日志监控错误: {e}',
                'timestamp': datetime.now().isoformat()
            }, room=task_id)
            time.sleep(1)

        time.sleep(POLL_INTERVAL)

    _socketio.emit('log_message', {
        'task_id': task_id,
        'message': '日志监控结束',
        'timestamp': datetime.now().isoformat()
    }, room=task_id)

def update_task_progress(task_id):
    """更新任务进度（不依赖process对象）"""
    try:
        if task_id not in running_tasks:
            return
        task = running_tasks[task_id]
        if 'process_id' in task:
            try:
                import psutil
                process = psutil.Process(task['process_id'])
                if not process.is_running():
                    if task['status'] == 'running':
                        task['status'] = 'completed'
                        task['progress'] = 100
                        task['current_step'] = '检测完成'
                        task['end_time'] = datetime.now().isoformat()

                        extract_task_results(task_id, task)
                        if 'results' in task:
                            update_task_in_db(task_id, {'results': task['results']})
            except Exception:
                if task['status'] == 'running':
                    task['status'] = 'completed'
                    task['progress'] = 100
                    task['current_step'] = '检测完成'
                    task['end_time'] = datetime.now().isoformat()
                    extract_task_results(task_id, task)
                    if 'results' in task:
                        update_task_in_db(task_id, {'results': task['results']})
    except Exception:
        pass

def monitor_task_progress(task_id, process):
    """基于 psutil 或简单 wait 监控任务，并在结束后提取结果与广播（保持原逻辑）"""
    try:
        print("🔍 开始监控任务进度")
        task = running_tasks.get(task_id)
        if not task:
            print(f"❌ 任务 {task_id} 不存在")
            return

        try:
            import psutil
            proc = psutil.Process(process.pid)
            print(f"✅ 使用psutil监控进程 PID={process.pid}")
        except Exception:
            print("⚠️ psutil不可用或出错，使用简单方法"); proc = None

        if proc is not None:
            print("🔍 使用psutil监控，等待进程完成...")
            while proc.is_running():
                if hasattr(process, 'stdout') and process.stdout is not None:
                    try:
                        output = process.stdout.readline()
                        if output:
                            output = output.strip()
                            if output:
                                if 'Attack started at:' in output:
                                    running_tasks[task_id]['current_step'] = '开始攻击测试...'
                                    running_tasks[task_id]['progress'] = 20
                                elif '任务完成:' in output or 'Task completed:' in output:
                                    running_tasks[task_id]['current_step'] = '处理任务结果...'
                                    running_tasks[task_id]['progress'] = min(90, running_tasks[task_id].get('progress', 0) + 10)
                                elif 'Attack ended at:' in output:
                                    running_tasks[task_id]['current_step'] = '完成检测...'
                                    running_tasks[task_id]['progress'] = 95

                                if 'logs' not in running_tasks[task_id]:
                                    running_tasks[task_id]['logs'] = []
                                running_tasks[task_id]['logs'].append({
                                    'timestamp': datetime.now().isoformat(),
                                    'message': output
                                })
                                if len(running_tasks[task_id]['logs']) > 50:
                                    running_tasks[task_id]['logs'] = running_tasks[task_id]['logs'][-50:]
                    except Exception as e:
                        print(f"⚠️ 读取进程输出时出错: {e}")
                time.sleep(0.1)
            print("✅ 进程已退出（使用psutil检测）")
        else:
            print("🔍 使用简单方法等待进程完成（无psutil）...")
            try:
                process.wait()
                print("✅ 进程已结束")
            except Exception as e:
                print(f"⚠️ 等待进程时出错: {e}")

        print("🔍 检查进程返回码...")
        try:
            return_code = process.returncode
            print(f"📊 进程返回码: {return_code}")
            if return_code == 0:
                running_tasks[task_id]['status'] = 'completed'
                running_tasks[task_id]['progress'] = 100
                running_tasks[task_id]['current_step'] = '检测完成'
                print("✅ 任务已完成")
            else:
                running_tasks[task_id]['status'] = 'failed'
                running_tasks[task_id]['error'] = f'进程退出码: {return_code}'
                print(f"❌ 任务失败，退出码: {return_code}")
        except Exception as e:
            print(f"⚠️ 获取进程返回码时出错: {e}")
            running_tasks[task_id]['status'] = 'completed'
            running_tasks[task_id]['progress'] = 100
            running_tasks[task_id]['current_step'] = '检测完成'

        running_tasks[task_id]['end_time'] = datetime.now().isoformat()

        try:
            update_task_in_db(task_id, {
                'status': running_tasks[task_id]['status'],
                'end_time': running_tasks[task_id]['end_time'],
                'progress': running_tasks[task_id].get('progress', 100),
                'current_step': running_tasks[task_id].get('current_step', ''),
                'error': running_tasks[task_id].get('error')
            })
            print(f"✅ 任务状态已更新到数据库: {running_tasks[task_id]['status']}")
        except Exception as e:
            print(f"❌ 更新数据库失败: {e}")

        if running_tasks[task_id]['status'] == 'completed':
            print("⏳ 等待结果文件写入完成..."); time.sleep(2)
            print(f"🔍 调用 extract_task_results，任务ID: {task_id}")
            try:
                extract_task_results(task_id, running_tasks[task_id])
                if 'results' in running_tasks[task_id]:
                    update_task_in_db(task_id, {'results': running_tasks[task_id]['results']})
                    print("✅ 任务结果已保存到数据库")
            except Exception as e:
                print(f"❌ 提取结果失败: {e}")

        # 广播
        if _socketio:
            if running_tasks[task_id]['status'] == 'completed':
                payload = {
                    'task_id': task_id, 'status': 'completed', 'progress': 100,
                    'timestamp': running_tasks[task_id]['end_time']
                }
                _socketio.emit('task_complete', payload, room=task_id)
                _socketio.emit('task_status', payload, room=task_id)
            else:
                _socketio.emit('task_status', {
                    'task_id': task_id,
                    'status': running_tasks[task_id]['status'],
                    'current_step': running_tasks[task_id].get('current_step', '任务结束'),
                    'timestamp': datetime.now().isoformat()
                })

    except Exception as e:
        print(f"监控任务进度时出错: {e}")
        if task_id in running_tasks:
            running_tasks[task_id]['status'] = 'failed'
            running_tasks[task_id]['error'] = str(e)
            running_tasks[task_id]['end_time'] = datetime.now().isoformat()
            try:
                update_task_in_db(task_id, {
                    'status': 'failed',
                    'end_time': running_tasks[task_id]['end_time'],
                    'error': str(e)
                })
                print("✅ 任务失败状态已更新到数据库")
            except Exception as e2:
                print(f"❌ 更新数据库失败: {e2}")
