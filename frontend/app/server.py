#!/usr/bin/env python3
"""
智能体安全检测工具 - Flask后端API服务器
"""

# ---------- begin: imports ----------
import os, sys, re, json, time, uuid, math, traceback, subprocess, threading
import sqlite3, glob
from datetime import datetime

import pandas as pd
import numpy as np
from flask import Flask, request, jsonify, send_file, send_from_directory, current_app
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.exceptions import HTTPException

# 业务
from core.progress_tracker import ProgressTracker

from core.path_utils import PROJECT_ROOT, FRONTEND_BASE, APP_ROOT, resolve_path, _logs_base, build_paths
from app.services.db import (
    DB_PATH, ensure_schema,
    mark_task_status, mark_run_status,
    save_task_to_db, update_task_in_db,
    load_tasks_from_db, get_task_from_db
)
from app.services.files import normalize_df, extract_task_results, list_historical_results
from app.services.tasks import (
    running_tasks, task_results_cache, log_monitors,
    get_local_ip,
    parse_log_path_from_command,
    monitor_process_output, monitor_log_file,
    update_task_progress, monitor_task_progress
)
from app.services.tasks import set_socketio as set_tasks_socketio
from app.services.execution import run_detection_task, set_socketio as set_exec_socketio
from app.services.commands import generate_command_payload
from app.services.queries import collect_all_tasks_data, sync_running_tasks_with_db
from app.services.results import build_detection_result
from app.services.logs import (
    list_log_files, delete_old_logs, clear_all_logs, read_log_lines, download_log_file, read_log_content, get_log_file_path
)
from app.services.csv import get_csv_page, download_csv_response
from app.services.settings import (
    load_default_settings,
    validate_settings_payload,
    merge_with_defaults,
)
from app.services.catalog import get_agents_payload, get_attack_tools_payload
from app.services.streams import stream_task_logs_response
from app.services.sockets import register_socketio_handlers


ensure_schema()

# ---------- end: imports ----------

# ---------- begin: Flask app & static/uploads/results ----------
PUBLIC_STATIC   = os.path.join(FRONTEND_BASE, "public", "static")
UPLOAD_FOLDER   = os.path.join(FRONTEND_BASE, "public", "uploads")
RESULTS_FOLDER  = os.path.join(FRONTEND_BASE, "public", "results")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# 只创建一次 app
app = Flask(__name__, static_folder=PUBLIC_STATIC)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
set_tasks_socketio(socketio)   # 已在上一步添加过，保留
set_exec_socketio(socketio)    # 新增：给 execution 服务注入 socketio
register_socketio_handlers(socketio)

app.config["UPLOAD_FOLDER"]  = UPLOAD_FOLDER
app.config["RESULTS_FOLDER"] = RESULTS_FOLDER
# ---------- end: Flask app & static/uploads/results ----------

sync_running_tasks_with_db()

def _resp_json(payload):
    """
    兼容 Flask 路由内部调用的返回值：
    - Response对象 -> .get_json()
    - (Response, status) 元组 -> 取第一个再 .get_json()
    - 已经是 dict/list -> 原样返回
    """
    from flask import Response
    if isinstance(payload, tuple):
        payload = payload[0]
    if isinstance(payload, Response):
        try:
            return payload.get_json()
        except Exception:
            # 兜底：尝试按 data 解码
            data = payload.get_data(as_text=True)
            try:
                import json
                return json.loads(data)
            except Exception:
                return None
    # 已经是原生对象
    return payload

@app.route('/')
def index():
    public_root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'public')
    return send_from_directory(public_root, 'index.html')

@app.route('/simple')
def simple():
    """简单测试页面"""
    return send_from_directory('.', 'simple_test.html')

@app.route('/test')
def test():
    return send_from_directory(app.static_folder, 'test_page.html')

# favicon（防止控制台 404 噪音）
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/x-icon')

# 单页应用（可选）：所有未知路径都回到 index.html（便于前端路由）
@app.route('/<path:path>')
def spa_fallback(path):
    public_root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'public')
    # 已有的文件直接返回
    abs_static = os.path.join(app.static_folder, path)
    abs_public = os.path.join(public_root, path)
    if os.path.isfile(abs_static):
        return send_from_directory(app.static_folder, path)
    if os.path.isfile(abs_public):
        return send_from_directory(public_root, path)
    # 其余交给前端路由
    return send_from_directory(public_root, 'index.html')


@app.errorhandler(Exception)
def _any_error(e):
    if isinstance(e, HTTPException):
        return jsonify({
            "error": e.name,
            "message": e.description
        }), e.code
    # 非 HTTPException，给出堆栈，便于前端看清原因
    tb = traceback.format_exc()
    return jsonify({
        "error": "InternalServerError",
        "message": str(e),
        "traceback": tb
    }), 500


@app.route('/debug')
def debug():
    """调试页面"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>ASB Debug</title>
        <script src="https://unpkg.com/axios/dist/axios.min.js"></script>
    </head>
    <body>
        <h1>ASB Debug Page</h1>
        <div id="status">Loading...</div>
        <button onclick="testAll()">Test All APIs</button>
        <div id="results"></div>
        
        <script>
            async function testAll() {
                const results = document.getElementById('results');
                results.innerHTML = '<h2>Testing APIs...</h2>';
                
                try {
                    // Test agents API
                    const agentsRes = await axios.get('/api/agents');
                    results.innerHTML += '<p>✅ Agents API: ' + agentsRes.data.length + ' agents</p>';
                    
                    // Test attack tools API
                    const toolsRes = await axios.get('/api/attack-tools');
                    results.innerHTML += '<p>✅ Attack Tools API: ' + toolsRes.data.length + ' tools</p>';
                    
                    // Test detection
                    const detectionRes = await axios.post('/api/detection/start', {
                        agent: 'financial_analyst_agent',
                        task_num: 1
                    });
                    results.innerHTML += '<p>✅ Detection API: ' + detectionRes.data.status + '</p>';
                    
                    // Test tasks
                    const tasksRes = await axios.get('/api/tasks');
                    results.innerHTML += '<p>✅ Tasks API: ' + tasksRes.data.length + ' tasks</p>';
                    
                    document.getElementById('status').textContent = 'All tests passed!';
                    
                } catch (error) {
                    results.innerHTML += '<p>❌ Error: ' + error.message + '</p>';
                    document.getElementById('status').textContent = 'Test failed!';
                }
            }
            
            // Auto test on load
            window.onload = testAll;
        </script>
    </body>
    </html>
    '''

@app.route("/api/detection/result/<task_id>", methods=["GET"])
def detection_result(task_id):
    attack = request.args.get("attack")
    payload, code = build_detection_result(task_id, attack)
    return jsonify(payload), code

@app.route('/api/detection/cancel/<task_id>', methods=['POST'])
def cancel_detection(task_id):
    """取消检测任务（先TERM后KILL，写DB并广播）"""
    task = running_tasks.get(task_id)
    if not task:
        return jsonify({'error': '任务不存在'}), 404

    if task.get('status') in ['completed', 'failed', 'cancelled']:
        return jsonify({'error': '任务已完成或已取消，无法再次取消'}), 400

    pid = task.get('process_id')
    end_ts = datetime.now().isoformat()

    # 尝试优雅终止
    if pid:
        try:
            try:
                import psutil
                p = psutil.Process(pid)
                p.terminate()  # SIGTERM
                try:
                    p.wait(timeout=5)
                except psutil.TimeoutExpired:
                    p.kill()    # SIGKILL
            except ImportError:
                # 无 psutil，退化到 os.kill
                import signal
                os.kill(pid, signal.SIGTERM)
                time.sleep(2)
                # 若还活着，再 kill
                try:
                    os.kill(pid, 0)
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass
        except Exception as e:
            print(f"[cancel_detection] 终止进程失败: {e}")

    task['status'] = 'cancelled'
    task['end_time'] = end_ts
    running_tasks[task_id] = task

    # 落库
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE tasks SET status=?, end_time=?, updated_at=? WHERE id=?",
                  ('cancelled', end_ts, end_ts, task_id))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[cancel_detection] 写库失败: {e}")

    socketio.emit('task_status', {
        'task_id': task_id,
        'status': 'cancelled',
        'progress': task.get('progress', 0),
        'timestamp': end_ts
    }, room=task_id)

    return jsonify({'message': '任务已取消'})


@app.route('/api/historical-results', methods=['GET'])
def get_historical_results():
    inj = request.args.get('injection_method', 'observation_prompt_injection')
    llm = request.args.get('llm', 'llama3:8b')
    payload, code = list_historical_results(inj, llm)
    return jsonify(payload), code


@app.route('/api/tasks', methods=['GET'])
def get_all_tasks():
    """获取所有任务列表（仅包装 jsonify）"""
    try:
        tasks = collect_all_tasks_data()
        return jsonify(tasks)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/detection/progress/<task_id>', methods=['GET'])
def get_task_progress(task_id):
    """获取任务实时进度信息"""
    try:
        # 首先检查任务是否在 running_tasks 中
        if task_id in running_tasks:
            task = running_tasks[task_id]

            # 更新任务进度
            update_task_progress(task_id)

            # 获取日志文件路径
            log_file_path = task.get('log_path')

            # 获取任务命令
            task_command = task.get('config', {}).get('custom_command')
            
            # 确保进度值是数字类型
            progress_val = task.get('progress', 0)
            if progress_val is not None:
                try:
                    progress_val = float(progress_val)
                    progress_val = max(0, min(100, progress_val))  # 限制在 0-100 范围
                except (ValueError, TypeError):
                    progress_val = 0
            else:
                progress_val = 0

            return jsonify({
                'task_id': task_id,
                'status': task['status'],
                'progress': progress_val,
                'current_step': task.get('current_step', ''),
                'created_time': task['created_time'],
                'start_time': task.get('start_time'),
                'end_time': task.get('end_time'),
                'config': task['config'],
                'log_file_path': log_file_path,
                'task_command': task_command,
                'logs': task.get('logs', []),
                'error': task.get('error')
            })
        else:
            # 如果不在 running_tasks 中，尝试从数据库获取
            db_task = get_task_from_db(task_id)
            if db_task:
                # 确保进度值是数字类型
                db_progress = db_task.get('progress', 0)
                if db_progress is not None:
                    try:
                        db_progress = float(db_progress)
                        db_progress = max(0, min(100, db_progress))  # 限制在 0-100 范围
                    except (ValueError, TypeError):
                        db_progress = 0
                else:
                    db_progress = 0
                
                # 从数据库获取任务信息
                return jsonify({
                    'task_id': task_id,
                    'status': db_task.get('status', 'unknown'),
                    'progress': db_progress,
                    'current_step': db_task.get('current_step', ''),
                    'created_time': db_task.get('created_time'),
                    'start_time': db_task.get('start_time'),
                    'end_time': db_task.get('end_time'),
                    'config': db_task.get('config', {}),
                    'log_file_path': None,
                    'task_command': None,
                    'logs': [],
                    'error': db_task.get('error')
                })
            else:
                # 如果数据库中也没有，返回 404
                return jsonify({'error': '任务不存在'}), 404

    except Exception as e:
        print(f"获取任务进度失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'获取任务进度失败: {str(e)}'}), 500


@app.route('/api/agents', methods=['GET'])
def get_available_agents():
    payload, code = get_agents_payload()
    return jsonify(payload), code

@app.route('/api/attack-tools', methods=['GET'])
def get_attack_tools():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    payload, code = get_attack_tools_payload(project_root)
    return jsonify(payload), code

@app.route('/api/generate-command', methods=['POST'])
def generate_command():
    try:
        data = request.json or {}
        payload, code = generate_command_payload(data)
        return jsonify(payload), code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """处理WebSocket连接"""
    print(f'客户端已连接: {request.sid}')
    emit('connected', {'message': '已连接到服务器'})

@socketio.on('disconnect')
def handle_disconnect():
    """处理WebSocket断开连接"""
    print(f'客户端已断开: {request.sid}')

@socketio.on('join_task')
def handle_join_task(data):
    """加入任务房间，接收特定任务的日志"""
    try:
        # 处理不同的数据格式
        if isinstance(data, str):
            task_id = data
        elif isinstance(data, dict):
            task_id = data.get('task_id')
        else:
            task_id = None
            
        if task_id:
            from flask_socketio import join_room
            join_room(task_id)
            print(f"[SocketIO] 客户端 {request.sid} 加入任务房间: {task_id}")
            emit('joined_task', {'task_id': task_id, 'message': f'已加入任务 {task_id}'})
            
            # 如果日志文件已存在，立即发送已有内容给新加入的客户端
            try:
                room_clients = socketio.server.manager.rooms.get(task_id)
                client_count = len(room_clients) if room_clients else 0
                print(f"[SocketIO] 客户端 {request.sid} 加入任务房间: {task_id} (房间中现有 {client_count} 个客户端)")
            except Exception as e:
                print(f"[SocketIO] 客户端 {request.sid} 加入任务房间: {task_id} (无法获取房间信息: {e})")
            
            emit('joined_task', {'task_id': task_id, 'message': f'已加入任务 {task_id}'})
            
            # 立即发送所有已有日志内容给新加入的客户端
            def send_all_logs_to_client(log_file, source='unknown'):
                """发送日志文件的所有内容给当前客户端"""
                if os.path.exists(log_file):
                    file_size = os.path.getsize(log_file)
                    if file_size > 0:
                        try:
                            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if content.strip():
                                    lines = content.strip().split('\n')
                                    sent_count = 0
                                    for line in lines:
                                        if line.strip():
                                            sent_count += 1
                                            emit('log_message', {
                                                'task_id': task_id,
                                                'message': line.strip(),
                                                'timestamp': datetime.now().isoformat()
                                            })
                                    print(f"[SocketIO] 已向客户端 {request.sid} 发送 {sent_count} 行历史日志 ({source}: {log_file}, 大小: {file_size} 字节)")
                                    return True
                        except Exception as e:
                            print(f"[SocketIO] 读取日志文件失败 ({log_file}): {e}")
                return False
            
            try:
                # 方法1: 优先从 log_monitors 获取正在监控的日志文件（最可靠）
                if task_id in log_monitors and len(log_monitors[task_id]) > 0:
                    for monitor_info in log_monitors[task_id]:
                        log_file = monitor_info.get('log_path')
                        if log_file and send_all_logs_to_client(log_file, 'log_monitors'):
                            return  # 成功发送，不需要继续查找
                
                # 方法2: 从 running_tasks 构建日志路径
                task_info = running_tasks.get(task_id)
                if task_info:
                    config = task_info.get('config', {})
                    injection_method = task_info.get('injection_method') or config.get('injection_method', 'observation_prompt_injection')
                    llm_name = task_info.get('llm_name') or (config.get('llms') or ['llama3:8b'])[0]
                    attack_types = task_info.get('attack_types') or config.get('attack_types', ['context_ignoring'])
                    ts = task_info.get('timestamp', datetime.now().strftime('%Y%m%d_%H%M%S'))
                    
                    if attack_types:
                        res_csv, log_file = build_paths(injection_method, llm_name, attack_types[0], ts)
                        if send_all_logs_to_client(log_file, 'running_tasks'):
                            return  # 成功发送，不需要继续查找
                
                # 方法3: 从数据库获取日志路径
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("""
                    SELECT log_path FROM detection_runs
                    WHERE task_id=? ORDER BY id DESC LIMIT 1
                """, (task_id,))
                row = c.fetchone()
                conn.close()
                
                if row and row[0]:
                    send_all_logs_to_client(row[0], 'database')
                
                # 如果没有找到任何日志文件，发送提示信息
                if task_id in running_tasks and running_tasks[task_id]['status'] in ['running', 'queued']:
                    emit('log_message', {
                        'task_id': task_id,
                        'message': '日志文件尚未创建，请等待...',
                        'timestamp': datetime.now().isoformat()
                    })
                    
            except Exception as e:
                print(f"[SocketIO] 发送历史日志时出错: {e}")
                import traceback
                traceback.print_exc()
                
    except Exception as e:
        print(f"加入任务房间时出错: {e}")
        import traceback
        traceback.print_exc()

@socketio.on('leave_task')
def handle_leave_task(data):
    """离开任务房间"""
    try:
        # 处理不同的数据格式
        if isinstance(data, str):
            task_id = data
        elif isinstance(data, dict):
            task_id = data.get('task_id')
        else:
            task_id = None
            
        if task_id:
            from flask_socketio import leave_room
            leave_room(task_id)
            emit('left_task', {'task_id': task_id, 'message': f'已离开任务 {task_id}'})
    except Exception as e:
        print(f"离开任务房间时出错: {e}")

# 路由
@app.route("/api/detection/logs/<task_id>", methods=["GET"])
def detection_logs(task_id):
    print(f"request_args: {request.args.to_dict()}")
    attack = request.args.get("attack")
    tail_bytes_q = request.args.get("tail_bytes")
    tail_bytes = None
    if tail_bytes_q is not None:
        try:
            tail_bytes = max(0, int(tail_bytes_q))
        except ValueError:
            return jsonify({"error": "tail_bytes 必须为整数"}), 400

    payload, code = read_log_content(task_id, attack=attack, tail_bytes=tail_bytes)
    return jsonify(payload), code

@app.route('/api/detection/logs/download/<task_id>', methods=['GET'])
def download_logs(task_id):
    db_task = get_task_from_db(task_id)
    if not db_task:
        return jsonify({'error': '任务不存在'}), 404

    # get_log_file_path 约定接收 task 字典（需含 injection_method / llm_name / timestamp 等）
    log_file = get_log_file_path(db_task)
    if not log_file:
        return jsonify({'error': '未记录日志路径'}), 404

    return download_log_file(log_file)

@app.route('/api/detection/logs/clear', methods=['POST'])
def clear_logs():
    deleted = clear_all_logs()
    return jsonify({'message': f'清理完成，删除 {deleted} 个日志文件'})

@app.route('/api/detection/logs/list', methods=['GET'])
def list_logs():
    days = request.args.get('days', type=int)
    logs = list_log_files(days=days)
    return jsonify({'logs': logs})


@app.route('/api/detection/extract-results/<task_id>', methods=['POST'])
def manual_extract_results(task_id):
    """手动提取任务结果（不再互调路由）"""
    try:
        task = running_tasks.get(task_id)
        if not task:
            tasks_data = _collect_all_tasks_data()
            task = next((t for t in tasks_data if t.get('id') == task_id), None)

        if not task:
            return jsonify({'error': '任务不存在'}), 404

        extract_task_results(task_id, task)
        cached_results = task_results_cache.get(task_id, {})
        return jsonify({
            'task_id': task_id,
            'status': 'success',
            'message': '结果提取完成',
            'results': cached_results
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/detection/logs-stream/<task_id>', methods=['GET'])
def stream_task_logs(task_id):
    return stream_task_logs_response(task_id)

@app.route('/api/detection/csv-data/<task_id>', methods=['GET'])
def get_csv_data(task_id):
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    payload, code = get_csv_page(task_id, page=page, per_page=per_page)
    return jsonify(payload), code

@app.route('/api/detection/csv-download/<task_id>', methods=['GET'])
def download_csv(task_id):
    return download_csv_response(task_id)

@app.route('/api/config/template', methods=['GET'])
def get_config_template():
    return jsonify(load_default_settings())

@app.route('/api/config/validate', methods=['POST'])
def validate_config():
    payload, code = validate_settings_payload(request.json)
    return jsonify(payload), code

@app.route('/api/detection/start', methods=['POST'])
def start_detection():
    """启动检测任务（带 DB 记录：参数 & 每个攻击的结果/日志路径）"""
    try:
        # 1) 获取用户配置并合并默认项
        user_config = request.json or {}
        print(f"🔍 收到检测启动请求: {user_config}")

        # merge_with_defaults 来自 app.services.settings
        config_data = merge_with_defaults(user_config)

        # 2) 解析关键参数
        injection_method = config_data.get('injection_method') or 'observation_prompt_injection'
        llm_name = (config_data.get('llms') or ['llama3:8b'])[0]
        attack_types = config_data.get('attack_types') or ['context_ignoring']
        # 与产物文件名对齐的时间戳
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')

        # 3) 生成 task_id + 初始化内存态
        task_id = str(uuid.uuid4())
        running_tasks[task_id] = {
            'id': task_id,
            'status': 'queued',
            'config': config_data,
            'created_time': datetime.now().isoformat(),
            'progress': 0,
            'timestamp': ts,
            'injection_method': injection_method,
            'llm_name': llm_name,
            'attack_types': attack_types
        }

        # 4) 保存 task 到 DB，并立刻标记为 running
        save_task_to_db(running_tasks[task_id])
        now = datetime.now().isoformat()
        running_tasks[task_id]['status'] = 'running'
        running_tasks[task_id]['start_time'] = now
        mark_task_status(task_id, 'running', start=now, progress=0)

        # 5) 为每个 attack 预写 detection_runs（含结果/日志目标路径）
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        for atk in attack_types:
            csv_path, log_path = build_paths(injection_method, llm_name, atk, ts)
            os.makedirs(os.path.dirname(csv_path), exist_ok=True)
            c.execute(
                """
                INSERT INTO detection_runs (
                    task_id, attack_type, injection_method, llm_name, timestamp,
                    result_path, log_path, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'queued')
                """,
                (task_id, atk, injection_method, llm_name, ts, csv_path, log_path)
            )
        conn.commit()
        conn.close()

        # 6) 启动检测线程（把 ts 传下去，确保与落盘路径一致）
        thread = threading.Thread(target=run_detection_task, args=(task_id, config_data, ts), daemon=True)
        thread.start()

        return jsonify({
            'task_id': task_id,
            'status': 'queued',
            'timestamp': ts,
            'message': '检测任务已启动'
        })
    except Exception as e:
        current_app.logger.exception("启动检测失败")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # 获取本机实际IP
    local_ip = get_local_ip()
    
    print("🚀 启动Web应用...")
    print("绑定地址: 0.0.0.0:8888 (所有网络接口)")
    print(f"本机访问: http://localhost:8888")
    print(f"本机IP访问: http://{local_ip}:8888")
    print("映射访问: http://10.161.76.22:8888")
    print()
    print("启动智能体安全检测工具API服务器...")
    print("💡 提示: 学校内网访问地址")
    print(f"💡 注意: 本机IP是 {local_ip}，但通过 10.161.76.22 映射访问")
    socketio.run(app, host='0.0.0.0', port=8888, debug=True, allow_unsafe_werkzeug=True)
