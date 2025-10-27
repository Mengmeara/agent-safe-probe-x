#!/usr/bin/env python3
"""
智能体安全检测工具 - Flask后端API服务器
"""

import os
import sys
import json
import yaml
import subprocess
import threading
import time
import re
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import pandas as pd
import uuid

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# 配置
UPLOAD_FOLDER = 'uploads'
RESULTS_FOLDER = 'results'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['RESULTS_FOLDER'] = RESULTS_FOLDER

# 确保目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# 存储运行中的任务
running_tasks = {}

# 存储任务结果缓存
task_results_cache = {}

# 存储日志监控线程
log_monitors = {}

def extract_task_results(task_id, task):
    """提取任务完成时的CSV结果"""
    try:
        # 从任务配置中获取结果文件路径
        config = task.get('config', {})
        res_file = config.get('res_file')
        
        # 如果没有res_file，尝试从自定义命令中提取
        if not res_file:
            custom_command = config.get('custom_command', '')
            if custom_command and '--res_file' in custom_command:
                # 从自定义命令中提取res_file路径
                import re
                # 查找所有--res_file参数，取第一个
                matches = re.findall(r'--res_file\s+([^\s>]+)', custom_command)
                if matches:
                    res_file = matches[0]
                    print(f"从自定义命令中提取结果文件路径: {res_file}")
        
        # 如果还是没有res_file，尝试从日志文件路径推断
        if not res_file:
            log_file = config.get('log_file')
            if log_file and log_file.endswith('.log'):
                res_file = log_file.replace('.log', '.csv')
                print(f"从日志文件路径推断结果文件路径: {res_file}")
        
        if not res_file:
            print(f"任务 {task_id} 没有结果文件路径")
            return
        
        # 检查文件是否存在
        if not os.path.exists(res_file):
            print(f"结果文件不存在: {res_file}")
            return
        
        # 读取CSV文件
        import pandas as pd
        df = pd.read_csv(res_file)
        print(f"读取CSV文件成功: {res_file}, 数据形状: {df.shape}")
        print(f"CSV列名: {list(df.columns)}")
        print(f"前3行数据:")
        print(df.head(3))
        
        if df.empty:
            print(f"结果文件为空: {res_file}")
            return
        
        # 标准化字段名 - 映射到前端期望的字段名
        field_mapping = {
            'Agent Name': 'agent_name',
            'Attack Tool': 'attack_tool',  # 前端期望的是attack_tool，不是attacker_tool
            'Attack Successful': 'attack_success',
            'Original Task Successful': 'original_success',
            'Refuse Result': 'refuse_result',
            'Memory Found': 'memory_found',
            'Aggressive': 'aggressive',
            'messages': 'response'  # 前端期望的是response字段
        }
        
        # 重命名列
        for old_name, new_name in field_mapping.items():
            if old_name in df.columns:
                df = df.rename(columns={old_name: new_name})
        
        # 转换布尔值
        if 'attack_success' in df.columns:
            df['attack_success'] = df['attack_success'].astype(bool)
        if 'original_success' in df.columns:
            df['original_success'] = df['original_success'].astype(bool)
        
        # 添加前端期望的task字段 - 从agent_name中提取任务信息
        if 'agent_name' in df.columns:
            df['task'] = df['agent_name'].apply(lambda x: x.split('/')[-1] if '/' in str(x) else str(x))
        
        # 计算统计信息
        summary = {
            'total_tests': len(df),
            'successful_attacks': len(df[df.get('attack_success', False) == True]) if 'attack_success' in df.columns else 0,
            'failed_attacks': len(df[df.get('attack_success', False) == False]) if 'attack_success' in df.columns else 0,
            'original_success_rate': len(df[df.get('original_success', False) == True]) if 'original_success' in df.columns else 0,
            'refuse_rate': len(df[df.get('refuse_result', False) == True]) if 'refuse_result' in df.columns else 0
        }
        
        # 将结果存储到任务中
        data_records = df.to_dict('records')
        print(f"转换数据记录: {len(data_records)} 条")
        print(f"第一条记录: {data_records[0] if data_records else 'None'}")
        
        results = {
            'data': data_records,
            'summary': summary,
            'res_file': res_file
        }
        
        # 更新任务对象（如果存在）
        if task:
            task['results'] = results
        
        # 将结果存储到全局任务结果中
        task_results_cache[task_id] = results
        
        print(f"任务 {task_id} 结果提取完成: {summary}")
        
    except Exception as e:
        print(f"提取任务 {task_id} 结果失败: {str(e)}")
        task['results'] = {'error': str(e)}

def generate_log_path(config_data):
    """生成带时间戳的日志文件路径"""
    from datetime import datetime
    
    # 获取配置信息
    llm_name = config_data.get('llms', ['llama3:8b'])[0]
    attack_types = config_data.get('attack_types', ['context_ignoring'])
    
    # 如果有多个攻击类型，使用第一个作为主要日志文件名
    # 实际的多个攻击类型会在命令中分别处理
    attack_type = attack_types[0] if attack_types else 'context_ignoring'
    
    # 生成时间戳
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # 构建日志路径: logs/observation_prompt_injection/ollama:llama3:8b/no_memory/single/context_ignoring-single-{timestamp}.log
    log_filename = f"{attack_type}-single-{timestamp}.log"
    log_path = f"logs/observation_prompt_injection/{llm_name.replace('/', ':')}/no_memory/single/{log_filename}"
    
    # 转换为绝对路径
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    absolute_log_path = os.path.join(project_root, log_path)
    
    # 确保目录存在
    os.makedirs(os.path.dirname(absolute_log_path), exist_ok=True)
    
    return absolute_log_path

def parse_log_path_from_command(cmd_str):
    """从命令字符串中解析日志文件路径"""
    # 查找重定向到日志文件的模式: > path/to/logfile.log 2>&1
    log_pattern = r'>\s*([^\s]+\.log)\s+2>&1'
    match = re.search(log_pattern, cmd_str)
    if match:
        log_path = match.group(1)
        # 如果是相对路径，转换为绝对路径
        if not os.path.isabs(log_path):
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            log_path = os.path.join(project_root, log_path)
        return log_path
    
    # 如果没有找到.log文件，尝试查找.csv文件路径
    # 从--res_file参数中提取CSV文件路径
    csv_pattern = r'--res_file\s+([^\s]+\.csv)'
    csv_match = re.search(csv_pattern, cmd_str)
    if csv_match:
        csv_path = csv_match.group(1)
        # 如果是相对路径，转换为绝对路径
        if not os.path.isabs(csv_path):
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            csv_path = os.path.join(project_root, csv_path)
        
        # 将.csv路径转换为.log路径
        log_path = csv_path.replace('.csv', '.log')
        return log_path
    
    return None

def monitor_process_output(task_id, process, log_path):
    """监控进程输出，同时写入日志文件和实时推送"""
    try:
        # 确保日志文件目录存在
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        
        # 打开日志文件用于写入
        with open(log_path, 'w', encoding='utf-8') as log_file:
            # 实时读取进程输出
            for line in iter(process.stdout.readline, ''):
                if line:
                    # 写入日志文件
                    log_file.write(line)
                    log_file.flush()
                    
                    # 实时推送到前端
                    socketio.emit('log_message', {
                        'task_id': task_id,
                        'message': line.rstrip(),
                        'timestamp': datetime.now().isoformat()
                    }, room=task_id)
                    
                    # 检查任务是否还在运行
                    if task_id not in running_tasks or running_tasks[task_id]['status'] not in ['running', 'queued']:
                        break
        
        # 等待进程结束
        process.wait()
        
        # 更新任务状态
        if task_id in running_tasks:
            if process.returncode == 0:
                running_tasks[task_id]['status'] = 'completed'
                running_tasks[task_id]['current_step'] = '任务完成'
            else:
                running_tasks[task_id]['status'] = 'failed'
                running_tasks[task_id]['current_step'] = f'任务失败 (退出码: {process.returncode})'
            
            # 发送最终状态
            socketio.emit('task_status', {
                'task_id': task_id,
                'status': running_tasks[task_id]['status'],
                'current_step': running_tasks[task_id]['current_step'],
                'timestamp': datetime.now().isoformat()
            }, room=task_id)
            
    except Exception as e:
        print(f"监控进程输出时出错: {e}")
        socketio.emit('log_message', {
            'task_id': task_id,
            'message': f'监控进程输出时出错: {e}',
            'timestamp': datetime.now().isoformat()
        }, room=task_id)

def monitor_log_file(task_id, log_path):
    """监控日志文件的变化并实时推送"""
    if not os.path.exists(log_path):
        # 如果日志文件不存在，等待它被创建
        socketio.emit('log_message', {
            'task_id': task_id,
            'message': f'等待日志文件创建: {log_path}',
            'timestamp': datetime.now().isoformat()
        }, room=task_id)
        
        # 等待文件创建
        max_wait = 30  # 最多等待30秒
        wait_time = 0
        while not os.path.exists(log_path) and wait_time < max_wait:
            time.sleep(1)
            wait_time += 1
        
        if not os.path.exists(log_path):
            socketio.emit('log_message', {
                'task_id': task_id,
                'message': f'日志文件未创建: {log_path}',
                'timestamp': datetime.now().isoformat()
            }, room=task_id)
            return
    
    # 记录文件大小，用于检测新内容
    last_size = 0
    if os.path.exists(log_path):
        last_size = os.path.getsize(log_path)
    
    socketio.emit('log_message', {
        'task_id': task_id,
        'message': f'开始监控日志文件: {log_path}',
        'timestamp': datetime.now().isoformat()
    }, room=task_id)
    
    while task_id in running_tasks and running_tasks[task_id]['status'] in ['running', 'queued']:
        try:
            if os.path.exists(log_path):
                current_size = os.path.getsize(log_path)
                
                # 如果文件有新内容
                if current_size > last_size:
                    # 读取新增的内容
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(last_size)
                        new_content = f.read()
                        
                    if new_content.strip():
                        # 按行分割并发送每一行
                        lines = new_content.split('\n')
                        for line in lines:
                            if line.strip():
                                socketio.emit('log_message', {
                                    'task_id': task_id,
                                    'message': line.strip(),
                                    'timestamp': datetime.now().isoformat()
                                }, room=task_id)
                    
                    last_size = current_size
            else:
                # 文件被删除，等待重新创建
                socketio.emit('log_message', {
                    'task_id': task_id,
                    'message': '日志文件被删除，等待重新创建...',
                    'timestamp': datetime.now().isoformat()
                }, room=task_id)
                time.sleep(1)
                continue
                
        except Exception as e:
            socketio.emit('log_message', {
                'task_id': task_id,
                'message': f'日志监控错误: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }, room=task_id)
        
        time.sleep(0.5)  # 每0.5秒检查一次
    
    socketio.emit('log_message', {
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
        
        # 检查进程是否还在运行
        if 'process_id' in task:
            try:
                # 使用psutil检查进程状态
                import psutil
                process = psutil.Process(task['process_id'])
                if not process.is_running():
                    # 进程已结束
                    if task['status'] == 'running':
                        task['status'] = 'completed'
                        task['progress'] = 100
                        task['current_step'] = '检测完成'
                        task['end_time'] = datetime.now().isoformat()
                        
                        # 任务完成时，自动提取CSV结果
                        try:
                            extract_task_results(task_id, task)
                            print(f"任务 {task_id} 自动结果提取完成")
                        except Exception as e:
                            print(f"任务 {task_id} 自动结果提取失败: {e}")
            except ImportError:
                # psutil模块未安装，跳过进程检查
                pass
            except Exception as e:
                # 处理psutil相关异常（NoSuchProcess, AccessDenied等）
                # 进程不存在或无权限访问
                if task['status'] == 'running':
                    task['status'] = 'completed'
                    task['progress'] = 100
                    task['current_step'] = '检测完成'
                    task['end_time'] = datetime.now().isoformat()
                    
                    # 任务完成时，自动提取CSV结果
                    try:
                        extract_task_results(task_id, task)
                        print(f"任务 {task_id} 自动结果提取完成")
                    except Exception as e2:
                        print(f"任务 {task_id} 自动结果提取失败: {e2}")
    except Exception as e:
        print(f"更新进度时出错: {e}")
        # 即使更新进度失败，也不影响任务
        pass

def monitor_task_progress(task_id, process):
    """监控任务进度"""
    try:
        # 获取任务信息
        task = running_tasks.get(task_id)
        if not task:
            return
            
        # 尝试使用psutil监控进程
        try:
            import psutil
            proc = psutil.Process(process.pid)
        except ImportError:
            # psutil模块不存在，使用简单的方法
            print(f"psutil模块不存在，跳过进程监控")
            return
        except Exception as e:
            print(f"进程监控出错: {e}")
            return
            
        # 监控进程输出 - 只有当process.stdout存在时才读取
        while proc.is_running():
            # 尝试读取输出（只有在stdout存在且有内容时才读取）
            if hasattr(process, 'stdout') and process.stdout is not None:
                try:
                    output = process.stdout.readline()
                    if output:
                        output = output.strip()
                        if output:
                            # 解析进度信息
                            if 'Attack started at:' in output:
                                running_tasks[task_id]['current_step'] = '开始攻击测试...'
                                running_tasks[task_id]['progress'] = 20
                            elif '任务完成:' in output or 'Task completed:' in output:
                                running_tasks[task_id]['current_step'] = '处理任务结果...'
                                running_tasks[task_id]['progress'] = min(90, running_tasks[task_id].get('progress', 0) + 10)
                            elif 'Attack ended at:' in output:
                                running_tasks[task_id]['current_step'] = '完成检测...'
                                running_tasks[task_id]['progress'] = 95
                            
                            # 保存日志
                            if 'logs' not in running_tasks[task_id]:
                                running_tasks[task_id]['logs'] = []
                            running_tasks[task_id]['logs'].append({
                                'timestamp': datetime.now().isoformat(),
                                'message': output
                            })
                            
                            # 只保留最近的50条日志
                            if len(running_tasks[task_id]['logs']) > 50:
                                running_tasks[task_id]['logs'] = running_tasks[task_id]['logs'][-50:]
                except Exception as e:
                    print(f"读取进程输出时出错: {e}")
                    # 如果读取输出失败，继续监控进程状态
                    pass
            else:
                # 如果没有stdout，只监控进程是否在运行
                pass
            
            time.sleep(0.1)  # 短暂休眠避免CPU占用过高
        
        # 进程结束，更新最终状态
        try:
            if process.returncode == 0:
                running_tasks[task_id]['status'] = 'completed'
                running_tasks[task_id]['progress'] = 100
                running_tasks[task_id]['current_step'] = '检测完成'
                
                # 任务完成时，自动提取CSV结果
                extract_task_results(task_id, running_tasks[task_id])
            else:
                running_tasks[task_id]['status'] = 'failed'
                running_tasks[task_id]['error'] = f'进程退出码: {process.returncode}'
        except Exception as e:
            print(f"获取进程返回码时出错: {e}")
            running_tasks[task_id]['status'] = 'completed'
            running_tasks[task_id]['progress'] = 100
            running_tasks[task_id]['current_step'] = '检测完成'
        
        running_tasks[task_id]['end_time'] = datetime.now().isoformat()
        
    except Exception as e:
        print(f"监控任务进度时出错: {e}")
        if task_id in running_tasks:
            running_tasks[task_id]['status'] = 'failed'
            running_tasks[task_id]['error'] = str(e)
            running_tasks[task_id]['end_time'] = datetime.now().isoformat()

def load_config_template():
    """加载默认配置模板"""
    return {
        "injection_method": "observation_prompt_injection",
        "attack_tool": ["all"],
        "llms": ["ollama/llama3:8b"],
        "attack_types": ["clean_opi"],
        "task_num": 1,
        "defense_type": None,
        "write_db": False,
        "read_db": False
    }

def run_detection_task(task_id, config_data):
    """运行检测任务的线程函数"""
    try:
        print(f"🚀 开始执行检测任务 {task_id}")
        print(f"🔍 任务配置: {config_data}")
        
        # 更新任务状态
        running_tasks[task_id]['status'] = 'running'
        running_tasks[task_id]['start_time'] = datetime.now().isoformat()
        running_tasks[task_id]['progress'] = 0
        running_tasks[task_id]['current_step'] = '初始化中...'
        
        # 检查是否有自定义命令
        custom_command = config_data.get('custom_command')
        print(f"🔍 自定义命令: {custom_command}")
        log_path = None
        
        if custom_command:
            # 使用自定义命令
            running_tasks[task_id]['current_step'] = '执行自定义命令...'
            
            # 从命令中解析日志路径
            log_path = parse_log_path_from_command(custom_command)
            
            # 如果没有找到日志路径，生成一个新的
            if not log_path:
                log_path = generate_log_path(config_data)
                # 修改命令，使用新的日志路径
                import re
                log_pattern = r'>\s*[^\s]+\.log\s+2>&1'
                new_redirect = f'> {log_path} 2>&1'
                modified_command = re.sub(log_pattern, new_redirect, custom_command)
            else:
                # 如果找到了日志路径，确保命令中有重定向到该路径
                if ' > ' not in custom_command:
                    modified_command = custom_command + f' > {log_path} 2>&1'
                else:
                    modified_command = custom_command
            
            print(f"🔍 日志路径: {log_path}")
            print(f"🔍 修改后的命令: {modified_command}")
            
            # 执行修改后的命令
            # 直接使用conda环境的Python解释器
            python_path = "/home/flowteam/miniconda3/envs/ASB/bin/python"
            # 替换命令中的python为完整路径
            modified_command_with_python = modified_command.replace("python main_attacker.py", f"{python_path} main_attacker.py")
            print(f"🔍 修改后的命令: {modified_command_with_python}")
            
            # 使用subprocess执行命令，这样可以获取进程ID并正确监控
            print(f"🔍 最终执行命令: {modified_command_with_python}")
            
            # 分离命令和重定向部分
            # 命令格式: cd /path && conda activate ASB && python main_attacker.py ... > logfile.log 2>&1
            # 我们需要去掉重定向部分，因为subprocess会处理输出
            command_without_redirect = modified_command_with_python.split(' > ')[0]
            print(f"🔍 去掉重定向的命令: {command_without_redirect}")
            
            # 简化命令，直接使用conda环境的Python解释器
            # 从命令中提取main_attacker.py的参数
            import re
            args_match = re.search(r'main_attacker\.py\s+(.+?)(?:\s+>|$)', command_without_redirect)
            if args_match:
                args = args_match.group(1).strip()
                simplified_command = f"{python_path} main_attacker.py {args}"
                print(f"🔍 简化后的命令: {simplified_command}")
            else:
                simplified_command = command_without_redirect
                print(f"🔍 使用原命令: {simplified_command}")
            
            # 使用subprocess.Popen执行命令
            process = subprocess.Popen(
                simplified_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # 将stderr重定向到stdout
                text=True,
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                bufsize=1,
                universal_newlines=True
            )
            
            # 保存进程信息
            running_tasks[task_id]['process_id'] = process.pid
            running_tasks[task_id]['log_path'] = log_path
            
            # 将日志文件路径存储到任务配置中
            running_tasks[task_id]['config']['log_file'] = log_path
            
            # 启动进程输出监控线程
            if log_path:
                log_monitor_thread = threading.Thread(
                    target=monitor_process_output,
                    args=(task_id, process, log_path)
                )
                log_monitor_thread.daemon = True
                log_monitor_thread.start()
                log_monitors[task_id] = log_monitor_thread
            
            # 启动进程监控线程
            monitor_thread = threading.Thread(
                target=monitor_task_progress,
                args=(task_id, process)
            )
            monitor_thread.daemon = True
            monitor_thread.start()
            
        else:
            # 使用默认的配置文件方式
            # 创建临时配置文件
            config_file = os.path.join(UPLOAD_FOLDER, f"{task_id}_config.yml")
            with open(config_file, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False)
            
            # 构建命令
            cmd = [
                'python', 'scripts/agent_attack_clean_opi.py',
                '--cfg_path', os.path.abspath(config_file)
            ]
            
            # 运行检测
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                bufsize=1,
                universal_newlines=True
            )
            
            # 保存进程信息
            running_tasks[task_id]['process_id'] = process.pid
            
            # 为非自定义命令生成日志文件路径
            log_path = generate_log_path(config_data)
            running_tasks[task_id]['log_path'] = log_path
            running_tasks[task_id]['config']['log_file'] = log_path
            
            # 启动监控线程
            monitor_thread = threading.Thread(
                target=monitor_task_progress,
                args=(task_id, process)
            )
            monitor_thread.daemon = True
            monitor_thread.start()
            
    except Exception as e:
        running_tasks[task_id]['status'] = 'failed'
        running_tasks[task_id]['result'] = 'error'
        running_tasks[task_id]['error'] = str(e)
        running_tasks[task_id]['current_step'] = f'错误: {str(e)}'
    finally:
        running_tasks[task_id]['end_time'] = datetime.now().isoformat()
        
        # 清理临时文件
        try:
            if 'config_file' in locals():
                os.remove(config_file)
        except:
            pass

@app.route('/')
def index():
    """提供前端页面"""
    return send_from_directory('static', 'index.html')

@app.route('/simple')
def simple():
    """简单测试页面"""
    return send_from_directory('.', 'simple_test.html')

@app.route('/test')
def test():
    """测试页面"""
    return send_from_directory('static', 'test_page.html')

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

@app.route('/api/config/template', methods=['GET'])
def get_config_template():
    """获取配置模板"""
    return jsonify(load_config_template())

@app.route('/api/config/validate', methods=['POST'])
def validate_config():
    """验证配置文件"""
    try:
        config_data = request.json
        required_fields = ['injection_method', 'attack_tool', 'llms', 'attack_types']
        
        for field in required_fields:
            if field not in config_data:
                return jsonify({'valid': False, 'error': f'缺少必需字段: {field}'}), 400
        
        return jsonify({'valid': True})
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 400

@app.route('/api/detection/start', methods=['POST'])
def start_detection():
    """启动检测任务"""
    try:
        user_config = request.json
        print(f"🔍 收到检测启动请求: {user_config}")
        
        # 获取默认配置并合并用户配置
        default_config = load_config_template()
        config_data = {**default_config, **user_config}
        print(f"🔍 合并后的配置: {config_data}")
        
        # 确保attack_tool使用默认值（脚本需要特定的值）
        config_data['attack_tool'] = default_config['attack_tool']
        
        # 生成任务ID
        task_id = str(uuid.uuid4())
        
        # 初始化任务状态
        running_tasks[task_id] = {
            'id': task_id,
            'status': 'queued',
            'config': config_data,
            'created_time': datetime.now().isoformat(),
            'progress': 0
        }
        
        # 启动检测线程
        thread = threading.Thread(target=run_detection_task, args=(task_id, config_data))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'task_id': task_id,
            'status': 'queued',
            'message': '检测任务已启动'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/detection/status/<task_id>', methods=['GET'])
def get_detection_status(task_id):
    """获取检测任务状态"""
    if task_id in running_tasks:
        task = running_tasks[task_id]
        return jsonify({
            'task_id': task_id,
            'status': task['status'],
            'progress': task.get('progress', 0),
            'current_step': task.get('current_step', ''),
            'created_time': task['created_time'],
            'start_time': task.get('start_time'),
            'end_time': task.get('end_time'),
            'config': task['config']
        })
    
    # 如果任务不在running_tasks中，尝试从结果文件推断任务状态
    try:
        # 查找结果文件
        result_files = []
        logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
        
        if os.path.exists(logs_dir):
            for root, dirs, files in os.walk(logs_dir):
                for file in files:
                    if file.endswith('.csv') and ('clean_opi' in file or 'context_ignoring' in file):
                        result_files.append(os.path.join(root, file))
        
        if result_files:
            # 选择最新的结果文件
            latest_file = max(result_files, key=os.path.getmtime)
            
            # 从文件路径推断任务信息
            file_stats = os.stat(latest_file)
            
            return jsonify({
                'task_id': task_id,
                'status': 'completed',
                'progress': 100,
                'current_step': '任务完成',
                'created_time': datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
                'start_time': datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
                'end_time': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                'config': {
                    'res_file': latest_file,
                    'log_file': latest_file.replace('.csv', '.log')
                },
                'available_files': result_files  # 添加所有可用文件列表
            })
        else:
            return jsonify({'error': '任务不存在'}), 404
            
    except Exception as e:
        return jsonify({'error': f'获取任务状态失败: {str(e)}'}), 500

@app.route('/api/detection/result/<task_id>', methods=['GET'])
def get_detection_result(task_id):
    """获取检测结果或任务状态"""
    # 如果任务在running_tasks中，返回当前状态
    if task_id in running_tasks:
        task = running_tasks[task_id]
        
        # 更新任务状态和进度
        update_task_progress(task_id)
        
        # 返回任务状态信息
        result_data = {
            'task_id': task_id,
            'status': task['status'],
            'progress': task.get('progress', 0),
            'current_step': task.get('current_step', ''),
            'created_time': task['created_time'],
            'start_time': task.get('start_time'),
            'end_time': task.get('end_time'),
            'config': task['config'],
            'logs': task.get('logs', []),
            'error': task.get('error')
        }
        
        # 如果任务已完成且有结果，返回结果数据
        if task['status'] == 'completed' and 'results' in task:
            result_data.update({
                'result': 'success',
                'data': task['results'].get('data', []),
                'summary': task['results'].get('summary', {}),
                'res_file': task['results'].get('res_file', '')
            })
        
        return jsonify(result_data)
    
    # 如果任务不在running_tasks中，尝试从历史任务中查找
    try:
        # 获取所有历史任务
        tasks_response = get_all_tasks()
        tasks_data = tasks_response.get_json()
        
        # 查找匹配的任务
        target_task = None
        for task in tasks_data:
            if task.get('id') == task_id:
                target_task = task
                break
        
        if not target_task:
            # 如果任务不在历史记录中，尝试从文件系统中查找结果文件
            result_response = search_result_files(task_id)
            if isinstance(result_response, tuple):
                # 如果是错误响应，直接返回
                return result_response
            else:
                # 如果是成功响应，返回数据
                return result_response
        
        # 如果任务已完成，尝试读取结果文件
        if target_task.get('status') == 'completed':
            results = target_task.get('results', {})
            res_file = results.get('res_file', '')
            
            # 如果没有从results中获取到res_file，尝试从配置中获取
            if not res_file:
                config = target_task.get('config', {})
                res_file = config.get('res_file')
                
                # 如果配置中也没有res_file，尝试从自定义命令中提取
                if not res_file:
                    custom_command = config.get('custom_command', '')
                    if custom_command and '--res_file' in custom_command:
                        import re
                        matches = re.findall(r'--res_file\s+([^\s>]+)', custom_command)
                        if matches:
                            res_file = matches[0]
                
                # 如果还是没有res_file，尝试从日志文件路径推断
                if not res_file:
                    log_file = config.get('log_file')
                    if log_file and log_file.endswith('.log'):
                        res_file = log_file.replace('.log', '.csv')
            
            if res_file and os.path.exists(res_file):
                # 读取CSV文件
                df = pd.read_csv(res_file)
                
                # 标准化字段名，将CSV列名映射为前端期望的字段名
                df_normalized = df.copy()
                field_mapping = {
                    'Agent Name': 'agent_name',
                    'Attack Tool': 'attack_tool',
                    'Attack Successful': 'attack_success',
                    'Original Task Successful': 'original_success',
                    'Refuse Result': 'refuse_result',
                    'Memory Found': 'memory_found',
                    'Aggressive': 'aggressive',
                    'messages': 'response'
                }
                
                # 重命名列
                for old_name, new_name in field_mapping.items():
                    if old_name in df_normalized.columns:
                        df_normalized = df_normalized.rename(columns={old_name: new_name})
                
                # 转换布尔值
                if 'attack_success' in df_normalized.columns:
                    df_normalized['attack_success'] = df_normalized['attack_success'].astype(bool)
                if 'original_success' in df_normalized.columns:
                    df_normalized['original_success'] = df_normalized['original_success'].astype(bool)
                
                # 添加前端期望的task字段
                if 'agent_name' in df_normalized.columns:
                    df_normalized['task'] = df_normalized['agent_name'].apply(lambda x: x.split('/')[-1] if '/' in str(x) else str(x))
                
                return jsonify({
                    'task_id': task_id,
                    'status': 'completed',
                    'result': 'success',
                    'data': df_normalized.to_dict('records'),
                    'summary': {
                        'total_tests': len(df_normalized),
                        'successful_attacks': len(df_normalized[df_normalized.get('attack_success', False) == True]) if 'attack_success' in df_normalized.columns else 0,
                        'failed_attacks': len(df_normalized[df_normalized.get('attack_success', False) == False]) if 'attack_success' in df_normalized.columns else 0,
                        'success_rate': 0
                    },
                    'res_file': res_file,
                    'config': target_task.get('config', {}),
                    'created_time': target_task.get('created_time'),
                    'start_time': target_task.get('start_time'),
                    'end_time': target_task.get('end_time')
                })
            else:
                return jsonify({'error': '结果文件不存在'}), 404
        else:
            return jsonify({
                'task_id': task_id,
                'status': target_task.get('status'),
                'error': '任务未完成'
            })
    
    except Exception as e:
        return jsonify({'error': f'获取任务信息失败: {str(e)}'}), 500

@app.route('/api/detection/cancel/<task_id>', methods=['POST'])
def cancel_detection(task_id):
    """取消检测任务"""
    if task_id not in running_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
    task = running_tasks[task_id]
    
    if task['status'] in ['completed', 'failed']:
        return jsonify({'error': '任务已完成，无法取消'}), 400
    
    # 尝试终止进程
    if 'process_id' in task:
        try:
            os.kill(task['process_id'], 9)
        except:
            pass
    
    task['status'] = 'cancelled'
    task['end_time'] = datetime.now().isoformat()
    
    return jsonify({'message': '任务已取消'})

def search_result_files(task_id):
    """从文件系统中搜索结果文件"""
    try:
        import glob
        from datetime import datetime
        
        # 优先搜索指定目录: logs/observation_prompt_injection/ollama:llama3:8b/no_memory/single/
        target_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                 'logs', 'observation_prompt_injection', 'ollama:llama3:8b', 'no_memory', 'single')
        
        # 如果指定目录存在，优先搜索该目录
        if os.path.exists(target_dir):
            csv_files = glob.glob(os.path.join(target_dir, '*.csv'))
            print(f"🔍 在指定目录找到 {len(csv_files)} 个CSV文件: {target_dir}")
        else:
            # 回退到搜索整个logs目录
            logs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
            csv_files = glob.glob(os.path.join(logs_dir, '**', '*.csv'), recursive=True)
            print(f"🔍 在logs目录找到 {len(csv_files)} 个CSV文件")
        
        # 查找可能的结果文件（基于时间戳或文件名模式）
        for csv_file in csv_files:
            filename = os.path.basename(csv_file)
            print(f"📄 检查文件: {filename}")
            
            # 如果文件名包含任务ID，直接使用
            if task_id in filename:
                print(f"✅ 找到匹配文件: {filename}")
                return read_result_file(task_id, csv_file)
            
            # 检查文件修改时间是否接近任务创建时间
            try:
                file_mtime = os.path.getmtime(csv_file)
                file_time = datetime.fromtimestamp(file_mtime)
                
                # 如果文件是在最近7天内创建的，可能是我们的结果文件
                now = datetime.now()
                if (now - file_time).total_seconds() < 7 * 24 * 3600:  # 7天内
                    # 读取文件并检查内容是否合理
                    try:
                        df = pd.read_csv(csv_file)
                        if not df.empty and 'Agent Name' in df.columns:
                            print(f"✅ 找到有效文件: {filename} (包含 {len(df)} 条记录)")
                            return read_result_file(task_id, csv_file)
                    except Exception as e:
                        print(f"❌ 读取文件失败: {filename}, 错误: {e}")
                        continue
            except Exception as e:
                print(f"❌ 检查文件时间失败: {filename}, 错误: {e}")
                continue
        
        print(f"❌ 未找到匹配的结果文件，任务ID: {task_id}")
        return jsonify({'error': '未找到结果文件'}), 404
        
    except Exception as e:
        return jsonify({'error': f'搜索结果文件失败: {str(e)}'}), 500

def read_result_file(task_id, res_file):
    """读取结果文件并返回标准格式的数据"""
    try:
        # 读取CSV文件
        df = pd.read_csv(res_file)
        
        if df.empty:
            return jsonify({'error': '结果文件为空'}), 404
        
        # 标准化字段名，将CSV列名映射为前端期望的字段名
        df_normalized = df.copy()
        field_mapping = {
            'Agent Name': 'agent_name',
            'Attack Tool': 'attack_tool',
            'Attack Successful': 'attack_success',
            'Original Task Successful': 'original_success',
            'Refuse Result': 'refuse_result',
            'Memory Found': 'memory_found',
            'Aggressive': 'aggressive',
            'messages': 'response'
        }
        
        # 重命名列
        for old_name, new_name in field_mapping.items():
            if old_name in df_normalized.columns:
                df_normalized = df_normalized.rename(columns={old_name: new_name})
        
        # 转换布尔值
        if 'attack_success' in df_normalized.columns:
            df_normalized['attack_success'] = df_normalized['attack_success'].astype(bool)
        if 'original_success' in df_normalized.columns:
            df_normalized['original_success'] = df_normalized['original_success'].astype(bool)
        
        # 添加前端期望的task字段
        if 'agent_name' in df_normalized.columns:
            df_normalized['task'] = df_normalized['agent_name'].apply(lambda x: x.split('/')[-1] if '/' in str(x) else str(x))
        
        # 计算成功率
        success_rate = 0
        if 'attack_success' in df_normalized.columns:
            successful_attacks = len(df_normalized[df_normalized['attack_success'] == True])
            total_tests = len(df_normalized)
            success_rate = round((successful_attacks / total_tests) * 100) if total_tests > 0 else 0
        
        return jsonify({
            'task_id': task_id,
            'status': 'completed',
            'result': 'success',
            'data': df_normalized.to_dict('records'),
            'summary': {
                'total_tests': len(df_normalized),
                'successful_attacks': len(df_normalized[df_normalized.get('attack_success', False) == True]) if 'attack_success' in df_normalized.columns else 0,
                'failed_attacks': len(df_normalized[df_normalized.get('attack_success', False) == False]) if 'attack_success' in df_normalized.columns else 0,
                'success_rate': success_rate
            },
            'res_file': res_file,
            'config': {},  # 无法从文件中恢复配置信息
            'created_time': datetime.now().isoformat(),
            'start_time': datetime.now().isoformat(),
            'end_time': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': f'读取结果文件失败: {str(e)}'}), 500

@app.route('/api/historical-results', methods=['GET'])
def get_historical_results():
    """获取指定目录下的所有历史记录"""
    try:
        import glob
        from datetime import datetime
        
        # 指定目录
        target_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                 'logs', 'observation_prompt_injection', 'ollama:llama3:8b', 'no_memory', 'single')
        
        if not os.path.exists(target_dir):
            return jsonify({'error': '指定目录不存在'}), 404
        
        # 获取所有CSV文件
        csv_files = glob.glob(os.path.join(target_dir, '*.csv'))
        csv_files.sort(key=os.path.getmtime, reverse=True)  # 按修改时间倒序排列
        
        results = []
        for csv_file in csv_files:
            filename = os.path.basename(csv_file)
            try:
                df = pd.read_csv(csv_file)
                if not df.empty and 'Agent Name' in df.columns:
                    file_mtime = os.path.getmtime(csv_file)
                    file_time = datetime.fromtimestamp(file_mtime)
                    
                    results.append({
                        'filename': filename,
                        'file_path': csv_file,
                        'record_count': len(df),
                        'created_time': file_time.isoformat(),
                        'attack_types': df['Attack Tool'].unique().tolist() if 'Attack Tool' in df.columns else [],
                        'agents': df['Agent Name'].unique().tolist() if 'Agent Name' in df.columns else []
                    })
            except Exception as e:
                print(f"❌ 读取文件失败: {filename}, 错误: {e}")
                continue
        
        return jsonify({
            'directory': target_dir,
            'total_files': len(results),
            'files': results
        })
        
    except Exception as e:
        return jsonify({'error': f'获取历史记录失败: {str(e)}'}), 500

@app.route('/api/tasks', methods=['GET'])
def get_all_tasks():
    """获取所有任务列表"""
    tasks = list(running_tasks.values())
    
    # 添加历史任务
    try:
        import glob
        from datetime import datetime
        
        # 指定目录
        target_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                 'logs', 'observation_prompt_injection', 'ollama:llama3:8b', 'no_memory', 'single')
        
        if os.path.exists(target_dir):
            # 获取所有CSV文件
            csv_files = glob.glob(os.path.join(target_dir, '*.csv'))
            csv_files.sort(key=os.path.getmtime, reverse=True)  # 按修改时间倒序排列
            
            for csv_file in csv_files:
                filename = os.path.basename(csv_file)
                try:
                    df = pd.read_csv(csv_file)
                    if not df.empty and 'Agent Name' in df.columns:
                        file_mtime = os.path.getmtime(csv_file)
                        file_time = datetime.fromtimestamp(file_mtime)
                        
                        # 从文件名提取任务信息
                        # 文件名格式: attack_type-single-timestamp.csv
                        parts = filename.replace('.csv', '').split('-')
                        if len(parts) >= 3:
                            attack_type = parts[0]
                            timestamp_str = '-'.join(parts[2:])  # 重新组合时间戳部分
                            
                            # 生成任务ID（使用文件名hash）
                            import hashlib
                            task_id = hashlib.md5(filename.encode()).hexdigest()[:8]
                            
                            # 获取智能体信息
                            agents = df['Agent Name'].unique().tolist() if 'Agent Name' in df.columns else []
                            agent_name = agents[0] if agents else 'unknown_agent'
                            
                            # 计算统计信息
                            total_tests = len(df)
                            successful_attacks = len(df[df.get('Attack Successful', False) == True]) if 'Attack Successful' in df.columns else 0
                            failed_attacks = total_tests - successful_attacks
                            
                            # 检查对应的日志文件是否存在
                            log_file = csv_file.replace('.csv', '.log')
                            log_path = log_file if os.path.exists(log_file) else None
                            
                            historical_task = {
                                'id': task_id,
                                'status': 'completed',
                                'created_time': file_time.isoformat(),
                                'start_time': file_time.isoformat(),
                                'end_time': file_time.isoformat(),
                                'log_path': log_path,
                                'config': {
                                    'agent': agent_name,
                                    'attack_types': [attack_type],
                                    'llms': ['ollama/llama3:8b'],
                                    'injection_method': 'observation_prompt_injection'
                                },
                                'results': task_results_cache.get(task_id, {
                                    'res_file': csv_file,
                                    'data': [],
                                    'summary': {
                                        'total_tests': total_tests,
                                        'successful_attacks': successful_attacks,
                                        'failed_attacks': failed_attacks,
                                        'success_rate': round(successful_attacks / total_tests * 100, 2) if total_tests > 0 else 0
                                    }
                                })
                            }
                            tasks.append(historical_task)
                            
                except Exception as e:
                    print(f"❌ 处理历史文件失败: {filename}, 错误: {e}")
                    continue
                    
    except Exception as e:
        print(f"❌ 获取历史任务失败: {e}")
    
    # 如果没有任务，添加示例任务
    if not tasks:
        sample_task = {
            'id': 'cf793aaa-459b-4c09-aeee-1a5479502aec',
            'status': 'completed',
            'created_time': '2025-10-23T14:55:00.000000',
            'start_time': '2025-10-23T14:55:05.000000',
            'end_time': '2025-10-23T14:58:30.000000',
            'log_path': '/home/flowteam/zqy/ASB/logs/observation_prompt_injection/ollama:llama3:8b/no_memory/single/context_ignoring-single-20251023_152255.log',
            'config': {
                'agent': 'legal_consultant_agent',
                'attack_types': ['context_ignoring'],
                'llms': ['ollama/llama3:8b'],
                'injection_method': 'observation_prompt_injection'
            },
            'results': {
                'res_file': '/home/flowteam/zqy/ASB/logs/observation_prompt_injection/ollama:llama3:8b/no_memory/single/context_ignoring-single-20251023_152255.csv',
                'data': [],
                'summary': {
                    'total_tests': 40,
                    'successful_attacks': 0,
                    'failed_attacks': 40
                }
            }
        }
        tasks.append(sample_task)
    
    return jsonify(tasks)

@app.route('/api/download', methods=['GET'])
def download_file():
    """下载文件"""
    try:
        file_path = request.args.get('file')
        if not file_path:
            return jsonify({'error': '缺少文件路径参数'}), 400
        
        # 安全检查：确保文件路径在允许的目录内
        allowed_dirs = ['/home/flowteam/zqy/ASB/logs', '/home/flowteam/zqy/ASB/results']
        file_path = os.path.abspath(file_path)
        
        if not any(file_path.startswith(allowed_dir) for allowed_dir in allowed_dirs):
            return jsonify({'error': '文件路径不在允许的目录内'}), 403
        
        if not os.path.exists(file_path):
            return jsonify({'error': '文件不存在'}), 404
        
        # 获取文件名
        filename = os.path.basename(file_path)
        
        # 返回文件
        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        print(f"下载文件失败: {str(e)}")
        return jsonify({'error': f'下载文件失败: {str(e)}'}), 500

@app.route('/api/detection/progress/<task_id>', methods=['GET'])
def get_task_progress(task_id):
    """获取任务实时进度信息"""
    if task_id not in running_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
    task = running_tasks[task_id]
    
    # 更新任务进度
    update_task_progress(task_id)
    
    # 获取日志文件路径
    log_file_path = None
    if 'log_path' in task:
        log_file_path = task['log_path']
    
    # 获取任务命令
    task_command = None
    if 'custom_command' in task.get('config', {}):
        task_command = task['config']['custom_command']
    
    return jsonify({
        'task_id': task_id,
        'status': task['status'],
        'progress': task.get('progress', 0),
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

@app.route('/api/agents', methods=['GET'])
def get_available_agents():
    """获取可用的智能体列表"""
    try:
        agents_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'agent_task.jsonl')
        
        if os.path.exists(agents_file):
            agents = []
            with open(agents_file, 'r') as f:
                for line in f:
                    agent_data = json.loads(line.strip())
                    agents.append({
                        'name': agent_data['agent_name'],
                        'path': agent_data['agent_path'],
                        'tasks': agent_data['tasks']
                    })
            return jsonify(agents)
        else:
            return jsonify([])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attack-tools', methods=['GET'])
def get_attack_tools():
    """获取攻击工具列表"""
    try:
        tools_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'all_attack_tools.jsonl')
        
        if os.path.exists(tools_file):
            tools = []
            with open(tools_file, 'r') as f:
                for line in f:
                    tool_data = json.loads(line.strip())
                    tools.append({
                        'name': tool_data['Attacker Tool'],
                        'description': tool_data['Description'],
                        'attack_type': tool_data['Attack Type'],
                        'aggressive': tool_data['Aggressive'],
                        'agent': tool_data['Corresponding Agent']
                    })
            return jsonify(tools)
        else:
            return jsonify([])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-command', methods=['POST'])
def generate_command():
    """生成命令行"""
    try:
        data = request.json
        single_agent = data.get('single_agent')
        attack_types = data.get('attack_types', ['context_ignoring'])
        
        # 确保attack_types是列表
        if isinstance(attack_types, str):
            attack_types = [attack_types]
        
        # 验证攻击类型是否有效
        valid_attack_types = ['context_ignoring', 'fake_completion', 'escape_characters', 'naive', 'combined_attack']
        for attack_type in attack_types:
            if attack_type not in valid_attack_types:
                return jsonify({'error': f'无效的攻击类型: {attack_type}. 有效选项: {", ".join(valid_attack_types)}'}), 400
        llm_name = data.get('llm_name', 'llama3:8b')
        use_backend = data.get('use_backend', 'ollama')
        attacker_tools_path = data.get('attacker_tools_path', 'data/all_attack_tools.jsonl')
        task_num = data.get('task_num', 1)
        workflow_mode = data.get('workflow_mode', 'manual')
        injection_method = data.get('injection_method', 'observation_prompt_injection')
        
        # 验证注入方法是否有效
        valid_injection_methods = [
            'observation_prompt_injection', 
            'memory_attack', 
            'direct_prompt_injection',
            'clean',
            'mixed_attack',
            'pot_backdoor',
            'pot_clean'
        ]
        if injection_method not in valid_injection_methods:
            return jsonify({'error': f'无效的注入方法: {injection_method}. 有效选项: {", ".join(valid_injection_methods)}'}), 400
        
        if not single_agent:
            return jsonify({'error': '缺少必需参数: single_agent'}), 400
        
        # 生成时间戳
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 构建命令行 - 匹配实际的main_attacker.py参数
        # 修正LLM名称格式：为Ollama添加ollama/前缀
        if use_backend == 'ollama' and not llm_name.startswith('ollama/'):
            formatted_llm_name = f'ollama/{llm_name}'
        else:
            formatted_llm_name = llm_name
            
        # 为每个攻击类型生成命令
        commands = []
        for attack_type in attack_types:
            cmd_parts = [
                'python', 'main_attacker.py',
                '--llm_name', formatted_llm_name,
                '--attack_type', attack_type,
                '--use_backend', use_backend,
                '--attacker_tools_path', attacker_tools_path,
                '--task_num', str(task_num),
                '--single_agent', single_agent,
                '--workflow_mode', workflow_mode,
                '--single',  # 新增参数：启用单模式
                '--timestamp', timestamp  # 新增参数：时间戳
            ]
            
            # 根据注入方法添加对应的布尔标志
            if injection_method == 'observation_prompt_injection':
                cmd_parts.append('--observation_prompt_injection')
            elif injection_method == 'direct_prompt_injection':
                cmd_parts.append('--direct_prompt_injection')
            elif injection_method == 'memory_attack':
                cmd_parts.append('--memory_attack')
            elif injection_method == 'clean':
                cmd_parts.append('--clean')
            elif injection_method == 'mixed_attack':
                cmd_parts.append('--mixed_attack')
            elif injection_method == 'pot_backdoor':
                cmd_parts.append('--pot_backdoor')
            elif injection_method == 'pot_clean':
                cmd_parts.append('--pot_clean')
            
            # 添加结果文件路径
            result_file = f'logs/{injection_method}/{formatted_llm_name.replace("/", ":")}/no_memory/single/{attack_type}-single-{timestamp}.csv'
            cmd_parts.extend(['--res_file', result_file])
            
            # 将命令部分转换为字符串
            command = ' '.join(cmd_parts)
            commands.append(command)
        
        # 如果有多个攻击类型，用 && 连接命令
        final_command = ' && '.join(commands)
        
        # 生成日志文件路径（使用第一个攻击类型作为主要日志文件名）
        llm_path = formatted_llm_name.replace("/", ":")  # ollama/llama3:8b -> ollama:llama3:8b
        log_file = f'logs/{injection_method}/{llm_path}/no_memory/single/{attack_types[0]}-single-{timestamp}.log'
        
        # 添加日志重定向，并确保在正确的目录和conda环境下运行
        # 获取项目根目录（web_app的父目录）
        import os
        current_file = os.path.abspath(__file__)  # /home/flowteam/zqy/ASB/web_app/app.py
        project_root = os.path.dirname(os.path.dirname(current_file))  # /home/flowteam/zqy/ASB
        command = f'cd {project_root} && conda activate ASB && {final_command} > {log_file} 2>&1'
        
        return jsonify({
            'command': command,
            'parameters': {
                'single_agent': single_agent,
                'attack_types': attack_types,
                'llm_name': llm_name,
                'use_backend': use_backend,
                'attacker_tools_path': attacker_tools_path,
                'task_num': task_num,
                'workflow_mode': workflow_mode,
                'injection_method': injection_method,
                'log_file': log_file
            }
        })
        
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
            emit('joined_task', {'task_id': task_id, 'message': f'已加入任务 {task_id}'})
    except Exception as e:
        print(f"加入任务房间时出错: {e}")

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

def get_local_ip():
    """获取本机IP地址"""
    import socket
    try:
        # 连接到一个外部地址来获取本机IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

@app.route('/api/detection/logs/<task_id>', methods=['GET'])
def get_task_logs(task_id):
    """获取任务的日志文件内容"""
    # 首先检查running_tasks
    if task_id in running_tasks:
        task = running_tasks[task_id]
        config = task.get('config', {})
    else:
        # 如果任务不在running_tasks中，尝试从历史任务中查找
        try:
            # 获取所有历史任务
            tasks_response = get_all_tasks()
            tasks_data = tasks_response.get_json()
            
            # 查找匹配的任务
            target_task = None
            for task in tasks_data:
                if task.get('id') == task_id:
                    target_task = task
                    break
            
            if not target_task:
                return jsonify({'error': '任务不存在'}), 404
            
            # 获取日志文件路径
            log_file = target_task.get('log_path')
            
            if not log_file:
                return jsonify({'error': '该任务没有日志文件'}), 404
            
            if not os.path.exists(log_file):
                return jsonify({'error': '日志文件不存在'}), 404
            
            # 读取日志文件内容
            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            file_stats = os.stat(log_file)
            
            return jsonify({
                'task_id': task_id,
                'log_file': log_file,
                'content': content,
                'file_size': file_stats.st_size,
                'last_modified': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                'config': target_task.get('config', {}),
                'created_time': target_task.get('created_time'),
                'start_time': target_task.get('start_time'),
                'end_time': target_task.get('end_time')
            })
            
        except Exception as e:
            return jsonify({'error': f'获取日志文件失败: {str(e)}'}), 500
    
    # 从配置中获取日志文件路径
    log_file = config.get('log_file')
    if not log_file:
        return jsonify({'error': '日志文件路径不存在'}), 404
    
    try:
        # 检查文件是否存在
        if not os.path.exists(log_file):
            return jsonify({'error': '日志文件不存在'}), 404
        
        # 读取日志文件内容
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 获取文件信息
        file_stats = os.stat(log_file)
        
        return jsonify({
            'task_id': task_id,
            'log_file': log_file,
            'content': content,
            'file_size': file_stats.st_size,
            'last_modified': datetime.fromtimestamp(file_stats.st_mtime).isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': f'读取日志文件失败: {str(e)}'}), 500

@app.route('/api/detection/extract-results/<task_id>', methods=['POST'])
def manual_extract_results(task_id):
    """手动提取任务结果"""
    try:
        # 查找任务
        task = None
        if task_id in running_tasks:
            task = running_tasks[task_id]
        else:
            # 从历史任务中查找
            tasks_response = get_all_tasks()
            tasks_data = tasks_response.get_json()
            for t in tasks_data:
                if t.get('id') == task_id:
                    task = t
                    break
        
        if not task:
            return jsonify({'error': '任务不存在'}), 404
        
        print(f"手动提取任务 {task_id} 的结果...")
        print(f"找到任务: {task.get('id')}, 状态: {task.get('status')}")
        print(f"任务配置: {task.get('config', {})}")
        
        # 直接调用extract_task_results函数
        try:
            print(f"开始调用extract_task_results...")
            extract_task_results(task_id, task)
            print(f"extract_task_results执行完成")
        except Exception as e:
            print(f"extract_task_results执行失败: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': f'结果提取失败: {str(e)}'}), 500
        
        print(f"提取后任务结果: {task.get('results', {})}")
        
        # 返回更新后的任务信息
        cached_results = task_results_cache.get(task_id, {})
        print(f"缓存中的结果: {cached_results}")
        print(f"缓存键: {list(task_results_cache.keys())}")
        
        return jsonify({
            'task_id': task_id,
            'status': 'success',
            'message': '结果提取完成',
            'results': cached_results
        })
        
    except Exception as e:
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
