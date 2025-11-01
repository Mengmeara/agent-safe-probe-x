# app/services/commands.py
import os
from datetime import datetime

from core.path_utils import PROJECT_ROOT

VALID_ATTACK_TYPES = [
    'context_ignoring', 'fake_completion', 'escape_characters', 'naive', 'combined_attack'
]

VALID_INJECTION_METHODS = [
    'observation_prompt_injection',
    'memory_attack',
    'direct_prompt_injection',
    'clean',
    'mixed_attack',
    'pot_backdoor',
    'pot_clean'
]

def _format_llm_name_for_backend(use_backend: str, llm_name: str) -> str:
    """与原逻辑一致：Ollama 后端统一加上 'ollama/' 前缀。"""
    if use_backend == 'ollama' and not llm_name.startswith('ollama/'):
        return f'ollama/{llm_name}'
    return llm_name

def generate_command_payload(data: dict):
    """
    组装与校验命令行参数，返回 (payload_dict, status_code)。
    返回结构保持与原 /api/generate-command 完全一致：
      {
        'command': '<完整命令字符串>',
        'parameters': {...}
      }, 200
    或 {'error': '...'}, 400/500
    """
    try:
        single_agent = data.get('single_agent')
        attack_types = data.get('attack_types', ['context_ignoring'])
        if isinstance(attack_types, str):
            attack_types = [attack_types]

        # 校验攻击类型
        for attack_type in attack_types:
            if attack_type not in VALID_ATTACK_TYPES:
                return ({'error': f'无效的攻击类型: {attack_type}. 有效选项: {", ".join(VALID_ATTACK_TYPES)}'}, 400)

        llm_name    = data.get('llm_name', 'llama3:8b')
        use_backend = data.get('use_backend', 'ollama')
        attacker_tools_path = data.get('attacker_tools_path', 'data/all_attack_tools.jsonl')
        tasks_path          = data.get('tasks_path', 'data/agent_task_pot.jsonl')
        task_num            = data.get('task_num', 1)
        workflow_mode       = data.get('workflow_mode', 'manual')
        injection_method    = data.get('injection_method', 'observation_prompt_injection')

        # 校验注入方法
        if injection_method not in VALID_INJECTION_METHODS:
            return ({'error': f'无效的注入方法: {injection_method}. 有效选项: {", ".join(VALID_INJECTION_METHODS)}'}, 400)

        if not single_agent:
            return ({'error': '缺少必需参数: single_agent'}, 400)

        # 时间戳
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # LLM 名称规范化（与原逻辑一致）
        formatted_llm_name = _format_llm_name_for_backend(use_backend, llm_name)

        # 为每个攻击类型生成命令片段
        commands = []
        for attack_type in attack_types:
            parts = [
                'python', 'main_attacker.py',
                '--llm_name', formatted_llm_name,
                '--attack_type', attack_type,
                '--use_backend', use_backend,
                '--attacker_tools_path', attacker_tools_path,
                '--tasks_path', tasks_path,
                '--task_num', str(task_num),
                '--single_agent', single_agent,
                '--workflow_mode', workflow_mode,
                '--single',
                '--timestamp', timestamp,
            ]

            # 注入方法开关（布尔标志）
            if injection_method == 'observation_prompt_injection':
                parts.append('--observation_prompt_injection')
            elif injection_method == 'direct_prompt_injection':
                parts.append('--direct_prompt_injection')
            elif injection_method == 'memory_attack':
                parts.append('--memory_attack')
            elif injection_method == 'clean':
                parts.append('--clean')
            elif injection_method == 'mixed_attack':
                parts.append('--mixed_attack')
            elif injection_method == 'pot_backdoor':
                parts.append('--pot_backdoor')
            elif injection_method == 'pot_clean':
                parts.append('--pot_clean')

            # 结果文件路径（保持原有目录结构和命名）
            result_file = f'logs/{injection_method}/{formatted_llm_name.replace("/", ":")}/no_memory/single/{attack_type}-single-{timestamp}.csv'
            parts.extend(['--res_file', result_file])

            commands.append(' '.join(parts))

        # 多个攻击类型用 && 串起来
        final_command_inner = ' && '.join(commands)

        # 生成日志路径（以第一个攻击类型命名）
        llm_path = formatted_llm_name.replace('/', ':')
        log_file = f'logs/{injection_method}/{llm_path}/no_memory/single/{attack_types[0]}-single-{timestamp}.log'

        # 拼接环境与目录（使用 PROJECT_ROOT，保持与原实现一致的路径与 conda 激活）
        project_root = PROJECT_ROOT
        full_command = (
            f'cd {project_root} && '
            f'source /home/flowteam/miniconda3/etc/profile.d/conda.sh && '
            f'conda activate ASB && '
            f'{final_command_inner} > {log_file} 2>&1'
        )

        payload = {
            'command': full_command,
            'parameters': {
                'single_agent': single_agent,
                'attack_types': attack_types,
                'llm_name': llm_name,
                'use_backend': use_backend,
                'attacker_tools_path': attacker_tools_path,
                'tasks_path': tasks_path,
                'task_num': task_num,
                'workflow_mode': workflow_mode,
                'injection_method': injection_method,
                'log_file': log_file
            }
        }
        return (payload, 200)

    except Exception as e:
        return ({'error': str(e)}, 500)
