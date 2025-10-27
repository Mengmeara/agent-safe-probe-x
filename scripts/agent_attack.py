import os, yaml, argparse, re, sys, shlex
import subprocess

def sanitize_filename(name):
    return re.sub(r'[\/:*?"<>|]', '_', name)

def get_run_command():
    """Return different background run commands based on the operating system"""
    if sys.platform == 'win32':
        # Windows uses start command
        return 'start /B {}'
    else:
        # Unix/Linux uses nohup
        return 'nohup {} > {} 2>&1 &'

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Load YAML config file')
    parser.add_argument('--cfg_path', type=str, required=True, help='Path to the YAML configuration file')
    parser.add_argument('--foreground', action='store_true', help='Run tasks in foreground instead of background')
    args = parser.parse_args()

    with open(args.cfg_path, 'r') as file:
        cfg = yaml.safe_load(file)

    llms = cfg.get('llms', None)
    suffix = cfg.get('suffix', '')
    attack_tool_types = cfg.get('attack_tool', None)
    write_db = cfg.get('write_db', None)
    read_db = cfg.get('read_db', None)
    defense_type = cfg.get('defense_type', None)
    injection_method = cfg['injection_method'] # 'direct_prompt_injection', 'memory_attack', 'observation_prompt_injection', 'clean'
    attack_types = cfg.get('attack_types', None)
    task_num = cfg.get('task_num', 1)


    for attack_tool_type in attack_tool_types:
        for llm in llms:
            for attack_type in attack_types:
                if llm.startswith('gpt') or llm.startswith('gemini') or llm.startswith('claude'):
                    llm_name = llm
                    backend=None
                elif llm.startswith('ollama'):
                    llm_name = llm.split('/')[-1]
                    llm_name = sanitize_filename(llm_name)
                    backend='ollama'

                log_path = f'logs/{injection_method}/{llm_name}'
                database = f'memory_db/direct_prompt_injection/{attack_type}_gpt-4o-mini'

                if attack_tool_type == 'all':
                    attacker_tools_path = 'data/all_attack_tools.jsonl'
                elif attack_tool_type == 'non-agg':
                    attacker_tools_path = 'data/all_attack_tools_non_aggressive.jsonl'
                elif attack_tool_type == 'agg':
                    attacker_tools_path = 'data/all_attack_tools_aggressive.jsonl'
                elif attack_tool_type == 'test':
                    attacker_tools_path = 'data/attack_tools_test.jsonl'
                    args.tasks_path = 'data/attack_tools_test.jsonl'

                log_memory_type = 'new_memory' if read_db else 'no_memory'
                log_base = f'{log_path}/{defense_type}' if defense_type else f'{log_path}/{log_memory_type}'
                log_file = f'{log_base}/{attack_type}-{attack_tool_type}'
                os.makedirs(os.path.dirname(log_file), exist_ok=True)


                base_cmd = f'''nohup python main_attacker.py --llm_name {llm} --attack_type {attack_type} --use_backend {backend} --attacker_tools_path {attacker_tools_path} --res_file {log_file}_{suffix}.csv --task_num {task_num}'''

                if database:
                    base_cmd += f' --database {database}'
                if write_db:
                    base_cmd += ' --write_db'
                if read_db:
                    base_cmd += ' --read_db'
                if defense_type:
                    base_cmd += f' --defense_type {defense_type}'

                if injection_method in ['direct_prompt_injection', 'memory_attack', 'observation_prompt_injection', 'clean']:
                    specific_cmd = f' --{injection_method}'
                elif injection_method == 'mixed_attack':
                    specific_cmd = ' --direct_prompt_injection --observation_prompt_injection'
                elif injection_method == 'DPI_MP':
                    specific_cmd = ' --direct_prompt_injection'
                elif injection_method == 'OPI_MP':
                    specific_cmd = ' --observation_prompt_injection'
                elif injection_method == 'DPI_OPI':
                    specific_cmd = ' --direct_prompt_injection --observation_prompt_injection'
                else:
                    specific_cmd = ''

                # Build command based on operating system
                log_file_full = f'{log_file}_{suffix}.log'
                
                if args.foreground:
                    # Foreground run: execute command directly and display output in terminal while writing to log file
                    cmd_list = ['python', 'main_attacker.py', '--llm_name', llm, '--attack_type', attack_type]
                    if backend:
                        cmd_list.extend(['--use_backend', backend])
                    cmd_list.extend(['--attacker_tools_path', attacker_tools_path, '--res_file', f'{log_file}_{suffix}.csv', '--task_num', str(task_num)])
                    
                    if database:
                        cmd_list.extend(['--database', database])
                    if write_db:
                        cmd_list.append('--write_db')
                    if read_db:
                        cmd_list.append('--read_db')
                    if defense_type:
                        cmd_list.extend(['--defense_type', defense_type])
                    
                    # Process specific_cmd
                    if specific_cmd.strip():
                        parts = shlex.split(specific_cmd)
                        for part in parts:
                            if part.startswith('--'):
                                cmd_list.append(part)
                            elif part and not part.startswith('-'):
                                cmd_list.append(part)
                    
                    print(f'[Starting foreground task] {log_file_full}')
                    # Use subprocess to output to both terminal and file
                    with open(log_file_full, 'w', encoding='utf-8') as log_file_handle:
                        process = subprocess.Popen(
                            cmd_list,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            universal_newlines=True,
                            bufsize=1
                        )
                        for line in process.stdout:
                            print(line, end='')  # Output to terminal
                            log_file_handle.write(line)  # Write to file
                            log_file_handle.flush()  # Flush immediately
                        process.wait()
                    print(f'[Task completed] {log_file_full}')
                else:
                    # Background run
                    if sys.platform == 'win32':
                        # Windows: use start /B for background run
                        cmd = f"start /B python main_attacker.py --llm_name {llm} --attack_type {attack_type} --use_backend {backend} --attacker_tools_path {attacker_tools_path} --res_file {log_file}_{suffix}.csv --task_num {task_num}"
                        if database:
                            cmd += f' --database {database}'
                        if write_db:
                            cmd += ' --write_db'
                        if read_db:
                            cmd += ' --read_db'
                        if defense_type:
                            cmd += f' --defense_type {defense_type}'
                        cmd += f"{specific_cmd} > {log_file_full} 2>&1"
                    else:
                        # Unix/Linux: use nohup
                        cmd = f"{base_cmd}{specific_cmd} > {log_file}_{suffix}.log 2>&1 &"
                    
                    print(f'[Starting background task] {log_file_full}')
                    os.system(cmd)
                    if sys.platform == 'win32':
                        print(f'  -> Task started in background, view logs at: {log_file_full}')

