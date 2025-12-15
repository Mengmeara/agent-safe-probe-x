# app/services/files.py
import os, re, json, glob
from datetime import datetime
import pandas as pd
import numpy as np

from core.path_utils import PROJECT_ROOT, resolve_path

# --------- DataFrame 标准化工具 ---------
FIELD_MAPPING = {
    'Agent Name': 'agent_name',
    'Attack Tool': 'attack_tool',
    'Attack Successful': 'attack_success',
    'Original Task Successful': 'original_success',
    'Refuse Result': 'refuse_result',
    'Memory Found': 'memory_found',
    'Aggressive': 'aggressive',
    'messages': 'response'
}
BOOL_COLS = ('attack_success','original_success','refuse_result','memory_found','aggressive')

def safe_to_bool_series(s):
    if getattr(s, "dtype", None) == bool:
        return s
    s_str = s.astype(str).str.strip().str.lower()
    map_tbl = {
        'true': True, '1': True, 'yes': True, 'y': True, 't': True,
        'false': False, '0': False, 'no': False, 'n': False, 'f': False,
        '': False, 'none': False, 'nan': False
    }
    out = s_str.map(map_tbl)
    return out.fillna(False).astype(bool)

def normalize_df(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns={k:v for k,v in FIELD_MAPPING.items() if k in df.columns})
    for col in BOOL_COLS:
        if col in df.columns:
            s = df[col].astype(str).str.strip().str.lower()
            df[col] = s.isin({'true','1','yes','y','t','true.0','1.0'})
    if 'agent_name' in df.columns:
        df['task'] = df['agent_name'].astype(str).apply(lambda x: x.split('/')[-1] if '/' in x else x)
    df = df.replace([np.inf, -np.inf], None)
    df = df.where(pd.notna(df), None)
    return df

# --------- 结果提取与读取 ---------
def extract_task_results(task_id: str, task: dict, resolve_path_fn=resolve_path):
    """
    根据 task.config 定位结果 CSV -> 读取 -> normalize -> 生成 summary+records
    读取失败/缺失时在 task['results'] 写入错误描述
    """
    try:
        cfg = task.get('config', {}) or {}
        res_file = cfg.get('res_file')

        if not res_file:
            # 从命令/日志名推断
            cmd = cfg.get('custom_command', '')
            if cmd:
                m = re.search(r'--res_file\s+([^\s>]+)', cmd)
                if m: res_file = m.group(1)
        if not res_file:
            log_file = cfg.get('log_file')
            if log_file and log_file.endswith('.log'):
                res_file = log_file.replace('.log', '.csv')

        if res_file and not os.path.isabs(res_file):
            res_file = resolve_path_fn(res_file)

        if not res_file or not os.path.exists(res_file):
            task['results'] = {'error': '结果文件不存在', 'res_file': res_file}
            return

        df = pd.read_csv(res_file)
        if df.empty:
            task['results'] = {'error': '结果文件为空', 'data': [], 'summary': {}, 'res_file': res_file}
            return

        df = normalize_df(df)
        total = len(df)
        succ_attack = int(df['attack_success'].sum()) if 'attack_success' in df.columns else 0
        succ_origin = int(df['original_success'].sum()) if 'original_success' in df.columns else 0
        summary = {
            'total_tests': total,
            'successful_attacks': succ_attack,
            'failed_attacks': total - succ_attack,
            'success_rate': int(round((succ_attack / total) * 100)) if total else 0,
            'successful_original': succ_origin,
            'failed_original': total - succ_origin,
            'success_rate_original': int(round((succ_origin / total) * 100)) if total else 0,
        }

        task['results'] = {'data': df.to_dict('records'), 'summary': summary, 'res_file': res_file}
    except Exception as e:
        task['results'] = {'error': str(e)}

def read_result_file(task_id, res_file):
    """读取结果文件并返回标准格式的数据（与原 server.py 等价）。"""
    try:
        if not res_file or not os.path.exists(res_file):
            return {'error': '结果文件不存在'}, 404

        df = pd.read_csv(res_file)
        if df.empty:
            return {'error': '结果文件为空'}, 404

        df = normalize_df(df)

        total = len(df)
        succ = int(df['attack_success'].sum()) if 'attack_success' in df.columns else 0
        success_rate = int(round((succ / total) * 100)) if total else 0

        return {
            'task_id': task_id,
            'status': 'completed',
            'result': 'success',
            'data': df.to_dict('records'),
            'summary': {
                'total_tests': total,
                'successful_attacks': succ,
                'failed_attacks': total - succ,
                'success_rate': success_rate
            },
            'res_file': res_file,
            'created_time': datetime.now().isoformat(),
            'start_time': datetime.now().isoformat(),
            'end_time': datetime.now().isoformat()
        }, 200

    except Exception as e:
        return {'error': f'读取结果文件失败: {str(e)}'}, 500


def list_historical_results(injection_method='observation_prompt_injection', llm='llama3:8b'):
    """列举某目录下的历史 CSV（与原 server.py /api/historical-results 的实现等价）。"""
    try:
        target_dir = os.path.join(PROJECT_ROOT, 'logs', injection_method, f'ollama:{llm}', 'no_memory', 'single')

        if not os.path.exists(target_dir):
            return {'error': f'指定目录不存在: {target_dir}'}, 404

        csv_files = glob.glob(os.path.join(target_dir, '*.csv'))
        csv_files.sort(key=os.path.getmtime, reverse=True)

        results = []
        for csv_file in csv_files:
            try:
                df = pd.read_csv(csv_file)
                if df.empty:
                    continue
                df = normalize_df(df)
                results.append({
                    'filename': os.path.basename(csv_file),
                    'file_path': csv_file,
                    'record_count': len(df),
                    'created_time': datetime.fromtimestamp(os.path.getmtime(csv_file)).isoformat(),
                    'attack_types': list(pd.Series(df.get('attack_tool')).dropna().unique()) if 'attack_tool' in df.columns else [],
                    'agents': list(pd.Series(df.get('agent_name')).dropna().unique()) if 'agent_name' in df.columns else []
                })
            except Exception:
                continue

        return {'directory': target_dir, 'total_files': len(results), 'files': results}, 200

    except Exception as e:
        return {'error': f'获取历史记录失败: {str(e)}'}, 500

