#!/usr/bin/env python3
"""
配置管理模块
"""
import os

class Config:
    """应用配置"""
    
    # 基础配置
    UPLOAD_FOLDER = 'uploads'
    RESULTS_FOLDER = 'results'
    
    # 数据库配置
    DB_NAME = 'tasks.db'
    
    # 项目路径
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Flask配置
    DEBUG = True
    HOST = '0.0.0.0'
    PORT = 8888
    
    # 日志配置
    DEFAULT_LOG_DIR = 'logs'
    
    @classmethod
    def get_db_path(cls):
        """获取数据库路径"""
        return os.path.join(os.path.dirname(__file__), cls.DB_NAME)
    
    @classmethod
    def get_upload_folder(cls):
        """获取上传文件夹路径"""
        folder = os.path.join(os.path.dirname(__file__), cls.UPLOAD_FOLDER)
        os.makedirs(folder, exist_ok=True)
        return folder
    
    @classmethod
    def get_results_folder(cls):
        """获取结果文件夹路径"""
        folder = os.path.join(os.path.dirname(__file__), cls.RESULTS_FOLDER)
        os.makedirs(folder, exist_ok=True)
        return folder

# 有效的攻击类型
VALID_ATTACK_TYPES = ['context_ignoring', 'fake_completion', 'escape_characters', 'naive', 'combined_attack']

# 有效的注入方法
VALID_INJECTION_METHODS = [
    'observation_prompt_injection', 
    'memory_attack', 
    'direct_prompt_injection',
    'clean',
    'mixed_attack',
    'pot_backdoor',
    'pot_clean'
]

# 默认配置模板
DEFAULT_CONFIG = {
    "injection_method": "observation_prompt_injection",
    "attack_tool": ["all"],
    "llms": ["ollama/llama3:8b"],
    "attack_types": ["clean_opi"],
    "task_num": 1,
    "defense_type": None,
    "write_db": False,
    "read_db": False
}

