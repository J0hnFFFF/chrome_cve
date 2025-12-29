"""
Subprocess 调试包装器

用于追踪所有 subprocess 调用并自动修复编码问题
"""
import subprocess
import sys
import traceback
from functools import wraps

# 保存原始函数
_original_popen = subprocess.Popen
_original_run = subprocess.run

def _safe_popen(*args, **kwargs):
    """安全的 Popen 包装器,自动添加编码参数"""
    # 获取调用栈信息
    stack = traceback.extract_stack()
    caller_info = stack[-2]  # 调用者信息
    
    # 检查是否已经设置了编码
    has_encoding = 'encoding' in kwargs or 'text' in kwargs or 'universal_newlines' in kwargs
    
    if not has_encoding and (kwargs.get('stdout') == subprocess.PIPE or kwargs.get('stderr') == subprocess.PIPE):
        # 自动添加编码参数
        kwargs['encoding'] = 'utf-8'
        kwargs['errors'] = 'ignore'
        print(f"[DEBUG] Auto-fixed encoding for Popen call from {caller_info.filename}:{caller_info.lineno}")
    
    return _original_popen(*args, **kwargs)

def _safe_run(*args, **kwargs):
    """安全的 run 包装器,自动添加编码参数"""
    # 检查是否已经设置了编码
    has_encoding = 'encoding' in kwargs or 'text' in kwargs or 'universal_newlines' in kwargs
    
    if not has_encoding and kwargs.get('capture_output'):
        # 自动添加编码参数
        kwargs['encoding'] = 'utf-8'
        kwargs['errors'] = 'ignore'
    
    return _original_run(*args, **kwargs)

def install_subprocess_wrapper():
    """安装 subprocess 包装器"""
    subprocess.Popen = _safe_popen
    subprocess.run = _safe_run
    print("[DEBUG] Subprocess wrapper installed - all calls will use UTF-8 encoding")

def uninstall_subprocess_wrapper():
    """卸载 subprocess 包装器"""
    subprocess.Popen = _original_popen
    subprocess.run = _original_run
    print("[DEBUG] Subprocess wrapper uninstalled")
