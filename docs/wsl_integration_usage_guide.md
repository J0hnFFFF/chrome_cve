# WSL 集成使用指南

## 功能概述

`WSLIntegration` 类提供了在 Windows 上通过 WSL 运行 Linux 工具（特别是 ASAN 二进制）的完整功能，包括自动路径转换和环境管理。

### 核心功能
1. **WSL 检测**: 自动检测 WSL 是否可用及默认发行版
2. **路径转换**: Windows 和 WSL 路径的双向自动转换
3. **命令执行**: 在 WSL 中运行任意 Linux 命令
4. **ASAN 支持**: 专门优化的 ASAN 二进制执行
5. **工具管理**: 检查和安装 Linux 工具

---

## 1. 基本用法

### 初始化

```python
from browser.tools.wsl_integration import WSLIntegration

# 初始化
wsl = WSLIntegration()

# 检查可用性
if wsl.wsl_available:
    print(f"WSL is available")
    print(f"Default distro: {wsl.default_distro}")
else:
    print("WSL is not available")
```

### 获取 WSL 信息

```python
# 获取详细信息
info = wsl.get_wsl_info()

print(f"Available: {info['available']}")
print(f"Default: {info['default_distro']}")
print(f"Distributions:")
for distro in info['distros']:
    print(f"  - {distro}")
```

### 输出示例

```
Available: True
Default: Ubuntu
Distributions:
  - Ubuntu
  - Debian
  - kali-linux
```

---

## 2. 路径转换

### Windows 到 WSL

```python
# 转换 Windows 路径到 WSL 路径
win_path = r"C:\Users\Admin\test.js"
wsl_path = wsl.windows_to_wsl_path(win_path)

print(f"Windows: {win_path}")
print(f"WSL: {wsl_path}")
# 输出: WSL: /mnt/c/Users/Admin/test.js
```

### WSL 到 Windows

```python
# 转换 WSL 路径到 Windows 路径
wsl_path = "/mnt/d/code/chrome_cve/poc.js"
win_path = wsl.wsl_to_windows_path(wsl_path)

print(f"WSL: {wsl_path}")
print(f"Windows: {win_path}")
# 输出: Windows: D:\code\chrome_cve\poc.js
```

### 路径转换规则

| Windows 路径 | WSL 路径 |
|-------------|----------|
| `C:\Users\Admin\file.txt` | `/mnt/c/Users/Admin/file.txt` |
| `D:\code\test.js` | `/mnt/d/code/test.js` |
| `E:\data\output.log` | `/mnt/e/data/output.log` |

---

## 3. 运行 Linux 命令

### 基本命令执行

```python
# 运行简单命令
result = wsl.run_command(["uname", "-a"])

if result["success"]:
    print(f"Output: {result['stdout']}")
else:
    print(f"Error: {result['stderr']}")
```

### 带工作目录

```python
# 在特定目录运行命令
result = wsl.run_command(
    ["ls", "-la"],
    cwd="C:\\Users\\Admin\\Documents"  # Windows 路径会自动转换
)
```

### 指定发行版

```python
# 在特定发行版中运行
result = wsl.run_command(
    ["python3", "--version"],
    distro="Ubuntu"
)
```

### 返回值结构

```python
{
    "returncode": 0,
    "stdout": "Linux version 5.10.16.3-microsoft-standard-WSL2\n",
    "stderr": "",
    "success": True
}
```

---

## 4. 运行 Linux 二进制

### 基本用法

```python
# 运行 Linux 二进制
result = wsl.run_linux_binary(
    binary_path="/mnt/d/linux_binaries/d8",
    args=["--version"],
    timeout=10
)

print(f"Version: {result['stdout']}")
```

### 使用 Windows 路径

```python
# 路径会自动转换
result = wsl.run_linux_binary(
    binary_path=r"D:\linux_binaries\d8",  # Windows 路径
    args=["test.js"]
)
```

### 设置环境变量

```python
# 设置环境变量
result = wsl.run_linux_binary(
    binary_path="/mnt/d/linux_binaries/d8",
    args=["poc.js"],
    env={
        "ASAN_OPTIONS": "detect_leaks=0",
        "V8_FLAGS": "--allow-natives-syntax"
    }
)
```

---

## 5. 运行 ASAN 二进制

### 专用方法

```python
# 运行 ASAN 二进制并检测崩溃
poc_code = """
function trigger() {
    let arr = new Array(0x1000);
    // Trigger vulnerability
}
trigger();
"""

result = wsl.run_asan_binary(
    binary_path=r"D:\linux_binaries\d8_asan",
    poc_code=poc_code,
    timeout=30
)

# 检查结果
if result["crashed"]:
    print("PoC triggered a crash!")
    print(f"ASAN output:\n{result['asan_output']}")
else:
    print("No crash detected")
```

### 返回值结构

```python
{
    "returncode": 1,
    "stdout": "",
    "stderr": "==12345==ERROR: AddressSanitizer: heap-use-after-free...",
    "success": False,
    "crashed": True,
    "asan_output": "==12345==ERROR: AddressSanitizer: heap-use-after-free..."
}
```

---

## 6. 工具管理

### 检查工具可用性

```python
# 检查工具是否安装
tools = ["llvm-symbolizer", "gdb", "python3", "git"]

for tool in tools:
    available = wsl.check_tool_available(tool)
    status = "✓" if available else "✗"
    print(f"{status} {tool}")
```

### 安装工具

```python
# 安装缺失的工具
if not wsl.check_tool_available("llvm-symbolizer"):
    print("Installing llvm-symbolizer...")
    success = wsl.install_tool("llvm")
    
    if success:
        print("✓ Installation successful")
    else:
        print("✗ Installation failed")
```

---

## 7. 集成到验证流程

### 与 VerifierAgent 集成

```python
from browser.tools.wsl_integration import WSLIntegration
from browser.agents.multi.verifier import VerifierAgent

wsl = WSLIntegration()

if wsl.wsl_available:
    # 使用 WSL 中的 Linux ASAN 二进制
    result = wsl.run_asan_binary(
        binary_path=r"D:\linux_binaries\d8_asan",
        poc_code=poc_code
    )
    
    if result["crashed"]:
        print("Crash detected in WSL!")
        
        # 可以进一步使用 WSL 中的符号化工具
        if wsl.check_tool_available("llvm-symbolizer"):
            # 符号化堆栈
            pass
```

### 混合验证（Windows + WSL）

```python
from browser.tools.version_manager import VersionManager
from browser.tools.wsl_integration import WSLIntegration

mgr = VersionManager()
wsl = WSLIntegration()

# Windows 版本
win_version = mgr.get_version("95.0")

# WSL Linux 版本
linux_d8 = r"D:\linux_binaries\d8_95.0_asan"

# 在两个环境中测试
print("Testing on Windows...")
win_result = execute_poc(poc_code, win_version.d8_path)

print("Testing on WSL...")
wsl_result = wsl.run_asan_binary(linux_d8, poc_code)

# 对比结果
print(f"Windows crashed: {win_result.get('crashed', False)}")
print(f"WSL crashed: {wsl_result['crashed']}")
```

---

## 8. 完整示例

### 端到端 WSL 验证

```python
from browser.tools.wsl_integration import WSLIntegration
from browser.tools.debug import CrashAnalyzer

# 1. 初始化
wsl = WSLIntegration()

if not wsl.wsl_available:
    print("WSL not available, falling back to Windows")
    exit(1)

# 2. 检查必要工具
required_tools = ["llvm-symbolizer"]
for tool in required_tools:
    if not wsl.check_tool_available(tool):
        print(f"Installing {tool}...")
        wsl.install_tool(tool.split('-')[0])  # Install package

# 3. 准备 PoC
poc_code = """
// PoC code here
"""

# 4. 运行 ASAN 二进制
print("Running PoC in WSL...")
result = wsl.run_asan_binary(
    binary_path=r"D:\linux_binaries\d8_asan",
    poc_code=poc_code,
    timeout=30
)

# 5. 分析结果
if result["crashed"]:
    print("✓ Crash detected!")
    print(f"\nASAN Output:")
    print(result["asan_output"])
    
    # 6. 符号化（如果需要）
    if wsl.check_tool_available("llvm-symbolizer"):
        # 使用 WSL 中的符号化工具
        symbolize_cmd = [
            "llvm-symbolizer",
            "--obj=" + wsl.windows_to_wsl_path(r"D:\linux_binaries\d8_asan")
        ]
        # ... 符号化逻辑
else:
    print("✗ No crash detected")

# 7. 清理
print("\nVerification complete")
```

---

## 9. 故障排查

### WSL 不可用

**问题**: `wsl_available = False`

**解决方案**:
1. 确认 WSL 已安装：`wsl --status`
2. 安装 WSL：`wsl --install`
3. 更新 WSL：`wsl --update`

### 路径转换失败

**问题**: 路径转换不正确

**解决方案**:
```python
# 确保使用绝对路径
from pathlib import Path

win_path = Path(r"C:\Users\Admin\test.js").resolve()
wsl_path = wsl.windows_to_wsl_path(str(win_path))
```

### 命令执行超时

**问题**: 命令超时

**解决方案**:
```python
# 增加超时时间
result = wsl.run_command(
    ["long-running-command"],
    timeout=120  # 2 分钟
)
```

### 权限问题

**问题**: `Permission denied`

**解决方案**:
```python
# 确保二进制有执行权限
wsl.run_command(["chmod", "+x", "/mnt/d/linux_binaries/d8"])
```

---

## 10. 最佳实践

### 1. 路径处理

```python
# ✅ 好的做法：使用绝对路径
win_path = Path(file_path).resolve()
wsl_path = wsl.windows_to_wsl_path(str(win_path))

# ❌ 避免：使用相对路径
wsl_path = wsl.windows_to_wsl_path("./test.js")  # 可能不准确
```

### 2. 错误处理

```python
# ✅ 好的做法：检查结果
result = wsl.run_command(["some-command"])
if result["success"]:
    process_output(result["stdout"])
else:
    logger.error(f"Command failed: {result['stderr']}")

# ❌ 避免：假设总是成功
output = wsl.run_command(["some-command"])["stdout"]  # 可能失败
```

### 3. 资源清理

```python
# ✅ 好的做法：清理临时文件
import tempfile
import os

temp_file = tempfile.mktemp(suffix='.js')
try:
    # 使用临时文件
    wsl_path = wsl.windows_to_wsl_path(temp_file)
    result = wsl.run_command(["process", wsl_path])
finally:
    if os.path.exists(temp_file):
        os.remove(temp_file)
```

---

## 总结

`WSLIntegration` 提供了完整的 WSL 集成能力：

- ✅ **自动检测**: WSL 可用性和发行版
- ✅ **路径转换**: Windows ↔ WSL 双向转换
- ✅ **命令执行**: 运行任意 Linux 命令
- ✅ **ASAN 支持**: 专门优化的 ASAN 二进制执行
- ✅ **工具管理**: 检查和安装 Linux 工具
- ✅ **易于集成**: 简单的 API，易于集成到现有流程

结合 Windows 原生支持，框架现在可以在 Windows 和 Linux 环境中无缝运行验证。
