# Windows 高级功能使用指南

## 功能概述

本指南介绍两个 Windows 平台的高级调试和开发功能：
1. **PDB 符号自动下载** - 从 Microsoft Symbol Server 下载调试符号
2. **VS 环境自动配置** - 自动设置 Visual Studio 编译环境

---

## 1. PDB 符号自动下载

### 功能说明

`PDBDownloader` 类提供从 Microsoft Symbol Server 自动下载 PDB 符号文件的功能，用于 Windows 调试和堆栈符号化。

### 基本用法

```python
from browser.tools.pdb_downloader import PDBDownloader

# 初始化下载器
downloader = PDBDownloader()

# 下载特定 PDB 文件
pdb_path = downloader.download_pdb(
    pdb_name="chrome.dll.pdb",
    guid="A1B2C3D4E5F6...",  # 从 PE 头提取
    age=1
)

if pdb_path:
    print(f"Downloaded: {pdb_path}")
```

### 从二进制自动下载

```python
# 自动从二进制提取 PDB 信息并下载
# 需要: pip install pefile

pdb_path = downloader.download_for_binary("d8.exe")
```

### 缓存管理

```python
# 查看缓存大小
cache_size = downloader.get_cache_size()
print(f"Cache: {cache_size / 1024 / 1024:.2f} MB")

# 列出缓存的符号
cached = downloader.list_cached_symbols()
for symbol in cached:
    print(f"{symbol['name']}: {symbol['size']} bytes")

# 清空缓存
downloader.clear_cache()
```

### 符号服务器

默认使用两个符号服务器：
1. **Microsoft**: `https://msdl.microsoft.com/download/symbols`
2. **Chromium**: `https://chromium-browser-symsrv.commondatastorage.googleapis.com`

### 集成到调试流程

```python
from browser.tools.pdb_downloader import PDBDownloader
from browser.tools.debug import CrashAnalyzer

# 下载符号
downloader = PDBDownloader()
pdb_path = downloader.download_for_binary("chrome.exe")

# 使用符号进行堆栈分析
analyzer = CrashAnalyzer()
crash_report = analyzer.analyze(asan_output)

# 符号化堆栈（如果有 PDB）
if pdb_path:
    symbolized = analyzer.symbolize_stack_trace(
        crash_report.stack_trace,
        symbol_path=pdb_path
    )
```

### 注意事项

1. **需要 GUID**: PDB 下载需要准确的 GUID 和 Age，从 PE 头提取
2. **网络连接**: 需要访问 Microsoft Symbol Server
3. **存储空间**: PDB 文件可能很大（数百 MB）
4. **pefile 库**: 自动提取需要 `pip install pefile`

---

## 2. Visual Studio 环境自动配置

### 功能说明

`VSEnvironment` 类自动检测 Visual Studio 安装，运行 `vcvarsall.bat`，并配置编译环境变量。

### 基本用法

```python
from browser.tools.vs_environment import VSEnvironment

# 初始化
vs_env = VSEnvironment()

# 检测 VS 安装
vs_path = vs_env.detect_vs_installation()
print(f"VS Path: {vs_path}")
print(f"VS Version: {vs_env.vs_version}")
```

### 配置环境

```python
# 配置 x64 环境
env_vars = vs_env.setup_environment(arch="x64")

# 配置 x86 环境
env_vars = vs_env.setup_environment(arch="x86")

# 指定 SDK 版本
env_vars = vs_env.setup_environment(
    arch="x64",
    sdk_version="10.0.19041.0"
)
```

### 应用到当前进程

```python
# 配置并应用环境变量
vs_env.setup_environment("x64")
vs_env.apply_to_current_process()

# 现在可以使用 cl.exe 等工具
import subprocess
result = subprocess.run(["cl", "/help"], capture_output=True)
```

### 获取工具路径

```python
# 获取编译器路径
compiler = vs_env.get_compiler_path()
print(f"Compiler: {compiler}")

# 获取 SDK 版本
sdk = vs_env.get_sdk_version()
print(f"SDK: {sdk}")
```

### 支持的 VS 版本

- Visual Studio 2022 (17.0)
- Visual Studio 2019 (16.0)
- Visual Studio 2017 (15.0)
- Visual Studio 2015 (14.0)

### 环境变量

配置后可用的关键环境变量：
- `PATH` - 包含编译器和工具
- `INCLUDE` - C/C++ 头文件路径
- `LIB` - 库文件路径
- `LIBPATH` - .NET 库路径
- `WindowsSdkDir` - Windows SDK 目录
- `VCToolsInstallDir` - VC 工具目录

### 集成到构建流程

```python
from browser.tools.vs_environment import setup_vs_environment
import subprocess

# 配置环境
env_vars = setup_vs_environment("x64")

# 使用配置的环境编译
result = subprocess.run(
    ["cl", "/c", "test.cpp"],
    env={**os.environ, **env_vars},
    capture_output=True
)
```

---

## 3. 完整示例

### 端到端调试流程

```python
from browser.tools.pdb_downloader import PDBDownloader
from browser.tools.vs_environment import VSEnvironment
from browser.tools.debug import CrashAnalyzer

# 1. 配置 VS 环境
print("Setting up VS environment...")
vs_env = VSEnvironment()
vs_env.setup_environment("x64")
vs_env.apply_to_current_process()

# 2. 下载符号
print("Downloading symbols...")
downloader = PDBDownloader()
pdb_path = downloader.download_for_binary("chrome.exe")

# 3. 分析崩溃
print("Analyzing crash...")
analyzer = CrashAnalyzer()
crash_report = analyzer.analyze(asan_output)

# 4. 符号化堆栈
if pdb_path:
    print("Symbolizing stack trace...")
    symbolized = analyzer.symbolize_stack_trace(
        crash_report.stack_trace,
        symbol_path=pdb_path
    )
    
    for frame in symbolized:
        print(f"  {frame['function']} at {frame['file']}:{frame['line']}")
else:
    print("No symbols available")
```

---

## 4. 故障排查

### PDB 下载失败

**问题**: 无法下载 PDB

**解决方案**:
1. 检查网络连接
2. 确认 GUID 和 Age 正确
3. 尝试手动访问符号服务器 URL
4. 检查防火墙设置

### VS 检测失败

**问题**: 无法检测 Visual Studio

**解决方案**:
1. 确认 VS 已安装
2. 检查注册表项是否存在
3. 尝试使用 vswhere.exe
4. 手动指定 VS 路径

### vcvarsall 失败

**问题**: vcvarsall.bat 执行失败

**解决方案**:
1. 确认 C++ 工具已安装
2. 检查 Windows SDK 是否安装
3. 尝试不同的架构（x86/x64）
4. 查看详细错误信息

---

## 5. 最佳实践

### PDB 符号管理

```python
# ✅ 好的做法：使用缓存
downloader = PDBDownloader(cache_dir="./symbols")

# ✅ 定期清理旧符号
if downloader.get_cache_size() > 5 * 1024 * 1024 * 1024:  # 5GB
    downloader.clear_cache()

# ❌ 避免：每次都重新下载
```

### VS 环境配置

```python
# ✅ 好的做法：配置一次，重复使用
vs_env = VSEnvironment()
env_vars = vs_env.setup_environment("x64")

# 在多个子进程中使用
subprocess.run(["cl", "..."], env={**os.environ, **env_vars})

# ❌ 避免：每次都重新配置
```

---

## 总结

这两个高级功能为 Windows 平台提供了专业级的调试和开发支持：

- ✅ **PDB 符号下载**: 自动化符号管理，提升调试效率
- ✅ **VS 环境配置**: 简化编译环境设置，支持多版本
- ✅ **缓存管理**: 智能缓存，节省带宽和时间
- ✅ **易于集成**: 简单的 API，易于集成到现有流程

结合之前的 WSL 集成和多版本管理，框架现在拥有完整的 Windows 开发和调试工具链。
