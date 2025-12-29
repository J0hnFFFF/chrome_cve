# Phase 3 - Windows 环境增强使用指南

## 功能概述

Phase 3 针对 Windows 平台进行了深度优化，提升了环境自动检测的可靠性和调试信息的丰富度。

### 主要改进
1. **智能路径检测**: 不再依赖硬编码路径，通过 Windows 注册表自动发现 Chrome、Visual Studio 和 Windows SDK。
2. **多版本管理**: 自动发现并索引 `./volumes` 目录下的多个 Chrome/d8 版本。
3. **版本元数据**: 自动提取二进制文件的 ProductVersion（通过 PowerShell）。
4. **WSL 集成基础**: 自动检测 WSL2 可用性，为后续跨平台验证做准备。
5. **SEH 异常解析**: 支持解析 Windows 原生异常码（如 `0xC0000005` 访问冲突）。

---

## 1. 智能路径检测

### 自动发现
`EnvironmentManager` 现在会查询注册表：
- **Chrome**: `HKEY_LOCAL_MACHINE\...\App Paths\chrome.exe`
- **Visual Studio**: 自动检测 2017/2019/2022 (VS 15.0/16.0/17.0)
- **Windows SDK**: 检测安装目录和版本。

### 使用示例
```python
from browser.tools.environment_manager import EnvironmentManager

manager = EnvironmentManager()

# 检测完整的开发工具链
toolchain = manager.detect_toolchain()
print(f"VS Path: {toolchain['vs_path']}")
print(f"SDK Path: {toolchain['sdk_path']}")
print(f"WSL Available: {toolchain['wsl_available']}")
```

---

## 2. 多版本共存管理

### 功能说明
框架会自动扫描指定目录（默认 `./volumes`）下所有符合 `chrome-*` 模式的文件夹。

### 使用示例
```python
# 发现所有本地版本
versions = manager.find_all_versions("./volumes")

for v in versions:
    print(f"Version: {v['version']}")
    print(f"  d8: {v['d8_path']}")
    print(f"  ASAN: {v['asan']}")
```

---

## 3. 二进制版本提取

### 功能说明
使用 PowerShell 获取 `.exe` 文件的详细版本信息，这比解析 `--version` 输出更可靠。

### 使用示例
```python
version = manager.get_binary_version(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
print(f"Exact Version: {version}") # 输出如: 120.0.6099.110
```

---

## 4. SEH 异常解析

### 功能说明
在没有 ASAN 的情况下，Windows 程序的崩溃通常表现为 SEH 异常。`CrashAnalyzer` 现在能识别这些异常。

### 识别列表
- `0xC0000005`: Access Violation (内存访问冲突)
- `0xC00000FD`: Stack Overflow (栈溢出)
- `0xC000001D`: Illegal Instruction (非法指令)
- `0xC0000094`: Integer Divide by Zero (除零)

### 使用示例
```python
from browser.tools.debug import CrashAnalyzer

analyzer = CrashAnalyzer()
report = analyzer.analyze("Process exited with code 0xC0000005")

print(f"Crash Type: {report.crash_type}") # 输出: Access Violation
print(f"SEH Code: {report.seh_exception}") # 输出: 0xC0000005
```

---

## 5. 集成到 VerificationEnv

现在 `VerificationEnv` 包含了更丰富的元数据：

```python
env = manager.get_default_env()
print(f"Chrome: {env.chrome_path} (v{env.chrome_version})")
print(f"d8: {env.d8_path} (v{env.d8_version})")
print(f"Toolchain: {env.toolchain['vs_path']}")
```

---

## 总结

Phase 3 显著减少了在 Windows 上手动配置环境的需求，并为自动化验证提供了更坚实的基础。通过注册表和 PowerShell 的结合，框架现在能够像真正的 Windows 开发者一样"感知"其运行环境。
