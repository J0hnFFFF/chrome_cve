# 多版本 Chrome/d8 管理使用指南

## 功能概述

`VersionManager` 类提供了便捷的 API 来管理多个 Chrome/d8 版本，支持自动发现、版本选择、vulnerable/fixed 配对等功能。

### 核心功能
1. **自动发现**: 扫描目录，自动发现所有版本
2. **版本选择**: 按版本号、最新版、ASAN 等条件选择
3. **版本配对**: 自动获取 vulnerable/fixed 版本对
4. **交互式选择**: 提供命令行交互界面

---

## 1. 基本用法

### 初始化

```python
from browser.tools.version_manager import VersionManager

# 使用默认目录 (./volumes)
mgr = VersionManager()

# 或指定自定义目录
mgr = VersionManager("d:/chrome_versions")
```

### 列出所有版本

```python
# 列出所有版本
versions = mgr.list_versions()
for v in versions:
    print(v)

# 只列出 ASAN 版本
asan_versions = mgr.list_versions(asan_only=True)
```

### 输出示例

```
Version 96.0.4664.45 | d8: ./volumes/chrome-96.0.4664.45/d8.exe | chrome: ./volumes/chrome-96.0.4664.45/chrome.exe | (ASAN)
Version 95.0.4638.69 | d8: ./volumes/chrome-95.0.4638.69/d8.exe
Version 94.0.4606.81 | d8: ./volumes/chrome-94.0.4606.81/d8.exe | (ASAN)
```

---

## 2. 获取特定版本

### 按版本号获取

```python
# 精确匹配
version = mgr.get_version("95.0.4638.69")

# 部分匹配
version = mgr.get_version("95.0")

if version:
    print(f"Found: {version.version}")
    print(f"d8: {version.d8_path}")
    print(f"ASAN: {version.asan_enabled}")
```

### 获取最新版本

```python
# 获取最新版本
latest = mgr.get_latest()
print(f"Latest: {latest.version}")

# 获取最新 ASAN 版本
latest_asan = mgr.get_latest(asan_only=True)
print(f"Latest ASAN: {latest_asan.version}")
```

---

## 3. 版本配对（Vulnerable/Fixed）

### 自动配对

```python
# 指定 vulnerable 版本，自动找下一个版本作为 fixed
vuln, fixed = mgr.get_version_pair("95.0.4638.69")

if vuln and fixed:
    print(f"Vulnerable: {vuln.version} -> {vuln.d8_path}")
    print(f"Fixed: {fixed.version} -> {fixed.d8_path}")
```

### 手动指定两个版本

```python
# 明确指定两个版本
vuln, fixed = mgr.get_version_pair(
    vulnerable_version="95.0.4638.69",
    fixed_version="96.0.4664.45"
)
```

### 基于 CVE 信息配对

```python
cve_info = {
    "cve_id": "CVE-2021-21220",
    "vulnerable_version": "95.0.4638.69",
    "fixed_version": "96.0.4664.45"
}

vuln, fixed = mgr.get_by_cve("CVE-2021-21220", cve_info)
```

---

## 4. 交互式选择

### 命令行交互

```python
# 显示所有版本并让用户选择
selected = mgr.select_interactive()

if selected:
    print(f"You selected: {selected.version}")
    print(f"d8 path: {selected.d8_path}")
```

### 输出示例

```
Available Chrome/d8 Versions (3 total):
================================================================================
 1. Version 96.0.4664.45 | d8: ./volumes/chrome-96.0.4664.45/d8.exe | (ASAN)
 2. Version 95.0.4638.69 | d8: ./volumes/chrome-95.0.4638.69/d8.exe
 3. Version 94.0.4606.81 | d8: ./volumes/chrome-94.0.4606.81/d8.exe | (ASAN)
================================================================================

ASAN-enabled: 2/3
Latest: 96.0.4664.45

Select version number (or 'q' to quit): 2

You selected: 95.0.4638.69
d8 path: ./volumes/chrome-95.0.4638.69/d8.exe
```

---

## 5. 便捷方法

### 直接获取路径

```python
# 获取 d8 路径
d8_path = mgr.get_d8_path("95.0.4638.69")

# 获取 Chrome 路径
chrome_path = mgr.get_chrome_path("95.0.4638.69")
```

### 打印摘要

```python
# 打印所有版本的摘要
mgr.print_summary()
```

---

## 6. 集成到验证流程

### 与 VerifierAgent 集成

```python
from browser.tools.version_manager import VersionManager
from browser.agents.multi.verifier import VerifierAgent

mgr = VersionManager()
verifier = VerifierAgent()

# 获取版本对
vuln, fixed = mgr.get_version_pair("95.0")

# 双端验证
result = verifier.verify_differential(
    poc=poc_code,
    vulnerable_binary=vuln.d8_path,
    fixed_binary=fixed.d8_path
)

print(f"Vulnerable crashed: {result['vulnerable_crashed']}")
print(f"Fixed crashed: {result['fixed_crashed']}")
```

### 与补丁验证集成

```python
from browser.tools.version_manager import VersionManager
from browser.tools.analysis_tools import verify_patch_effectiveness

mgr = VersionManager()

# 获取版本对
vuln, fixed = mgr.get_version_pair("95.0.4638.69")

# 验证补丁
report = verify_patch_effectiveness(
    vulnerable_binary=vuln.d8_path,
    fixed_binary=fixed.d8_path,
    poc_code=poc_code
)

print(f"Patch effective: {report.patch_effective}")
```

---

## 7. 目录结构要求

### 推荐结构

```
./volumes/
├── chrome-96.0.4664.45/
│   ├── d8.exe
│   ├── chrome.exe
│   └── ... (其他文件)
├── chrome-95.0.4638.69/
│   ├── d8.exe
│   └── ...
└── chrome-94.0.4606.81/
    ├── d8.exe (ASAN)
    └── ...
```

### 命名规则

- 文件夹名称必须以 `chrome-` 开头
- 版本号跟在 `chrome-` 后面
- 二进制文件名为 `d8.exe` 或 `chrome.exe`（Windows）
- ASAN 版本会自动检测

---

## 8. 完整示例

### 自动化 CVE 验证流程

```python
from browser.tools.version_manager import VersionManager
from browser.agents.multi.generator import GeneratorAgent
from browser.agents.multi.verifier import VerifierAgent
from browser.tools.analysis_tools import (
    verify_patch_effectiveness,
    generate_patch_verification_report
)

# 1. 初始化
mgr = VersionManager()
generator = GeneratorAgent()
verifier = VerifierAgent()

# 2. 显示可用版本
mgr.print_summary()

# 3. 获取版本对
cve_info = {
    "cve_id": "CVE-2021-21220",
    "vulnerable_version": "95.0",
    "fixed_version": "96.0"
}

vuln, fixed = mgr.get_by_cve("CVE-2021-21220", cve_info)

if not vuln or not fixed:
    print("Required versions not found!")
    exit(1)

print(f"\nUsing versions:")
print(f"  Vulnerable: {vuln.version}")
print(f"  Fixed: {fixed.version}")

# 4. 生成 PoC
poc_result = generator.run({
    "analysis": analysis_result,
    "cve_info": cve_info
})

# 5. 验证 PoC
print("\nVerifying PoC...")
patch_report = verify_patch_effectiveness(
    vulnerable_binary=vuln.d8_path,
    fixed_binary=fixed.d8_path,
    poc_code=poc_result["code"]
)

# 6. 生成报告
report_md = generate_patch_verification_report(patch_report)

# 7. 保存结果
with open("verification_report.md", "w") as f:
    f.write(report_md)

print(f"\n{'='*70}")
print(f"Verification complete!")
print(f"  Patch effective: {patch_report.patch_effective}")
print(f"  Report saved to: verification_report.md")
print(f"{'='*70}")
```

---

## 9. BinaryVersion 数据类

### 属性

```python
@dataclass
class BinaryVersion:
    version: str              # 版本号 (e.g., "95.0.4638.69")
    d8_path: Optional[str]    # d8 二进制路径
    chrome_path: Optional[str] # Chrome 二进制路径
    asan_enabled: bool        # 是否启用 ASAN
    base_dir: str             # 版本基础目录
```

### 使用示例

```python
version = mgr.get_version("95.0")

print(f"Version: {version.version}")
print(f"d8: {version.d8_path}")
print(f"Chrome: {version.chrome_path}")
print(f"ASAN: {version.asan_enabled}")
print(f"Base dir: {version.base_dir}")

# 字符串表示
print(str(version))
# 输出: Version 95.0.4638.69 | d8: ./volumes/chrome-95.0.4638.69/d8.exe
```

---

## 10. 故障排查

### 找不到版本

**问题**: `list_versions()` 返回空列表

**解决方案**:
1. 检查目录结构是否正确
2. 确认文件夹名称以 `chrome-` 开头
3. 确认包含 `d8.exe` 或 `chrome.exe`

```python
# 检查基础目录
mgr = VersionManager("./volumes")
print(f"Base dir exists: {mgr.base_dir.exists()}")

# 手动刷新
mgr._refresh()
```

### 版本配对失败

**问题**: `get_version_pair()` 返回 `(None, None)`

**解决方案**:
1. 确认 vulnerable 版本存在
2. 检查是否有更新的版本
3. 手动指定 fixed 版本

```python
# 检查可用版本
mgr.print_summary()

# 手动指定
vuln, fixed = mgr.get_version_pair("95.0", "96.0")
```

---

## 总结

`VersionManager` 提供了完整的多版本管理能力：

- ✅ **自动发现**: 扫描目录，识别所有版本
- ✅ **灵活选择**: 多种方式选择版本
- ✅ **智能配对**: 自动找到 vulnerable/fixed 对
- ✅ **ASAN 支持**: 自动检测和筛选 ASAN 版本
- ✅ **易于集成**: 简单的 API，易于集成到验证流程

结合 `EnvironmentManager`、`VerifierAgent` 和 `analysis_tools`，现在拥有了完整的多版本验证工具链。
