# Phase 1.2 - 验证引擎精准化使用指南

## 功能概述

Phase 1.2 为 Chrome CVE 框架添加了两个关键能力：
1. **符号化堆栈** - 将内存地址转换为源码位置
2. **双端验证** - 自动对比漏洞版本和修复版本

---

## 1. 符号化堆栈

### 功能说明
将崩溃堆栈中的内存地址（如 `0x7fff12345678`）转换为可读的源码位置（如 `v8/src/compiler/typer.cc:123`）

### 前置条件
需要安装 `llvm-symbolizer`：
- **Windows**: 安装 LLVM (https://releases.llvm.org/)
- **自动检测路径**: 
  - `PATH` 环境变量
  - `C:\Program Files\LLVM\bin\llvm-symbolizer.exe`
  - `C:\Program Files (x86)\LLVM\bin\llvm-symbolizer.exe`

### 使用示例

```python
from browser.tools.debug import CrashAnalyzer, StackFrame

# 初始化分析器（自动检测 llvm-symbolizer）
analyzer = CrashAnalyzer()

# 或手动指定路径
analyzer = CrashAnalyzer(symbolizer_path=r"C:\LLVM\bin\llvm-symbolizer.exe")

# 解析崩溃报告
crash_output = """
#0 0x7fff12345678 in v8::internal::Typer::Visitor::TypeNumberAdd
#1 0x7fff12345679 in v8::internal::Typer::Visitor::Reduce
"""

report = analyzer.analyze(crash_output)

# 符号化堆栈
symbolized_frames = analyzer.symbolize_stack_trace(
    stack_trace=report.stack_trace,
    binary_path=r"D:\src\v8\out\Debug\d8.exe"
)

# 输出结果
for frame in symbolized_frames:
    print(frame)
    # 输出: #0 TypeNumberAdd at v8/src/compiler/typer.cc:1234
```

### 效果对比

**之前**:
```
#0 0x7fff12345678
#1 0x7fff12345679
```

**之后**:
```
#0 TypeNumberAdd at v8/src/compiler/typer.cc:1234
#1 Reduce at v8/src/compiler/typer.cc:567
```

---

## 2. 双端验证

### 功能说明
自动在漏洞版本和修复版本上运行 PoC，验证补丁是否有效修复了漏洞。

### 使用场景
- 确认 PoC 真实触发了漏洞（而非误报）
- 验证补丁确实修复了该漏洞
- 生成补丁有效性报告

### 使用示例

```python
from browser.agents.multi.verifier import VerifierAgent
from browser.plugins.base import PoCResult

# 初始化 Verifier
verifier = VerifierAgent()

# 准备 PoC
poc = PoCResult(
    code="""
    // V8 Type Confusion PoC
    function trigger() {
        let arr = new Uint32Array(10);
        return arr;
    }
    
    for (let i = 0; i < 10000; i++) {
        trigger();
    }
    
    %OptimizeFunctionOnNextCall(trigger);
    trigger();
    """,
    language="javascript",
    expected_behavior="Type confusion crash"
)

# 执行双端验证
result = verifier.verify_differential(
    poc=poc,
    vulnerable_binary=r"D:\chrome_versions\chrome_vulnerable\d8.exe",
    fixed_binary=r"D:\chrome_versions\chrome_fixed\d8.exe",
    timeout=30
)

# 查看结果
print(f"补丁有效性: {result['patch_effective']}")
print(f"置信度: {result['confidence']}")
print(f"分析: {result['analysis']}")

# 详细结果
print("\n漏洞版本:")
print(f"  崩溃: {result['vulnerable']['crashed']}")
print(f"  崩溃类型: {result['vulnerable']['crash_type']}")

print("\n修复版本:")
print(f"  崩溃: {result['fixed']['crashed']}")

# 符号化堆栈（如果有）
if 'symbolized_stack' in result['vulnerable']:
    print("\n符号化堆栈:")
    for frame in result['vulnerable']['symbolized_stack']:
        print(f"  {frame}")
```

### 输出示例

```
补丁有效性: True
置信度: 1.0
分析: ✅ Patch is effective: PoC crashes vulnerable version but not fixed version

漏洞版本:
  崩溃: True
  崩溃类型: heap-use-after-free

修复版本:
  崩溃: False

符号化堆栈:
  #0 TypeNumberAdd at v8/src/compiler/typer.cc:1234
  #1 Reduce at v8/src/compiler/typer.cc:567
  #2 VisitNode at v8/src/compiler/graph-reducer.cc:89
```

---

## 3. 集成到 Pipeline

### 自动符号化

在 `execution.py` 中，崩溃堆栈会自动符号化（如果 llvm-symbolizer 可用）：

```python
# 在 D8Executor 或 ChromeExecutor 中
if crashed:
    crash_report = self._crash_analyzer.analyze(stderr_str)
    
    # 自动符号化
    if crash_report.stack_trace:
        symbolized = self._crash_analyzer.symbolize_stack_trace(
            crash_report.stack_trace,
            self.d8_path  # 或 self.chrome_path
        )
        result.stack_trace = "\n".join(str(f) for f in symbolized[:10])
```

### 手动触发双端验证

在 Pipeline 中添加双端验证步骤：

```python
# 在 pipeline.py 中
if poc_result.success:
    # 获取漏洞和修复版本的二进制
    vuln_binary = self._get_vulnerable_binary(cve_info)
    fixed_binary = self._get_fixed_binary(cve_info)
    
    if vuln_binary and fixed_binary:
        diff_result = self.verifier.verify_differential(
            poc=poc_result,
            vulnerable_binary=vuln_binary,
            fixed_binary=fixed_binary
        )
        
        # 保存到结果
        self.results['differential_verification'] = diff_result
```

---

## 4. 故障排查

### llvm-symbolizer 未找到
```
⚠️  llvm-symbolizer not found, skipping symbolization
```

**解决方案**:
1. 安装 LLVM: https://releases.llvm.org/
2. 添加到 PATH: `C:\Program Files\LLVM\bin`
3. 或手动指定: `CrashAnalyzer(symbolizer_path="...")`

### 符号化失败
```
#0 ??
??:0:0
```

**可能原因**:
- 二进制文件没有调试符号
- 需要使用 ASAN 编译的版本
- 路径不正确

**解决方案**:
- 使用带符号的 Debug 版本
- 确保二进制路径正确

### 双端验证都不崩溃
```
❌ Neither version crashes - PoC may be ineffective
```

**可能原因**:
- PoC 代码有误
- 需要特定的运行条件
- 漏洞触发概率较低

**解决方案**:
- 检查 PoC 代码
- 增加 `num_runs` 重复执行
- 查看 LLM 建议

---

## 5. 最佳实践

### 1. 始终使用 ASAN 版本
```bash
# 编译 d8 with ASAN
gn gen out/Debug --args='is_debug=true is_asan=true'
ninja -C out/Debug d8
```

### 2. 保留多个版本
```
D:\chrome_versions\
  ├── chrome_vulnerable\
  │   └── d8.exe (commit: abc123)
  ├── chrome_fixed\
  │   └── d8.exe (commit: def456)
  └── chrome_latest\
      └── d8.exe (latest)
```

### 3. 自动化版本管理
使用 `WindowsBuildManager` 自动编译特定 commit 的版本。

---

## 6. 性能优化

- **符号化缓存**: llvm-symbolizer 会自动缓存结果
- **并行验证**: 双端验证是顺序执行的，未来可改为并行
- **超时设置**: 根据 PoC 复杂度调整 timeout

---

## 总结

Phase 1.2 的两个功能显著提升了验证的准确性和可信度：
- ✅ 符号化堆栈让调试更直观
- ✅ 双端验证确保补丁有效性
- ✅ 自动集成到现有流程
- ✅ 优雅降级（工具不可用时）
