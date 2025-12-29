# Phase 4.1.3 - 源码预览功能使用指南

## 功能概述

任务 4.1.3 为专家评审系统添加了强大的源码预览功能，允许专家在评审过程中直接查看 Chromium 源文件，并通过交互式堆栈跟踪浏览器快速定位问题代码。

### 核心功能
1. **源文件查看器**: 获取并显示任意 Chromium 源文件
2. **行号高亮**: 自动高亮目标行并显示上下文
3. **堆栈跟踪浏览**: 交互式浏览崩溃堆栈，点击查看源码
4. **语法高亮**: C++ 代码的 Monokai 主题高亮

---

## 1. 源文件查看器

### 基本用法

```python
from browser.review.expert_review import ExpertReviewCLI

cli = ExpertReviewCLI()

# 查看源文件（显示前 50 行）
cli.view_source("v8/src/compiler/js-call-reducer.cc")

# 查看特定行（带上下文）
cli.view_source(
    file_path="v8/src/compiler/js-call-reducer.cc",
    line_number=456,
    context_lines=10  # 前后各 10 行
)
```

### 输出示例（Rich 模式）

```
Fetching source: v8/src/compiler/js-call-reducer.cc

╔══════════════════════════════════════════════════════════════════╗
║ v8/src/compiler/js-call-reducer.cc @ Line 456                   ║
╠══════════════════════════════════════════════════════════════════╣
║ 446 │   Node* receiver = NodeProperties::GetValueInput(node, 1);║
║ 447 │   Node* effect = NodeProperties::GetEffectInput(node);    ║
║ 448 │   Node* control = NodeProperties::GetControlInput(node);  ║
║ 449 │                                                            ║
║ 450 │   // Check if we can optimize this call                   ║
║ 451 │   if (!CanOptimizeJSCall(node)) {                         ║
║ 452 │     return NoChange();                                    ║
║ 453 │   }                                                        ║
║ 454 │                                                            ║
║ 455 │   // Type check missing here - VULNERABILITY!             ║
║ 456 │   Node* result = graph()->NewNode(                        ║  ← 高亮
║ 457 │       simplified()->LoadField(access), receiver,          ║
║ 458 │       effect, control);                                   ║
║ 459 │                                                            ║
║ 460 │   ReplaceWithValue(node, result, effect, control);        ║
║ 461 │   return Replace(result);                                 ║
║ 462 │ }                                                          ║
╚══════════════════════════════════════════════════════════════════╝

Showing lines 446-466 of 1523
```

### 输出示例（纯文本模式）

```
Fetching source: v8/src/compiler/js-call-reducer.cc

v8/src/compiler/js-call-reducer.cc @ Line 456
----------------------------------------------------------------------
    446 |   Node* receiver = NodeProperties::GetValueInput(node, 1);
    447 |   Node* effect = NodeProperties::GetEffectInput(node);
    448 |   Node* control = NodeProperties::GetControlInput(node);
    449 |
    450 |   // Check if we can optimize this call
    451 |   if (!CanOptimizeJSCall(node)) {
    452 |     return NoChange();
    453 |   }
    454 |
    455 |   // Type check missing here - VULNERABILITY!
>>>  456 |   Node* result = graph()->NewNode(
    457 |       simplified()->LoadField(access), receiver,
    458 |       effect, control);
    459 |
    460 |   ReplaceWithValue(node, result, effect, control);
    461 |   return Replace(result);
    462 | }
----------------------------------------------------------------------
Showing lines 446-466 of 1523
```

---

## 2. 交互式堆栈跟踪浏览器

### 基本用法

```python
# 假设从崩溃报告中提取了堆栈跟踪
stack_trace = [
    {
        "function": "v8::internal::JSCallReducer::ReduceJSCall",
        "file": "v8/src/compiler/js-call-reducer.cc",
        "line": 456
    },
    {
        "function": "v8::internal::GraphReducer::Reduce",
        "file": "v8/src/compiler/graph-reducer.cc",
        "line": 234
    },
    {
        "function": "v8::internal::PipelineImpl::OptimizeGraph",
        "file": "v8/src/compiler/pipeline.cc",
        "line": 1789
    }
]

# 启动交互式浏览器
cli.view_stack_trace_source(stack_trace)
```

### 交互流程

```
                        Stack Trace                        
╭───┬──────────────────────────────────┬─────────────────────┬──────╮
│ # │ Function                         │ File                │ Line │
├───┼──────────────────────────────────┼─────────────────────┼──────┤
│ 0 │ JSCallReducer::ReduceJSCall      │ js-call-reducer.cc  │  456 │
│ 1 │ GraphReducer::Reduce             │ graph-reducer.cc    │  234 │
│ 2 │ PipelineImpl::OptimizeGraph      │ pipeline.cc         │ 1789 │
╰───┴──────────────────────────────────┴─────────────────────┴──────╯

Enter frame number to view source, or 'q' to quit (q): 0

[显示 frame 0 的源码...]

Enter frame number to view source, or 'q' to quit (q): 1

[显示 frame 1 的源码...]

Enter frame number to view source, or 'q' to quit (q): q
```

---

## 3. 集成到评审工作流

### 在 VerifierAgent 中使用

```python
from browser.agents.multi.verifier import VerifierAgent
from browser.review.expert_review import ExpertReviewCLI

verifier = VerifierAgent()
cli = ExpertReviewCLI()

# 验证 PoC
result = verifier.run({
    "poc": poc_code,
    "d8_path": d8_path
})

# 如果崩溃，查看堆栈
if result.get("crash_detected"):
    crash_report = result.get("crash_report")
    
    # 提取堆栈跟踪（假设已符号化）
    if crash_report and crash_report.stack_trace:
        cli.view_stack_trace_source(crash_report.stack_trace)
```

### 在专家评审中使用

```python
# 评审时提供源码查看选项
metadata = {
    "analysis": analysis_result,
    "verification": verification_result,
    "patch_files": [
        "v8/src/compiler/js-call-reducer.cc",
        "v8/src/compiler/js-call-reducer.h"
    ]
}

result = cli.request_review(
    poc_code=poc_code,
    cve_id=cve_id,
    metadata=metadata
)

# 专家可以在评审过程中按 'V' 查看源码
# （需要在 _request_review_rich 中添加此选项）
```

---

## 4. 高级功能

### 自定义上下文行数

```python
# 显示更多上下文（前后各 20 行）
cli.view_source(
    "v8/src/compiler/js-call-reducer.cc",
    line_number=456,
    context_lines=20
)

# 显示更少上下文（前后各 5 行）
cli.view_source(
    "v8/src/compiler/js-call-reducer.cc",
    line_number=456,
    context_lines=5
)
```

### 查看整个文件

```python
# 不指定 line_number，显示前 50 行
cli.view_source("v8/src/compiler/js-call-reducer.cc")
```

### 批量查看补丁文件

```python
patch_files = [
    "v8/src/compiler/js-call-reducer.cc",
    "v8/src/compiler/js-call-reducer.h",
    "v8/test/mjsunit/regress/regress-crbug-1234567.js"
]

for file_path in patch_files:
    print(f"\n{'='*70}")
    print(f"Viewing: {file_path}")
    print('='*70)
    cli.view_source(file_path)
```

---

## 5. 与其他工具集成

### 与 Phase 1.2 符号化工具集成

```python
from browser.tools.debug import CrashAnalyzer

analyzer = CrashAnalyzer()

# 分析崩溃
crash_report = analyzer.analyze(asan_output)

# 如果有符号化的堆栈
if crash_report.stack_trace:
    cli.view_stack_trace_source(crash_report.stack_trace)
```

### 与 Phase 2.2 代码搜索集成

```python
from browser.tools.chromium_tools import search_chromium_code

# 搜索相关代码
results = search_chromium_code("JSCallReducer::ReduceJSCall")

# 解析搜索结果，提取文件和行号
# 然后查看源码
cli.view_source("v8/src/compiler/js-call-reducer.cc", line_number=456)
```

---

## 6. 实际使用场景

### 场景 1: 分析崩溃堆栈

```python
# 1. 验证 PoC，获取崩溃
result = verifier.run({"poc": poc_code, "d8_path": d8_path})

# 2. 提取堆栈跟踪
stack_trace = result["crash_report"].stack_trace

# 3. 交互式浏览堆栈
cli.view_stack_trace_source(stack_trace)

# 4. 专家选择 frame 0，查看崩溃点源码
# 5. 专家选择 frame 1，查看调用者源码
# 6. 确认漏洞触发路径
```

### 场景 2: 对比补丁和 PoC

```python
# 1. 查看补丁修改的文件
patch_file = "v8/src/compiler/js-call-reducer.cc"
patch_line = 456

cli.view_source(patch_file, patch_line)

# 2. 专家查看源码，理解补丁修复了什么
# 3. 对比 PoC 是否正确触发了修复前的漏洞
```

### 场景 3: 验证 PoC 正确性

```python
# 1. 生成 PoC
poc = generator.run({"analysis": analysis, "cve_info": cve_info})

# 2. 专家评审
result = cli.request_review(poc["code"], cve_id, metadata={
    "analysis": analysis,
    "patch_files": analysis.get("affected_files", [])
})

# 3. 如果专家选择查看源码
if result.action == "view_source":
    for file_path in metadata["patch_files"]:
        cli.view_source(file_path)
```

---

## 7. 配置与优化

### 本地仓库优先

源码查看器会自动使用 `chromium_tools.fetch_chromium_file`，该工具优先使用本地仓库：

```bash
# 设置本地 Chromium 仓库（推荐）
git clone https://chromium.googlesource.com/chromium/src d:\src\chromium\src
```

### 语法高亮主题

当前使用 Monokai 主题。可以修改 `view_source` 方法中的 `theme` 参数：

```python
syntax = Syntax(
    content,
    "cpp",
    theme="github-dark",  # 或 "vim", "emacs", "vs" 等
    line_numbers=True
)
```

---

## 8. 故障排查

### 源文件获取失败

**问题**: `Error: Failed to fetch file`

**解决方案**:
1. 检查文件路径是否正确（区分大小写）
2. 确认本地仓库是否存在（如果使用本地模式）
3. 检查网络连接（如果使用 Web 模式）

### 堆栈跟踪无源码信息

**问题**: `No source location available for this frame`

**解决方案**:
1. 确保使用了 Phase 1.2 的符号化工具
2. 检查 `stack_trace` 中是否包含 `file` 和 `line` 字段
3. 验证符号文件是否正确

### Rich 库不可用

**问题**: 显示为纯文本模式

**解决方案**:
```bash
pip install rich
```

---

## 总结

Phase 4.1.3 的源码预览功能为专家提供了强大的调试能力：

- ✅ **快速定位**: 从堆栈跟踪直接跳转到源码
- ✅ **上下文理解**: 显示目标行的前后代码
- ✅ **语法高亮**: C++ 代码的专业级高亮
- ✅ **交互式浏览**: 在堆栈帧之间自由切换
- ✅ **优雅降级**: 无 Rich 时仍然可用

结合 Phase 1.2 的符号化和 Phase 2.2 的代码搜索，专家现在拥有了完整的源码分析工具链。
