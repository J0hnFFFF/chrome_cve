# Phase 2.1 - 多策略并行验证使用指南

## 功能概述

Phase 2.1 引入了多候选生成和并发验证机制，显著提升了 PoC 生成的成功率和验证效率。

### 核心改进
1. **多策略生成**: `GeneratorAgent` 现在能生成 3-5 个采用不同策略的候选 PoC
2. **并发验证**: `VerifierAgent` 使用线程池并发验证多个候选
3. **智能策略选择**: 根据漏洞类型自动选择最相关的利用策略

---

## 1. 多候选生成

### 支持的策略

| 策略名称 | 适用场景 | 特点 |
|---------|---------|------|
| **Direct Trigger** | 所有类型 | 最小化设置，直接触发漏洞 |
| **Memory Spray** | UAF, 堆溢出 | 堆喷射 + GC 控制 |
| **JIT Optimization** | 类型混淆, 边界检查消除 | 利用 JIT 优化特性 |
| **Race Condition** | 竞态条件 | 使用 Workers 或异步操作 |
| **Object Confusion** | 类型混淆, UAF | 操纵原型链和对象布局 |

### 使用示例

```python
from browser.agents.multi.generator import GeneratorAgent
from browser.plugins.base import AnalysisResult

generator = GeneratorAgent()

# 分析结果
analysis = AnalysisResult(
    vulnerability_type="type-confusion",
    component="v8",
    root_cause="Missing type check in JSCallReducer",
    trigger_conditions=["JIT optimization", "Type confusion"],
    poc_strategy="Trigger JIT compilation with type-confused objects"
)

cve_info = {"cve_id": "CVE-2021-21220"}

# 生成多个候选
candidates = generator.generate_candidates(
    analysis=analysis,
    cve_info=cve_info,
    num_candidates=3
)

# 查看结果
for i, candidate in enumerate(candidates):
    print(f"Candidate {i+1}: {candidate['strategy']}")
    print(f"  Code length: {len(candidate['code'])} chars")
```

### 输出示例

```
[Generator] Generating 3 candidate PoCs
  [Generator] ✓ Candidate 1: Template-based
  [Generator] ✓ Candidate 2: JIT Optimization
  [Generator] ✓ Candidate 3: Object Confusion
[Generator] Generated 3 candidates

Candidate 1: Template-based
  Code length: 450 chars
Candidate 2: JIT Optimization
  Code length: 520 chars
Candidate 3: Object Confusion
  Code length: 480 chars
```

---

## 2. 并发验证

### 功能说明
`verify_batch` 方法使用 `ThreadPoolExecutor` 并发验证多个候选，显著缩短总验证时间。

### 使用示例

```python
from browser.agents.multi.verifier import VerifierAgent

verifier = VerifierAgent()

# 并发验证所有候选
results = verifier.verify_batch(
    candidates=candidates,
    d8_path=r"D:\src\v8\out\Debug\d8.exe",
    max_workers=3,  # 最多 3 个并发
    timeout=30
)

# 查看结果
print(f"Total: {results['total']}")
print(f"Verified: {results['verified']}")
print(f"Crashed: {results['crashed']}")

if results['first_success']:
    best = results['first_success']
    print(f"\nBest candidate: #{best['index'] + 1}")
    print(f"  Strategy: {best['strategy']}")
    print(f"  Crash type: {best['crash_type']}")
    print(f"  Execution time: {best['execution_time']:.2f}s")
```

### 输出示例

```
[Verifier] Batch verification of 3 candidates
  [Verifier] Verifying candidate #1: Template-based
  [Verifier] Verifying candidate #2: JIT Optimization
  [Verifier] Verifying candidate #3: Object Confusion
  [Verifier] ✓ First crash found: Candidate #2 (JIT Optimization)
[Verifier] Batch verification complete:
  Total: 3
  Verified: 3
  Crashed: 1
  Best candidate: #2 (JIT Optimization)

Total: 3
Verified: 3
Crashed: 1

Best candidate: #2
  Strategy: JIT Optimization
  Crash type: heap-use-after-free
  Execution time: 2.34s
```

---

## 3. 策略选择逻辑

### 自动优先级

框架会根据漏洞类型自动选择最相关的策略：

```python
# 内部优先级映射
priority_map = {
    "type-confusion": ["JIT Optimization", "Object Confusion", "Direct Trigger"],
    "use-after-free": ["Memory Spray", "Object Confusion", "Direct Trigger"],
    "race-condition": ["Race Condition", "Direct Trigger", "Memory Spray"],
    "bounds-check": ["JIT Optimization", "Direct Trigger", "Memory Spray"],
}
```

### 示例

对于 `type-confusion` 漏洞：
1. 优先生成 **JIT Optimization** 策略的 PoC
2. 其次生成 **Object Confusion** 策略
3. 最后生成 **Direct Trigger** 策略

---

## 4. 性能对比

### 传统方式
```
生成 1 个 PoC → 验证 (30s) → 失败 → 重新生成 → 验证 (30s) → ...
总时间: 可能需要多次迭代，每次 30s+
```

### Phase 2.1 方式
```
并发生成 3 个 PoC (同时进行)
↓
并发验证 3 个 PoC (max_workers=3)
  - Candidate 1: 30s
  - Candidate 2: 25s (崩溃！)
  - Candidate 3: 28s
↓
总时间: ~30s (最慢的那个)
```

**时间节省**: 在 4 核机器上，验证 3 个候选的时间接近单个验证时间。

---

## 5. 集成到 Pipeline

虽然 Task 2.1.3 尚未完成，但您可以手动集成：

```python
# 在 Pipeline 中
analysis_result = analyzer.run(context)

# 生成多个候选
candidates = generator.generate_candidates(
    analysis=analysis_result,
    cve_info=cve_info,
    num_candidates=3
)

# 并发验证
batch_results = verifier.verify_batch(
    candidates=candidates,
    d8_path=env.d8_path,
    max_workers=3
)

# 使用第一个成功的
if batch_results['first_success']:
    best_candidate = candidates[batch_results['first_success']['index']]
    # 继续使用 best_candidate
```

---

## 6. 配置建议

### max_workers 设置

- **2 核 CPU**: `max_workers=2`
- **4 核 CPU**: `max_workers=3`
- **8 核+ CPU**: `max_workers=4`

> 不建议超过 4，因为每个验证都会启动独立的 d8/Chrome 进程。

### num_candidates 设置

- **快速验证**: `num_candidates=2`
- **平衡模式**: `num_candidates=3` (推荐)
- **高成功率**: `num_candidates=5`

---

## 7. 故障排查

### 所有候选都失败

```python
if results['all_failed']:
    # 查看每个候选的错误
    for candidate in results['candidates']:
        print(f"{candidate['strategy']}: {candidate.get('error', 'No crash')}")
```

### 验证超时

```python
# 增加超时时间
results = verifier.verify_batch(
    candidates=candidates,
    timeout=60  # 从 30s 增加到 60s
)
```

---

## 总结

Phase 2.1 通过多策略生成和并发验证，将 PoC 生成的成功率和效率提升到了新的水平：

- ✅ **成功率提升**: 3-5 个不同策略，至少一个成功的概率大幅增加
- ✅ **时间节省**: 并发验证将总时间缩短至单次验证的水平
- ✅ **智能选择**: 根据漏洞类型自动选择最相关的策略
- ✅ **易于集成**: 简单的 API，易于集成到现有流程
