# Chrome CVE Reproducer - Development TODO

## Project Vision
基于LLM的多Agent协同Chrome CVE复现框架，实现从CVE公告到PoC复现的完整自动化流程。

---

## Phase 0: 基础重构

### 0.1 项目结构调整
- [x] 整理现有代码，确定保留/移除的组件 ✅
- [x] 创建新的目录结构 ✅

#### 代码分析结果

**保留组件（核心价值）**:

| 模块 | 文件 | 用途 | 迁移方式 |
|------|------|------|----------|
| agentlib/agents | agent.py | Agent基类、LLMFunction、TokenUsage | 直接复用 |
| agentlib/agents | planning.py | AgentPlan、PlanExecutor、Critic | 直接复用 |
| agentlib/agents | critic.py | Critic评审 | 直接复用 |
| agentlib/common | base.py, parsers.py, store.py | 基础设施 | 直接复用 |
| agentlib/tools | tool_wrapper.py, common_tools.py | 工具封装 | 直接复用 |
| browser/data | cve_processor.py | NVD/Gitiles集成 | 迁移到intel/ |
| browser/knowledge | 8个组件知识库 | V8/Blink等知识 | 迁移到memory/ |
| browser/agents | base.py | XMLOutputParser | 整合到agents/ |
| browser/tools | chromium_tools.py, chrome_tools.py | 浏览器工具 | 保留在tools/ |
| browser/prompts | *.j2模板 | Agent提示词 | 保留 |

**移除/重构组件**:

| 模块 | 原因 |
|------|------|
| agentlib/web_console.py | 不需要Web控制台 |
| agentlib/web_guy.py | 不需要Web自动化 |
| agentlib/static/ | 不需要静态文件 |
| agentlib/examples/ | 移到docs作为参考 |
| browser/services/ | CodeQL/Ghidra待后续实现 |

**新目录结构**:
```
src/browser/
├── agents/          # 多Agent系统 (保留现有)
├── plugins/         # 插件系统 ✅ NEW
│   ├── __init__.py
│   ├── base.py      # PluginBase, AnalyzerPlugin, GeneratorPlugin, VerifierPlugin
│   ├── registry.py  # PluginRegistry
│   └── dynamic.py   # DynamicPluginGenerator
├── memory/          # 记忆系统 ✅ NEW
│   ├── __init__.py
│   ├── episode.py   # EpisodeMemory, CVECase
│   ├── semantic.py  # SemanticMemory, ComponentKnowledge
│   └── learning.py  # LearningEngine
├── intel/           # 情报收集 ✅ NEW
│   ├── __init__.py
│   ├── base.py      # IntelSource, IntelResult
│   ├── sources.py   # NVDSource, GitilesSource, etc.
│   ├── collector.py # IntelCollector
│   └── fusion.py    # IntelFusion
├── models/          # 数据模型 ✅ NEW
│   ├── __init__.py
│   ├── cve.py       # CVEInfo, PatchInfo
│   ├── analysis.py  # AnalysisResult, VulnerabilityType
│   ├── poc.py       # PoCResult, PoCType
│   ├── verify.py    # VerifyResult, CrashInfo
│   └── message.py   # Message, MessageType
├── config/          # 配置管理 ✅ NEW
│   ├── __init__.py
│   ├── loader.py    # ConfigLoader
│   └── settings.py  # Settings, LLMConfig, etc.
├── tools/           # 工具层 (保留现有)
├── prompts/         # 提示模板 (保留现有)
└── knowledge/       # 组件知识 (保留现有,后续迁移到memory)
```
- [x] 迁移现有可复用代码（agentlib核心直接复用，创建了新模块） ✅

### 0.2 配置系统
- [x] 设计统一配置文件格式（YAML）✅ → config.yaml.example
- [x] 实现配置加载器 ✅ → config/loader.py
- [x] 定义可配置项：重试次数、超时时间、API密钥等 ✅ → config/settings.py

---

## Phase 1: 核心系统 ✅ COMPLETED

### 1.1 插件系统 ✅
- [x] 定义PluginBase抽象基类 → `plugins/base.py`
  - [x] AnalyzerPlugin：分析补丁 → AnalysisResult
  - [x] GeneratorPlugin：生成PoC → PoCResult
  - [x] VerifierPlugin：验证PoC → VerifyResult
- [x] 实现插件注册器（PluginRegistry）→ `plugins/registry.py`
- [x] 实现插件匹配器（根据component/vuln_type匹配）
- [x] 实现动态插件生成器（DynamicPluginGenerator）→ `plugins/dynamic.py`
- [x] 内置插件实现：
  - V8AnalyzerPlugin, BlinkAnalyzerPlugin, GenericAnalyzerPlugin
  - JavaScriptGeneratorPlugin, HTMLGeneratorPlugin
  - ChromeVerifierPlugin, D8VerifierPlugin

### 1.2 记忆系统 ✅
- [x] 案例库（Episode Memory）→ `memory/episode.py`
  - [x] 定义CVECase数据结构
  - [x] 实现案例存储与检索
  - [x] 相似案例匹配
- [x] 知识库（Semantic Memory）→ `memory/semantic.py`
  - [x] 组件知识存储
  - [x] 漏洞类型知识
  - [x] 成功插件存储
- [x] 再学习机制 → `memory/learning.py`
  - [x] 成功案例提取经验
  - [x] 失败案例记录教训

### 1.3 多Agent协同 ✅
- [x] Agent定义 → `agents/multi/`
  - [x] OrchestratorAgent：任务编排、流程控制
  - [x] AnalyzerAgent：补丁分析、根因定位
  - [x] GeneratorAgent：PoC生成、迭代优化
  - [x] VerifierAgent：PoC验证、崩溃检测
  - [x] CriticAgent：结果评审、反思改进
- [x] 消息传递机制 → `agents/multi/base.py`
  - [x] 定义AgentMessage数据结构
  - [x] 实现消息路由
- [x] 反思循环
  - [x] Critic评审每个阶段输出
  - [x] 失败时触发反思和重试
  - [x] 可配置最大重试次数

### 1.4 情报收集系统 ✅
- [x] IntelSource基类定义 → `intel/base.py`
- [x] Tier 1 必须情报源 → `intel/sources.py`
  - [x] NVDSource：获取CVE描述、CVSS、CWE
  - [x] GitilesSource：获取补丁diff、相关文件
  - [x] ChromeReleaseSource：版本映射关系
- [x] Tier 2 重要情报源
  - [x] ChromiumBugTrackerSource：issue详情
  - [x] GitHubPoCSource：已有PoC搜索
  - [x] CISAKEVSource：已知利用确认
- [x] 情报融合器（IntelFusion）→ `intel/fusion.py`
- [x] 版本映射 → `intel/version.py`
  - [x] ChromeVersionMapper
  - [x] ChromeDownloader

### 新增：Pipeline入口 ✅
- [x] CVEReproductionPipeline → `pipeline.py`
  - 整合所有组件的新主入口

---

## Phase 2: 功能完善 ✅ COMPLETED

### 2.1 版本管理 ✅
- [x] ChromeVersionMapper → `intel/version.py`
  - [x] 版本号 → Chromium position映射
  - [x] 版本号 → Git commit映射
  - [x] 获取漏洞影响版本范围
- [x] ChromeDownloader → `intel/version.py`
  - [x] 自动下载指定版本Chrome
  - [x] 支持多平台（Windows/Linux/Mac）
  - [x] 缓存已下载版本
- [x] 多版本测试 → `tools/execution.py`
  - [x] MultiVersionTester
  - [x] 漏洞版本验证
  - [x] 修复版本确认

### 2.2 工具层完善 ✅
- [x] Intel工具 → `intel/sources.py`
  - [x] NVD API客户端 (NVDSource)
  - [x] Gitiles API客户端 (GitilesSource)
  - [x] GitHub Search API客户端 (GitHubPoCSource)
- [x] Execution工具 → `tools/execution.py`
  - [x] D8Executor（V8漏洞）
  - [x] ChromeExecutor（渲染器漏洞）
  - [x] ExecutionResult 数据结构
- [x] Debug工具 → `tools/debug.py`
  - [x] ASANParser - ASAN日志解析器
  - [x] StackTraceParser - 崩溃堆栈分析器
  - [x] CrashAnalyzer - 综合崩溃分析

### 2.3 内置插件 ✅ (Phase 1已完成)
- [x] V8AnalyzerPlugin → `plugins/analyzers/v8_analyzer.py`
- [x] BlinkAnalyzerPlugin → `plugins/analyzers/blink_analyzer.py`
- [x] GenericAnalyzerPlugin → `plugins/analyzers/generic_analyzer.py`
- [x] JavaScriptGeneratorPlugin → `plugins/generators/js_generator.py`
- [x] HTMLGeneratorPlugin → `plugins/generators/html_generator.py`

---

## Phase 3: 优化增强 ✅ COMPLETED

### 3.1 Pipeline优化 ✅
- [x] 主流程实现（main.py）→ 增强版 main.py
  - [x] 命令行参数解析 (argparse with rich options)
  - [x] 配置加载 (config.yaml support)
  - [x] Pipeline执行 (multi-agent/legacy modes)
  - [x] 结果输出 (colored console output)
- [x] 错误处理与恢复 (try-catch with fallback)
- [x] 进度展示与日志 (ProgressDisplay, ColoredFormatter)

### 3.2 知识库增强 ✅
- [x] 迁移现有knowledge到新结构 → `memory/knowledge_loader.py`
  - [x] KnowledgeLoader 桥接现有知识文件
  - [x] initialize_knowledge() 自动加载
- [x] 添加漏洞类型模板
  - [x] type-confusion
  - [x] use-after-free
  - [x] heap-buffer-overflow
  - [x] integer-overflow
  - [x] oob-read-write
  - [x] race-condition

### 3.3 文档完善 ✅
- [x] 更新CLAUDE.md → 完整架构文档
  - [x] 项目结构
  - [x] 架构图
  - [x] Pipeline流程
  - [x] CLI选项
  - [x] 插件开发指南
  - [x] Memory系统使用
  - [x] 配置说明

---

## Data Models

### 核心数据结构
```python
@dataclass
class CVEInfo:
    cve_id: str
    description: str
    cvss_score: float
    cwe_id: str
    affected_versions: List[str]
    fixed_version: str
    patch_commits: List[str]
    component: str  # v8, blink, skia, etc.

@dataclass
class AnalysisResult:
    vulnerability_type: str
    component: str
    root_cause: str
    trigger_conditions: List[str]
    trigger_approach: str
    poc_strategy: str
    confidence: float

@dataclass
class PoCResult:
    code: str
    language: str  # javascript, html
    target_version: str
    expected_behavior: str

@dataclass
class VerifyResult:
    success: bool
    crash_type: str
    crash_address: str
    stack_trace: str
    asan_report: str
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Orchestrator Agent                    │
│              (任务编排、流程控制、状态管理)                │
└─────────────────────┬───────────────────────────────────┘
                      │ Message
        ┌─────────────┼─────────────┬─────────────┐
        ▼             ▼             ▼             ▼
┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
│ Analyzer  │  │ Generator │  │ Verifier  │  │  Critic   │
│   Agent   │  │   Agent   │  │   Agent   │  │   Agent   │
└─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
      │              │              │              │
      ▼              ▼              ▼              ▼
┌─────────────────────────────────────────────────────────┐
│                    Plugin System                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │ Analyzer │  │Generator │  │ Verifier │  + Dynamic    │
│  │ Plugins  │  │ Plugins  │  │ Plugins  │    Plugins    │
│  └──────────┘  └──────────┘  └──────────┘               │
└─────────────────────────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
┌───────────┐  ┌───────────┐  ┌───────────┐
│   Intel   │  │  Memory   │  │   Tools   │
│  System   │  │  System   │  │   Layer   │
└───────────┘  └───────────┘  └───────────┘
```

---

## Phase 4: 代码清理 ✅ COMPLETED

### 4.1 删除遗留代码 ✅
- [x] 删除遗留Agent文件
  - `agents/patch_analyzer.py` - 已删除
  - `agents/poc_generator.py` - 已删除
  - `agents/crash_verifier.py` - 已删除
- [x] 删除孤立提示词模板
  - `prompts/patch_analyzer/` - 已删除
  - `prompts/poc_generator/` - 已删除
  - `prompts/crash_verifier/` - 已删除

### 4.2 合并重复功能 ✅
- [x] 统一崩溃分析
  - `execution.py` 现在使用 `debug.py` 的 `CrashAnalyzer`
  - 删除了 D8Executor 和 ChromeExecutor 中重复的 `_extract_*` 方法

### 4.3 简化入口 ✅
- [x] 移除 legacy 模式
  - `main.py` 只保留 multi-agent pipeline
  - 删除 `--mode` 命令行参数
  - 更新 `PipelineRunner` 类

### 4.4 更新导出 ✅
- [x] 更新 `agents/__init__.py`
  - 移除遗留 Agent 导出
  - 保留 multi-agent 系统导出

---

## Phase 5: LLM集成 ✅ COMPLETED

### 5.1 LLMService共享服务 ✅
- [x] 创建 `services/llm_service.py`
  - LLMService: 统一LLM服务入口
  - LLMSession: 会话管理，支持多轮对话
  - OpenAIBackend: OpenAI API支持
  - AnthropicBackend: Anthropic API支持
- [x] 实现核心功能:
  - `chat()`: 单轮对话
  - `chat_with_tools()`: 带工具调用的对话
  - `react_loop()`: ReAct模式执行
  - `digest_knowledge()`: 知识消化多轮对话
- [x] 更新 `services/__init__.py` 导出

### 5.2 Agent LLM集成 ✅
- [x] 更新 `agents/multi/base.py`
  - 添加 `set_llm_service()` 方法
  - 添加 `_create_session()` 方法
  - 添加 `_llm_chat()` 方法
  - 添加 `_llm_digest_knowledge()` 方法
  - 添加 `system_prompt_file` 属性
- [x] 更新 AnalyzerAgent
  - LLM分析补丁 + 知识消化
  - 工具调用获取更多上下文
- [x] 更新 GeneratorAgent
  - LLM生成PoC + 相似案例参考
  - `refine()` 方法支持迭代优化
- [x] 更新 VerifierAgent
  - LLM分析崩溃结果
  - 生成改进建议
- [x] 更新 CriticAgent
  - LLM智能评审
  - 提供结构化反馈

### 5.3 Orchestrator增强 ✅
- [x] LLM服务传播到所有子Agent
- [x] `_run_stage_with_retry()`: 基于Critic反馈的重试机制
- [x] `_learn_from_result()`: 失败/成功学习
- [x] 集成 EpisodeMemory 存储案例
- [x] 集成 LearningEngine 学习经验

### 5.4 Agent提示词 ✅
- [x] 创建 `prompts/multi/` 目录
- [x] `analyzer_system.txt`: 分析Agent系统提示
- [x] `generator_system.txt`: 生成Agent系统提示
- [x] `verifier_system.txt`: 验证Agent系统提示
- [x] `critic_system.txt`: 评审Agent系统提示

---

## LLM Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      LLMService                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ OpenAI     │  │  Anthropic  │  │  (Future)   │         │
│  │ Backend    │  │  Backend    │  │  Backends   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                              │
│  Features:                                                   │
│  - Multi-turn dialogue                                       │
│  - Tool calling (ReAct pattern)                             │
│  - Knowledge digestion                                       │
│  - Session management                                        │
└──────────────────────┬──────────────────────────────────────┘
                       │ set_llm_service()
         ┌─────────────┼─────────────┬─────────────┐
         ▼             ▼             ▼             ▼
   ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐
   │ Analyzer  │ │ Generator │ │ Verifier  │ │  Critic   │
   │   Agent   │ │   Agent   │ │   Agent   │ │   Agent   │
   │           │ │           │ │           │ │           │
   │ - analyze │ │ - generate│ │ - verify  │ │ - review  │
   │ - digest  │ │ - refine  │ │ - analyze │ │ - suggest │
   │   knowledge│ │           │ │   crash   │ │           │
   └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘
         │             │             │             │
         └─────────────┴─────────────┴─────────────┘
                       │
              ┌────────┴────────┐
              ▼                 ▼
        ┌───────────┐    ┌───────────┐
        │  Memory   │    │ Learning  │
        │  System   │    │  Engine   │
        │           │    │           │
        │ - Episode │    │ - Success │
        │ - Semantic│    │ - Failure │
        └───────────┘    └───────────┘
```

---

## Notes

- 优先实现核心功能，避免过度设计
- 插件系统是扩展性关键，需仔细设计Base接口
- 记忆系统支持经验复用和持续学习
- 多Agent协同通过消息传递，保持松耦合
- 情报收集分层，必须源优先，可选源增强
- LLM集成采用A+C混合方案：Agent层使用LLMService共享服务
