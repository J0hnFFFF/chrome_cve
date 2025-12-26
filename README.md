# Chrome CVE 复现框架

一个基于大语言模型的先进多智能体系统，用于自动化分析 Chrome/Chromium 漏洞并进行复现。该框架智能地分析补丁，理解漏洞，并通过协作式 AI 智能体生成工作漏洞概念验证（PoC）。

## 🚀 概述

Chrome CVE 复现框架是一个复杂的多智能体系统，利用大语言模型（LLM）自动分析 Chrome/Chromium 漏洞并生成工作漏洞利用。该系统具备以下特性：

- **多智能体协作**：专业智能体（分析器、生成器、验证器、批评器）具有反思循环
- **插件架构**：可扩展插件，支持 LLM 动态生成
- **记忆系统**：通过事件记忆和语义知识实现经验复用
- **智能情报收集**：从 NVD、Gitiles、GitHub 和其他来源进行多源收集
- **组件知识库**：深度了解 V8、Blink、Skia、WebGL 和其他 Chrome 组件

## 🏗️ 架构

```
                    ┌─────────────────────────────────────────┐
                    │          协调器智能体                     │
                    │      (任务协调，状态管理)                │
                    └──────────────────┬──────────────────────┘
                                       │ 智能体消息
           ┌───────────────┬───────────┼───────────┬───────────────┐
           ▼               ▼           ▼           ▼               ▼
    ┌────────────┐  ┌────────────┐ ┌────────────┐ ┌────────────┐
    │   分析器   │  │   生成器   │ │   验证器   │ │   批评器   │
    │   智能体   │  │   智能体   │ │   智能体   │ │   智能体   │
    └─────┬──────┘  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘
          │               │              │              │
          ▼               ▼              ▼              ▼
    ┌─────────────────────────────────────────────────────────────┐
    │                      插件系统                                │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
    │  │   分析器     │  │   生成器     │  │   验证器     │      │
    │  │   插件       │  │   插件       │  │   插件       │      │
    └─────────────────────────────────────────────────────────────┘
                    │               │               │
           ┌────────┴───────┬───────┴───────┬───────┴────────┐
           ▼                ▼               ▼                ▼
    ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐
    │   情报     │   │   记忆     │   │   工具     │   │   知识     │
    │   系统     │   │   系统     │   │   层       │   │   库       │
    └────────────┘   └────────────┘   └────────────┘   └────────────┘
```

## 🛠️ 特性

- **智能补丁分析**：从代码补丁中理解漏洞根本原因
- **动态 PoC 生成**：根据漏洞分析创建工作漏洞利用
- **崩溃验证**：执行 PoC 并验证崩溃复现性
- **跨平台支持**：支持 Chrome、d8（V8 shell）和各种环境
- **可扩展架构**：轻松添加新的分析器、生成器和验证器插件
- **学习系统**：存储成功案例以供将来参考和改进

## 📋 先决条件

- Python 3.9+
- LLM API 访问权限（OpenAI、Anthropic 或自定义端点）
- Docker（用于容器化执行）

## 🚀 快速开始

1. **安装智能体库**：
   ```bash
   cd src/agentlib && pip install -e .
   ```

2. **创建配置文件**：
   ```bash
   cp src/browser/config.yaml.example src/browser/config.yaml
   # 编辑 config.yaml 以添加您的 API 密钥和路径
   ```

3. **运行 CVE 复现流水线**：
   ```bash
   cd src/browser
   python main.py --cve CVE-2024-XXXX
   ```

## ⚙️ 配置

基于示例创建 `config.yaml` 文件。关键配置选项包括：

```yaml
general:
  output_dir: "./output"
  log_level: "INFO"

llm:
  default_model: "gpt-4o"
  temperature: 0.0
  openai_api_key: "your-api-key"  # 或设置 OPENAI_API_KEY 环境变量
  openai_base_url: ""             # 如需要，自定义端点

intel:
  nvd_api_key: "your-nvd-key"     # 用于 CVE 信息
  github_token: "your-github-token" # 用于 GitHub 访问

execution:
  chrome_path: "/path/to/chrome"  # Chrome 可执行文件路径
  d8_path: "/path/to/d8"          # d8 shell 路径
  timeout: 60
```

## 📁 项目结构

```
src/browser/
├── main.py                      # CLI 入口点
├── pipeline.py                  # 多智能体流水线协调器
├── agents/                      # 智能体系统
│   ├── multi/                   # 多智能体系统
│   │   ├── orchestrator.py      # 协调器智能体 - 任务协调
│   │   ├── analyzer.py          # 分析器智能体 - 补丁分析
│   │   ├── generator.py         # 生成器智能体 - PoC 生成
│   │   ├── verifier.py          # 验证器智能体 - 崩溃验证
│   │   └── critic.py            # 批评器智能体 - 审查和反思
├── plugins/                     # 插件系统
│   ├── analyzers/               # 内置分析器插件
│   ├── generators/              # 内置生成器插件
│   └── verifiers/               # 内置验证器插件
├── memory/                      # 记忆系统
│   ├── episode.py               # 事件记忆 - CVE 案例存储
│   └── semantic.py              # 语义记忆 - 知识存储
├── intel/                       # 情报收集
│   ├── collector.py             # 多源收集
│   └── sources.py               # 各种情报源
├── tools/                       # 工具层
│   ├── chromium_tools.py        # Gitiles API，代码搜索
│   └── chrome_tools.py          # Chrome 下载，执行
├── knowledge/                   # 组件知识库
│   ├── v8_knowledge.py          # V8/JavaScript 引擎
│   ├── blink_knowledge.py       # Blink 渲染器
│   └── ...                      # 其他组件
└── prompts/                     # Jinja2 提示模板
```

## 🧠 多智能体系统

该框架使用多个专业智能体协同工作：

### 分析器智能体
- 分析补丁以理解漏洞根本原因
- 识别漏洞类型和触发条件
- 利用组件知识库进行深度分析

### 生成器智能体
- 根据分析创建概念验证漏洞利用
- 使用模板和记忆中的类似案例
- 根据反馈迭代改进 PoC

### 验证器智能体
- 在 Chrome 或 d8 环境中执行 PoC
- 检测崩溃和 ASAN 报告
- 测试漏洞复现性

### 批评器智能体
- 审查其他智能体的输出
- 提供反馈和修正
- 确保质量和准确性

## 🔌 插件架构

该系统具有灵活的插件架构：

```python
# 示例自定义分析器插件
from browser.plugins.base import AnalyzerPlugin

class MyAnalyzer(AnalyzerPlugin):
    NAME = "my-analyzer"
    SUPPORTED_COMPONENTS = ["my-component"]
    SUPPORTED_VULN_TYPES = ["type-confusion"]

    def analyze(self, cve_info, patches, context):
        # 分析补丁
        return AnalysisResult(
            vulnerability_type="type-confusion",
            root_cause="...",
            poc_strategy="..."
        )
```

## 🧠 记忆系统

该框架包含一个复杂的记忆系统：

- **事件记忆**：存储成功的 CVE 复现案例
- **语义记忆**：维护组件知识和漏洞模式
- **学习引擎**：从过去案例中提取成功策略

## 📊 输出文件

运行后，检查 `./output/<CVE-ID>/`：
- `cve_info.json` - 收集的 CVE 信息
- `cve_knowledge.md` - 为 LLM 格式化的知识
- `vulnerability_analysis.json` - 分析结果
- `poc.js` 或 `poc.html` - 生成的 PoC
- `verification.json` - 验证结果
- `results.json` - 完整流水线结果
- `pipeline.log` - 执行日志（使用 --debug 时）

## 🛠️ CLI 选项

```bash
python main.py --cve CVE-2024-XXXX [OPTIONS]

选项:
  --config PATH                自定义配置文件
  --output PATH                输出目录
  --chrome-path PATH           Chrome 可执行文件路径
  --d8-path PATH               d8 可执行文件路径
  --verbose, -v                详细输出
  --debug                      调试日志
  --model MODEL                覆盖 LLM 模型
```

## 🐳 Docker 支持

该框架包含 Docker 支持：

```bash
# 构建容器
docker build -t chrome-cve-reproducer .

# 使用您的配置运行
docker run -v $(pwd)/output:/output chrome-cve-reproducer \
  python main.py --cve CVE-2024-XXXX
```

## 🤝 贡献

1. Fork 仓库
2. 创建功能分支
3. 进行更改
4. 如适用，添加测试
5. 提交拉取请求

## 📄 许可证

该项目根据仓库中指定的条款获得许可。

## 🆘 支持

如需支持，请在 GitHub 仓库中提交问题。