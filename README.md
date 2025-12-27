# Chrome CVE 复现框架

一个基于大语言模型的先进多智能体系统，用于自动化分析 Chrome/Chromium 漏洞并进行复现。该框架智能地分析补丁，理解漏洞，并通过协作式 AI 智能体生成漏洞概念验证（PoC）。

## 🚀 概述

Chrome CVE 复现框架利用大语言模型（LLM）自动分析 Chrome/Chromium 漏洞。该系统不仅仅是简单的分析工具，它具备**混合工作流（Hybrid Workflow）**能力，既能快速利用预编译二进制验证，也能在需要时自动回退到本地全量编译。

## 🛠️ 主要特性

- **混合工作流 (New)**：智能决策引擎。优先尝试下载官方预编译二进制（快），失败或需要深度调试时自动触发本地编译（慢但强）。
- **Windows 原生编译 (New)**：内置 PowerShell 自动化脚本，支持在 Windows 上全自动配置 `depot_tools`、拉取特定版本代码并编译带有 ASAN 的 `d8`。
- **智能情报收集**：从 NVD、Gitiles 等多源收集漏洞信息。
- **多智能体协作**：分析器、生成器、验证器和批评器协同工作。
- **深度排错**：支持 AddressSanitizer (ASAN) 堆栈分析。

## � 系统要求

- **操作系统**: Windows 10/11 (x64)
- **Python**: 3.9+
- **构建环境 (仅本地编译模式需要)**:
  - Visual Studio 2022 (Desktop C++, MFC, Windows SDK 10/11)
  - 至少 100GB 空闲磁盘空间 (NTFS)

## 🚀 快速开始

### 1. 安装依赖

```bash
cd src/agentlib && pip install -e .
```

### 2. 配置环境 (Depot Tools)

如果您需要使用本地编译功能，请先运行自动化脚本配置环境：

```powershell
./src/scripts/win_setup_depot_tools.ps1
```

### 3. 配置系统

复制配置文件模板：

```bash
cp src/browser/config.yaml.example src/browser/config.yaml
```

**[重要] 设置 API 密钥**
出于安全考虑，系统**不再支持**在配置文件中明文存储 LLM 密钥。请使用环境变量：

```powershell
$env:OPENAI_API_KEY="sk-..."
# 或者
$env:ANTHROPIC_API_KEY="sk-ant-..."
```

### 4. 运行复现

```bash
cd src/browser
python -m browser.main --cve CVE-2024-XXXX
```

系统将自动执行以下流程：
1. 收集情报，锁定漏洞版本。
2. 尝试下载预编译二进制。
3. 如果下载失败，**自动下载源码并编译**。
4. 分析漏洞并生成 PoC。
5. 在复现环境中验证。

## ⚙️ 配置文件 (config.yaml)

```yaml
general:
  output_dir: "./output"

# 情报收集设置
intel:
  nvd_api_key: "your-nvd-key"  # 可选，用于提高限额

# 构建系统设置 (新功能)
build:
  mode: "hybrid"           # 推荐: "hybrid" (混合模式), 可选: "local_windows" (强制本地), "lightweight" (仅下载)
  auto_fallback: true      # 下载失败自动切换到编译
  source_root: "D:/src"    # 源码存放路径
  msvc_path: "C:/Program Files/Microsoft Visual Studio/2022/Community"

# 执行设置
execution:
  timeout: 60
  asan_enabled: true       # 启用内存检测
```

## 🧠 架构与流程

```
CVE-2024-XXXX
    │
    ▼
[ 智能决策层 ] ──(下载二进制)──► [ 快速验证环境 ]
    │ (失败/需要深度分析)
    ▼
[ 本地构建层 ] ──(自动编译)───► [ ASAN 调试环境 ]
    │
    ▼
[ 多智能体核心 ]
    ├── 分析器 (Analyzer): 读懂补丁，找根因
    ├── 生成器 (Generator): 写 PoC
    └── 验证器 (Verifier): 跑 PoC，看崩没崩
```

## 📊 输出结果

运行结束后，检查 `./output/<CVE-ID>/` 目录：
- `cve_info.json`: 漏洞情报
- `poc.js`: 生成的漏洞利用代码
- `verification.json`: 验证结果（包含 ASAN 报告）
- `results.json`: 完整执行报告

## 🤝 贡献与支持

如遇问题，请提交 Issue。
由于涉及本地编译，请确保您的 Windows 环境满足 Visual Studio 的相关要求。