# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Chrome CVE Reproducer - An LLM-based multi-agent framework for Chrome/Chromium CVE reproduction. The system analyzes patches, understands vulnerabilities, and generates working PoCs through intelligent agent collaboration.

**Core Design Principles:**
1. **Multi-Agent Collaboration**: Specialized agents (Analyzer, Generator, Verifier, Critic) with reflection loops
2. **Plugin Architecture**: Extensible plugins with LLM-based dynamic generation
3. **Memory System**: Experience reuse through episode memory and semantic knowledge

## Quick Start

```bash
# Install agentlib
cd src/agentlib && pip install -e .

# Create config file
cp src/browser/config.yaml.example src/browser/config.yaml
# Edit config.yaml with your API keys

# Run the multi-agent pipeline
cd src/browser
python main.py --cve CVE-2024-XXXX
```

## Project Structure

```
src/browser/
├── main.py                      # CLI entry point
├── pipeline.py                  # Multi-agent pipeline orchestrator
│
├── agents/                      # Agent System
│   ├── base.py                  # Base classes, XMLOutputParser
│   ├── patch_analyzer.py        # Legacy: patch analysis
│   ├── poc_generator.py         # Legacy: PoC generation
│   ├── crash_verifier.py        # Legacy: crash verification
│   └── multi/                   # NEW: Multi-Agent System
│       ├── base.py              # BaseReproAgent, AgentMessage
│       ├── orchestrator.py      # OrchestratorAgent - task coordination
│       ├── analyzer.py          # AnalyzerAgent - patch analysis
│       ├── generator.py         # GeneratorAgent - PoC generation
│       ├── verifier.py          # VerifierAgent - crash verification
│       └── critic.py            # CriticAgent - review & reflection
│
├── plugins/                     # Plugin System
│   ├── base.py                  # PluginBase, AnalyzerPlugin, GeneratorPlugin
│   ├── registry.py              # PluginRegistry - plugin management
│   ├── dynamic.py               # DynamicPluginGenerator - LLM plugin creation
│   ├── analyzers/               # Built-in analyzer plugins
│   │   ├── v8_analyzer.py       # V8/JavaScript analysis
│   │   ├── blink_analyzer.py    # Blink/rendering analysis
│   │   └── generic_analyzer.py  # Fallback analyzer
│   ├── generators/              # Built-in generator plugins
│   │   ├── js_generator.py      # JavaScript PoC
│   │   └── html_generator.py    # HTML PoC
│   └── verifiers/               # Built-in verifier plugins
│       ├── d8_verifier.py       # d8 shell verification
│       └── chrome_verifier.py   # Chrome browser verification
│
├── memory/                      # Memory System
│   ├── episode.py               # EpisodeMemory - CVE case storage
│   ├── semantic.py              # SemanticMemory - knowledge storage
│   ├── learning.py              # LearningEngine - experience extraction
│   └── knowledge_loader.py      # Bridge to existing knowledge files
│
├── intel/                       # Intelligence Collection
│   ├── base.py                  # IntelSource, IntelResult
│   ├── sources.py               # NVD, Gitiles, GitHub, CISA sources
│   ├── collector.py             # IntelCollector - multi-source gathering
│   ├── fusion.py                # IntelFusion - data merging
│   └── version.py               # ChromeVersionMapper, ChromeDownloader
│
├── tools/                       # Tool Layer
│   ├── chromium_tools.py        # Gitiles API, code search
│   ├── chrome_tools.py          # Chrome download, execution
│   ├── common_tools.py          # File operations, commands
│   ├── analysis_tools.py        # CodeQL, Ghidra integration
│   ├── execution.py             # D8Executor, ChromeExecutor
│   └── debug.py                 # ASANParser, CrashAnalyzer
│
├── models/                      # Data Models
│   ├── cve.py                   # CVEInfo, PatchInfo
│   ├── analysis.py              # AnalysisResult
│   ├── poc.py                   # PoCResult
│   ├── verify.py                # VerifyResult
│   └── message.py               # AgentMessage, MessageType
│
├── config/                      # Configuration
│   ├── loader.py                # ConfigLoader
│   └── settings.py              # Settings dataclasses
│
├── knowledge/                   # Component Knowledge Bases
│   ├── v8_knowledge.py          # V8/JavaScript engine
│   ├── blink_knowledge.py       # Blink renderer
│   ├── skia_knowledge.py        # Skia graphics
│   ├── webgl_knowledge.py       # WebGL/GPU
│   ├── wasm_knowledge.py        # WebAssembly
│   └── ...                      # Other components
│
└── prompts/                     # Jinja2 prompt templates
```

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │          OrchestratorAgent              │
                    │    (Task coordination, state mgmt)      │
                    └──────────────────┬──────────────────────┘
                                       │ AgentMessage
           ┌───────────────┬───────────┼───────────┬───────────────┐
           ▼               ▼           ▼           ▼               ▼
    ┌────────────┐  ┌────────────┐ ┌────────────┐ ┌────────────┐
    │  Analyzer  │  │ Generator  │ │  Verifier  │ │   Critic   │
    │   Agent    │  │   Agent    │ │   Agent    │ │   Agent    │
    └─────┬──────┘  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘
          │               │              │              │
          ▼               ▼              ▼              ▼
    ┌─────────────────────────────────────────────────────────────┐
    │                      Plugin System                          │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
    │  │   Analyzer   │  │  Generator   │  │   Verifier   │      │
    │  │   Plugins    │  │   Plugins    │  │   Plugins    │      │
    │  └──────────────┘  └──────────────┘  └──────────────┘      │
    └─────────────────────────────────────────────────────────────┘
                    │               │               │
           ┌────────┴───────┬───────┴───────┬───────┴────────┐
           ▼                ▼               ▼                ▼
    ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐
    │   Intel    │   │   Memory   │   │   Tools    │   │ Knowledge  │
    │   System   │   │   System   │   │   Layer    │   │   Base     │
    └────────────┘   └────────────┘   └────────────┘   └────────────┘
```

## Pipeline Flow

```
CVE-2024-XXXX
    │
    ▼
┌─────────────────────────────────┐
│ 1. Intel Collection             │  IntelCollector
│    - NVD API (CVE details)      │  → CVEInfo with patches
│    - Gitiles (patch diffs)      │
│    - GitHub (existing PoCs)     │
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ 2. Patch Analysis               │  AnalyzerAgent + Plugins
│    - Identify vulnerability     │  → AnalysisResult
│    - Determine root cause       │
│    - Suggest PoC strategy       │  Critic reviews output
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ 3. PoC Generation               │  GeneratorAgent + Plugins
│    - Generate JS/HTML PoC       │  → PoCResult
│    - Iterate based on feedback  │
│    - Use similar cases          │  Critic reviews output
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ 4. Verification                 │  VerifierAgent + Plugins
│    - Run in d8 or Chrome        │  → VerifyResult
│    - Detect crash/ASAN          │
│    - Check reproducibility      │  Critic reviews output
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ 5. Learning                     │  LearningEngine
│    - Store case in memory       │
│    - Extract successful         │
│      strategies                 │
└─────────────────────────────────┘
```

## Key Components

### CLI Options

```bash
python main.py --cve CVE-2024-XXXX [OPTIONS]

Options:
  --config PATH                Custom config file
  --output PATH                Output directory
  --chrome-path PATH           Chrome executable path
  --d8-path PATH               d8 executable path
  --verbose, -v                Verbose output
  --debug                      Debug logging
  --list-stages                Show pipeline stages
```

### Plugin System

```python
# Creating a custom analyzer plugin
from browser.plugins.base import AnalyzerPlugin

class MyAnalyzer(AnalyzerPlugin):
    NAME = "my-analyzer"
    SUPPORTED_COMPONENTS = ["my-component"]
    SUPPORTED_VULN_TYPES = ["type-confusion"]

    def analyze(self, cve_info, patches, context):
        # Analyze patches
        return AnalysisResult(
            vulnerability_type="type-confusion",
            root_cause="...",
            poc_strategy="..."
        )

# Register plugin
from browser.plugins import PluginRegistry
registry = PluginRegistry()
registry.register(MyAnalyzer())
```

### Memory System

```python
from browser.memory import initialize_knowledge, EpisodeMemory

# Load all knowledge
semantic = initialize_knowledge()

# Get component knowledge
v8_knowledge = semantic.get_component_knowledge("v8")

# Get vulnerability patterns
uaf_patterns = semantic.get_vuln_knowledge("use-after-free")

# Store successful case
episode = EpisodeMemory()
episode.store_case(cve_case)

# Find similar cases
similar = episode.find_similar_cases(cve_id, component, vuln_type)
```

### Execution Tools

```python
from browser.tools import D8Executor, ChromeExecutor, CrashAnalyzer

# Execute in d8
d8 = D8Executor("/path/to/d8")
result = d8.execute("let x = 1;", timeout=30)
print(result.crashed, result.asan_report)

# Analyze crash
analyzer = CrashAnalyzer()
report = analyzer.analyze(result.stderr)
print(analyzer.get_summary(report))
print(analyzer.is_exploitable(report))
```

## Configuration

Create `config.yaml`:

```yaml
general:
  output_dir: ./output
  log_level: INFO

llm:
  default_model: gpt-4o
  temperature: 0.0
  max_retries: 3

intel:
  nvd_api_key: ${NVD_API_KEY}
  github_token: ${GITHUB_TOKEN}

execution:
  chrome_path: /path/to/chrome
  d8_path: /path/to/d8
  timeout: 60

memory:
  storage_path: ./volumes/memory

agents:
  max_retries: 3
  critic_enabled: true
```

## Output Files

After running, check `./output/<CVE-ID>/`:
- `cve_info.json` - Collected CVE information
- `cve_knowledge.md` - Formatted knowledge for LLM
- `vulnerability_analysis.json` - Analysis results
- `poc.js` or `poc.html` - Generated PoC
- `verification.json` - Verification results
- `results.json` - Full pipeline results
- `pipeline.log` - Execution log (with --debug)

## Development

### Adding a New Component Knowledge Base

```python
# In browser/knowledge/new_component.py
NEW_COMPONENT_OVERVIEW = """
Component overview text...
"""

NEW_COMPONENT_VULNERABILITY_PATTERNS = """
Common vulnerability patterns...
"""

# Update browser/knowledge/__init__.py
```

### Adding a New Intel Source

```python
# In browser/intel/sources.py
class NewSource(IntelSource):
    NAME = "new-source"
    TIER = 2

    def collect(self, cve_id: str) -> IntelResult:
        # Fetch data from source
        return IntelResult(source=self.NAME, data=data)
```

### Running Tests

```bash
cd src/browser
python -m pytest tests/
```
