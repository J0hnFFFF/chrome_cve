# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Browser CVE Reproducer - An LLM-based multi-agent framework for Chrome/Chromium CVE reproduction. The system analyzes patches, understands vulnerabilities, and generates working PoCs.

## Quick Start

```bash
# Install agentlib
cd src/agentlib && pip install -e .

# Create .env with API key
echo "OPENAI_API_KEY=sk-..." > src/browser/.env

# Run
cd src/browser
python main.py --cve CVE-2024-XXXX
```

## Project Structure

```
src/
├── agentlib/                    # Core LLM agent framework (reused)
│
└── browser/                     # Browser CVE reproduction
    ├── main.py                  # Entry point & pipeline orchestrator
    │
    ├── agents/                  # LLM Agents
    │   ├── base.py              # Base classes & XMLOutputParser
    │   ├── patch_analyzer.py    # Analyzes patches → vulnerability understanding
    │   ├── poc_generator.py     # Generates HTML/JS PoC
    │   └── crash_verifier.py    # Verifies crash reproducibility
    │
    ├── tools/                   # Agent tools
    │   ├── chromium_tools.py    # Fetch patches, search code
    │   ├── chrome_tools.py      # Download Chrome, run PoC, detect crash
    │   └── common_tools.py      # File operations
    │
    ├── prompts/                 # Jinja2 templates
    │   ├── patch_analyzer/
    │   ├── poc_generator/
    │   └── crash_verifier/
    │
    ├── data/                    # Data processors
    │   └── cve_processor.py     # Fetch CVE info from NVD/Chromium
    │
    └── services/                # External services (future: CodeQL, Ghidra)
```

## Pipeline Flow

```
CVE-2024-XXXX
    │
    ▼
┌─────────────────────┐
│ 1. Info Collection  │  ChromiumCVEProcessor
│    - NVD API        │  → CVEInfo, patches
│    - Chromium Git   │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ 2. Patch Analysis   │  PatchAnalyzer agent
│    - Understand fix │  → vulnerability_type, trigger_conditions
│    - Root cause     │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ 3. PoC Generation   │  PoCGenerator agent (with tools)
│    - Create HTML/JS │  → poc.html
│    - Test & iterate │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ 4. Verification     │  CrashVerifier agent
│    - Run PoC        │  → crash confirmed / not
│    - Check repro    │
└─────────────────────┘
```

## Key Components

### Tools

```python
# Chromium tools
fetch_chromium_commit(hash)      # Get patch diff
fetch_chromium_file(path, hash)  # Get source file
analyze_patch_components(hash)   # Detect V8/Blink/etc

# Chrome tools
download_chrome_version(ver)     # Download specific version
run_chrome_with_poc(chrome, poc) # Run and detect crash
test_poc_reproducibility(...)    # Multiple runs

# Common
read_file, write_file, run_command
```

### Creating New Agents

```python
from browser.agents.base import BrowserCVEAgent, XMLOutputParser

class MyAgent(BrowserCVEAgent):
    __LLM_MODEL__ = 'gpt-4o'
    __SYSTEM_PROMPT_TEMPLATE__ = 'my_agent/system.j2'
    __USER_PROMPT_TEMPLATE__ = 'my_agent/user.j2'
    __OUTPUT_PARSER__ = MyParser
```

### Output Format

Agents use XML-tagged output:
```xml
<vulnerability_type>Type Confusion</vulnerability_type>
<root_cause>Missing type check in...</root_cause>
```

## Output Files

After running, check `./output/<CVE-ID>/`:
- `cve_info.json` - Raw CVE data
- `cve_knowledge.md` - Formatted for LLM
- `vulnerability_analysis.json` - Patch analysis result
- `poc.html` - Generated PoC
- `verification.json` - Crash verification result
- `results.json` - Full pipeline results

## Development

### Adding a new tool

```python
# In src/browser/tools/my_tools.py
from agentlib.lib import tools

@tools.tool
def my_tool(param: str) -> str:
    """Tool description for LLM."""
    return result

# Add to __init__.py exports
```

### Adding external service (e.g., CodeQL)

```python
# In src/browser/services/codeql.py
class CodeQLService:
    def query(self, repo_path: str, query: str) -> str:
        # Run CodeQL and return results
        pass
```

set OPENAI_API_KEY=sk-xxx
set OPENAI_BASE_URL=http://your-proxy:8000/v1
set LLM_MODEL=your-model-name