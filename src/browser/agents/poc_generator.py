"""
PoC Generator Agent

Generates Proof-of-Concept code to trigger the vulnerability.
Uses tools to test and refine the PoC iteratively.
"""

from typing import Optional
from .base import BrowserCVEAgentWithTools, XMLOutputParser
from ..tools import POC_TOOLS, EXECUTION_TOOLS
from ..knowledge import (
    get_component_knowledge,
    get_vulnerability_patterns,
    get_debugging_guide,
    normalize_component,
)


POC_OUTPUT_FORMAT = """
After creating and testing the PoC, output the final result:

<success>
"yes" if a working PoC was created that triggers the vulnerability
"partial" if the PoC reaches vulnerable code but doesn't crash reliably
"no" if unable to create a working PoC
</success>

<poc_type>
The type of PoC:
- html: Standalone HTML file
- javascript: Pure JavaScript (requires d8 or node)
- html+js: HTML with embedded JavaScript
- html+worker: HTML with Web Worker
</poc_type>

<poc_code>
The complete, runnable PoC code.
- For HTML: Include full <!DOCTYPE html> document
- For JavaScript: Include all necessary code
- Must be copy-paste ready
- Include comments explaining each section
</poc_code>

<trigger_mechanism>
Detailed technical explanation of how the PoC works:
1. What objects/state are created in setup
2. What operation triggers the vulnerability
3. What memory corruption or security violation occurs
4. Why this leads to a crash/exploitable state
</trigger_mechanism>

<required_flags>
Chrome command-line flags required to trigger:
- List each flag and why it's needed
- Example: --no-sandbox (required for crash detection)
</required_flags>

<expected_behavior>
Observable behavior when the PoC succeeds:
- Crash type (SIGSEGV, SIGABRT, etc.)
- ASAN error message if applicable
- Crash location (function name if known)
- Alternative indicators if no crash
</expected_behavior>

<iterations_summary>
Brief summary of the development process:
- How many iterations were attempted
- What adjustments were made
- Key insights discovered
</iterations_summary>
"""


class PoCOutputParser(XMLOutputParser):
    def __init__(self):
        super().__init__(
            tags=[
                "success",
                "poc_type",
                "poc_code",
                "trigger_mechanism",
                "required_flags",
                "expected_behavior",
                "iterations_summary"
            ],
            format_description=POC_OUTPUT_FORMAT
        )


class PoCGenerator(BrowserCVEAgentWithTools):
    """
    Generates PoC code to trigger the vulnerability.

    Uses an iterative approach:
    1. Generate initial PoC based on analysis
    2. Test the PoC
    3. Refine based on results
    4. Repeat until crash or max attempts

    Features:
    - Loads component-specific knowledge based on vulnerability analysis
    - Provides relevant debugging guides
    - Includes vulnerability patterns for reference
    """

    __LLM_MODEL__ = 'o3'
    __SYSTEM_PROMPT_TEMPLATE__ = 'poc_generator/system.j2'
    __USER_PROMPT_TEMPLATE__ = 'poc_generator/user.j2'
    __OUTPUT_PARSER__ = PoCOutputParser
    __MAX_TOOL_ITERATIONS__ = 40

    # Input fields
    cve_id: Optional[str] = None
    vulnerability_analysis: Optional[dict] = None
    patch_diff: Optional[str] = None
    chrome_path: Optional[str] = None
    component: Optional[str] = None  # 可以手动指定组件

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cve_id = kwargs.get('cve_id')
        self.vulnerability_analysis = kwargs.get('vulnerability_analysis')
        self.patch_diff = kwargs.get('patch_diff')
        self.chrome_path = kwargs.get('chrome_path')
        self.component = kwargs.get('component')

    def _detect_component(self) -> Optional[str]:
        """从漏洞分析中检测组件"""
        # 优先使用手动指定的组件
        if self.component:
            return normalize_component(self.component)

        # 从漏洞分析中提取组件
        if self.vulnerability_analysis:
            component_field = self.vulnerability_analysis.get('component', '')
            if component_field:
                return normalize_component(component_field)

        return None

    def _get_component_knowledge(self) -> str:
        """获取组件特定知识"""
        component = self._detect_component()
        if not component:
            return ""

        knowledge = get_component_knowledge(component)
        patterns = get_vulnerability_patterns(component)

        if knowledge and patterns:
            return f"{knowledge}\n\n{patterns}"
        return knowledge or patterns or ""

    def _get_debugging_guide(self) -> str:
        """获取调试指南"""
        component = self._detect_component()
        if not component:
            return ""

        return get_debugging_guide(component)

    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)

        # Format vulnerability analysis for prompt
        vuln_text = ""
        if self.vulnerability_analysis:
            for key, value in self.vulnerability_analysis.items():
                vuln_text += f"## {key.replace('_', ' ').title()}\n{value}\n\n"

        # 获取组件特定知识
        component_knowledge = self._get_component_knowledge()
        debugging_guide = self._get_debugging_guide()

        vars.update(
            cve_id=self.cve_id,
            vulnerability_analysis=vuln_text,
            patch_diff=self.patch_diff,
            chrome_path=self.chrome_path or "/tmp/chrome/chrome",
            component_knowledge=component_knowledge,
            debugging_guide=debugging_guide,
        )
        return vars

    def get_available_tools(self):
        return POC_TOOLS + EXECUTION_TOOLS
