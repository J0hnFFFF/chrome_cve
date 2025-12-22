"""
Patch Analyzer Agent

Analyzes Chromium patches to understand:
1. What vulnerability was fixed
2. Root cause of the vulnerability
3. How to trigger the vulnerability
4. What input/conditions are needed
"""

import re
from typing import Optional, List
from .base import BrowserCVEAgent, XMLOutputParser
from ..tools import ANALYSIS_TOOLS
from ..knowledge import (
    get_component_knowledge,
    get_vulnerability_patterns,
    detect_component_from_path,
    normalize_component,
)


PATCH_ANALYSIS_FORMAT = """
After analyzing the patch, output your analysis in the following format:

<vulnerability_type>
The precise type of vulnerability. Examples:
- Type Confusion (specify: JIT type confusion, Map confusion, etc.)
- Use-After-Free (specify: GC-related, explicit free, etc.)
- Out-of-Bounds Read/Write (specify: array, buffer, etc.)
- Integer Overflow/Underflow
- Race Condition
- Logic Error
</vulnerability_type>

<component>
The specific affected component and subsystem. Examples:
- V8: TurboFan, Maglev, Builtins, GC, Parser, Wasm
- Blink: DOM, Layout, CSS, Bindings, Editing
- Other: Skia, PDFium, WebRTC, Network
</component>

<vulnerable_function>
The specific function(s) containing the vulnerability. Include file path and function name.
Example: "src/v8/src/compiler/js-call-reducer.cc: JSCallReducer::ReduceArrayPrototypePush"
</vulnerable_function>

<root_cause>
Detailed technical explanation of the root cause:
1. What was the incorrect assumption or missing check?
2. What code path leads to the vulnerability?
3. Why did this cause a security issue?
Be specific about the exact lines changed and why.
</root_cause>

<trigger_conditions>
Precise conditions required to trigger:
1. What object types/states are needed?
2. What sequence of operations?
3. Are there timing requirements?
4. What values/inputs are required?
</trigger_conditions>

<trigger_approach>
Concrete approach to trigger from JavaScript/HTML:
1. What APIs or language constructs to use?
2. What setup code is needed?
3. How to reach the vulnerable code path?
Include specific JavaScript patterns if applicable.
</trigger_approach>

<poc_strategy>
Step-by-step PoC strategy:
1. Setup phase: What objects/state to create
2. Trigger phase: What operation triggers the bug
3. Verification: How to confirm the vulnerability triggered
4. Expected behavior: Crash type, error message, or observable effect
</poc_strategy>

<exploitation_potential>
Assessment of exploitation potential:
- Can this lead to arbitrary code execution?
- Can this leak sensitive information?
- What are the exploitation constraints?
- What mitigations might prevent exploitation?
</exploitation_potential>
"""


class PatchAnalysisParser(XMLOutputParser):
    def __init__(self):
        super().__init__(
            tags=[
                "vulnerability_type",
                "component",
                "vulnerable_function",
                "root_cause",
                "trigger_conditions",
                "trigger_approach",
                "poc_strategy",
                "exploitation_potential"
            ],
            format_description=PATCH_ANALYSIS_FORMAT
        )


class PatchAnalyzer(BrowserCVEAgent):
    """
    Analyzes Chromium patches to understand the vulnerability.

    Input: CVE knowledge text with patch diffs
    Output: Structured vulnerability analysis

    Features:
    - Automatically detects component from patch files
    - Loads relevant knowledge base for the component
    - Provides component-specific vulnerability patterns
    """

    __LLM_MODEL__ = 'o3'
    __SYSTEM_PROMPT_TEMPLATE__ = 'patch_analyzer/system.j2'
    __USER_PROMPT_TEMPLATE__ = 'patch_analyzer/user.j2'
    __OUTPUT_PARSER__ = PatchAnalysisParser

    # Input fields
    cve_id: Optional[str] = None
    cve_knowledge: Optional[str] = None
    patch_diff: Optional[str] = None
    component: Optional[str] = None  # 可以手动指定组件

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cve_id = kwargs.get('cve_id')
        self.cve_knowledge = kwargs.get('cve_knowledge')
        self.patch_diff = kwargs.get('patch_diff')
        self.component = kwargs.get('component')

    def _detect_components_from_patch(self) -> List[str]:
        """从补丁差异中检测涉及的组件"""
        if not self.patch_diff:
            return []

        components = set()

        # 匹配文件路径 (diff --git a/path b/path 或 +++ b/path)
        file_patterns = [
            r'diff --git a/([^\s]+)',
            r'\+\+\+ [ab]/([^\s]+)',
            r'--- [ab]/([^\s]+)',
        ]

        for pattern in file_patterns:
            matches = re.findall(pattern, self.patch_diff)
            for match in matches:
                component = detect_component_from_path(match)
                if component:
                    components.add(component)

        return list(components)

    def _get_component_knowledge(self) -> str:
        """获取相关组件的知识库"""
        # 优先使用手动指定的组件
        if self.component:
            normalized = normalize_component(self.component)
            if normalized:
                knowledge = get_component_knowledge(normalized)
                patterns = get_vulnerability_patterns(normalized)
                return f"{knowledge}\n\n{patterns}"

        # 自动检测组件
        components = self._detect_components_from_patch()

        if not components:
            return ""

        # 合并所有检测到的组件知识
        knowledge_parts = []
        for comp in components:
            knowledge = get_component_knowledge(comp)
            patterns = get_vulnerability_patterns(comp)
            if knowledge:
                knowledge_parts.append(f"## {comp.upper()} Component\n\n{knowledge}")
            if patterns:
                knowledge_parts.append(patterns)

        return "\n\n".join(knowledge_parts)

    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)

        # 获取组件特定知识
        component_knowledge = self._get_component_knowledge()

        vars.update(
            cve_id=self.cve_id,
            cve_knowledge=self.cve_knowledge,
            patch_diff=self.patch_diff,
            component_knowledge=component_knowledge,
        )
        return vars
