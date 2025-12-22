"""
Crash Verifier Agent

Verifies that a PoC reliably triggers the vulnerability.
Tests reproducibility and analyzes crash characteristics.
"""

from typing import Optional
from .base import BrowserCVEAgentWithTools, XMLOutputParser
from ..tools import EXECUTION_TOOLS
from ..knowledge import (
    get_debugging_guide,
    normalize_component,
)


VERIFICATION_OUTPUT_FORMAT = """
After testing the PoC, output your verification results:

<verified>
yes or no - whether the PoC successfully triggers the vulnerability
</verified>

<crash_type>
The type of crash observed (e.g., SIGSEGV, SIGABRT, ASAN error, CHECK failure)
</crash_type>

<reproducibility>
Percentage of successful crashes across multiple runs (e.g., 100%, 80%, etc.)
</reproducibility>

<crash_details>
Details about the crash: address, faulting function, stack trace summary
</crash_details>

<affected_versions>
List of Chrome versions tested and whether they crashed
</affected_versions>

<notes>
Any additional observations or notes about the vulnerability
</notes>
"""


class VerificationOutputParser(XMLOutputParser):
    def __init__(self):
        super().__init__(
            tags=[
                "verified",
                "crash_type",
                "reproducibility",
                "crash_details",
                "affected_versions",
                "notes"
            ],
            format_description=VERIFICATION_OUTPUT_FORMAT
        )


class CrashVerifier(BrowserCVEAgentWithTools):
    """
    Verifies PoC reliability and crash characteristics.

    Tasks:
    1. Run PoC multiple times to test reproducibility
    2. Analyze crash type and details
    3. Test on different Chrome versions if needed
    4. Generate verification report

    Features:
    - Loads component-specific debugging guides
    """

    __LLM_MODEL__ = 'gpt-4o'
    __SYSTEM_PROMPT_TEMPLATE__ = 'crash_verifier/system.j2'
    __USER_PROMPT_TEMPLATE__ = 'crash_verifier/user.j2'
    __OUTPUT_PARSER__ = VerificationOutputParser
    __MAX_TOOL_ITERATIONS__ = 20

    # Input fields
    cve_id: Optional[str] = None
    poc_code: Optional[str] = None
    poc_path: Optional[str] = None
    chrome_path: Optional[str] = None
    expected_behavior: Optional[str] = None
    component: Optional[str] = None  # 组件名称

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cve_id = kwargs.get('cve_id')
        self.poc_code = kwargs.get('poc_code')
        self.poc_path = kwargs.get('poc_path')
        self.chrome_path = kwargs.get('chrome_path')
        self.expected_behavior = kwargs.get('expected_behavior')
        self.component = kwargs.get('component')

    def _get_debugging_guide(self) -> str:
        """获取组件调试指南"""
        if not self.component:
            return ""

        normalized = normalize_component(self.component)
        if normalized:
            return get_debugging_guide(normalized)
        return ""

    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)

        # 获取调试指南
        debugging_guide = self._get_debugging_guide()

        vars.update(
            cve_id=self.cve_id,
            poc_code=self.poc_code,
            poc_path=self.poc_path,
            chrome_path=self.chrome_path or "/tmp/chrome/chrome",
            expected_behavior=self.expected_behavior or "Crash (SIGSEGV, SIGABRT, or similar)",
            debugging_guide=debugging_guide,
        )
        return vars

    def get_available_tools(self):
        return EXECUTION_TOOLS
