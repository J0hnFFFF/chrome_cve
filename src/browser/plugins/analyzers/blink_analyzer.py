"""
Blink Analyzer Plugin

Specialized analyzer for Blink rendering engine vulnerabilities.
"""

import re
from typing import Dict, Any, List
from ..base import AnalyzerPlugin, AnalysisResult


class BlinkAnalyzerPlugin(AnalyzerPlugin):
    """
    Analyzer plugin specialized for Blink vulnerabilities.

    Handles:
    - DOM manipulation bugs
    - Use-after-free in renderer
    - CSS/layout vulnerabilities
    - Web API issues
    """

    name = "blink_analyzer"
    version = "1.0.0"
    description = "Analyzer for Blink rendering engine vulnerabilities"
    supported_components = ["blink", "dom", "layout", "css", "html", "renderer"]
    supported_vuln_types = [
        "use-after-free",
        "type-confusion",
        "out-of-bounds",
        "null-dereference",
    ]

    # Blink-specific patterns
    DOM_PATTERNS = [
        r"Document::",
        r"Element::",
        r"Node::",
        r"HTMLElement",
        r"SVGElement",
        r"EventTarget",
        r"TreeScope",
    ]

    LIFECYCLE_PATTERNS = [
        r"Dispose",
        r"Detach",
        r"Destroy",
        r"Release",
        r"GarbageCollected",
        r"Persistent<",
        r"Member<",
        r"TraceWrapperMember",
    ]

    LAYOUT_PATTERNS = [
        r"LayoutObject",
        r"LayoutBox",
        r"ComputedStyle",
        r"StyleResolver",
        r"LayoutBlock",
        r"InlineBox",
    ]

    def analyze(
        self,
        patch_diff: str,
        cve_info: Dict[str, Any],
        knowledge: str = ""
    ) -> AnalysisResult:
        """Analyze Blink patch and extract vulnerability information."""

        vuln_type = self._detect_vuln_type(patch_diff, cve_info)
        affected_functions = self._extract_affected_functions(patch_diff)
        root_cause = self._analyze_root_cause(patch_diff, vuln_type)
        trigger_conditions = self._determine_triggers(patch_diff, vuln_type)
        poc_strategy = self._suggest_poc_strategy(vuln_type, affected_functions)
        confidence = self._calculate_confidence(patch_diff, vuln_type)

        return AnalysisResult(
            vulnerability_type=vuln_type,
            component="Blink",
            root_cause=root_cause,
            trigger_conditions=trigger_conditions,
            trigger_approach=self._get_trigger_approach(vuln_type),
            poc_strategy=poc_strategy,
            confidence=confidence,
            affected_functions=affected_functions,
            patch_summary=self._summarize_patch(patch_diff),
            exploitation_difficulty=self._assess_difficulty(vuln_type),
        )

    def _detect_vuln_type(self, patch_diff: str, cve_info: Dict) -> str:
        """Detect the vulnerability type."""
        description = cve_info.get("description", "").lower()

        # Check for UAF patterns
        if any(re.search(p, patch_diff) for p in self.LIFECYCLE_PATTERNS):
            return "use-after-free"

        # Check description
        if "use after free" in description or "uaf" in description:
            return "use-after-free"
        if "type confusion" in description:
            return "type-confusion"
        if "out of bounds" in description:
            return "out-of-bounds"
        if "null" in description and "dereference" in description:
            return "null-dereference"

        return "use-after-free"  # Most common in Blink

    def _extract_affected_functions(self, patch_diff: str) -> List[str]:
        """Extract affected function names."""
        functions = []
        patterns = [
            r"^\+.*?([A-Z][a-zA-Z0-9_]+::[A-Za-z][a-zA-Z0-9_]+)",
            r"diff --git.*?/([^/]+\.(cc|h|cpp))",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, patch_diff, re.MULTILINE)
            for match in matches:
                if isinstance(match, tuple):
                    functions.append(match[0])
                else:
                    functions.append(match)

        return list(set(functions))[:10]

    def _analyze_root_cause(self, patch_diff: str, vuln_type: str) -> str:
        """Analyze root cause."""
        if vuln_type == "use-after-free":
            if any(re.search(p, patch_diff) for p in self.LIFECYCLE_PATTERNS):
                return "Object accessed after disposal during DOM lifecycle"
            return "Dangling pointer to freed renderer object"

        if vuln_type == "type-confusion":
            return "Incorrect type cast or interface assumption in Blink"

        return "Vulnerability in Blink rendering engine"

    def _determine_triggers(self, patch_diff: str, vuln_type: str) -> List[str]:
        """Determine trigger conditions."""
        triggers = []

        # DOM-related triggers
        if any(re.search(p, patch_diff) for p in self.DOM_PATTERNS):
            triggers.append("Manipulate DOM elements dynamically")
            triggers.append("Use callbacks/events during DOM operations")

        # Layout triggers
        if any(re.search(p, patch_diff) for p in self.LAYOUT_PATTERNS):
            triggers.append("Trigger layout/reflow during specific operations")
            triggers.append("Use CSS properties that force synchronous layout")

        # UAF triggers
        if vuln_type == "use-after-free":
            triggers.append("Trigger garbage collection (Oilpan)")
            triggers.append("Use requestAnimationFrame or setTimeout for timing")
            triggers.append("Remove/detach elements while they're being processed")

        if not triggers:
            triggers.append("Create HTML page that exercises vulnerable code path")

        return triggers

    def _suggest_poc_strategy(self, vuln_type: str, functions: List[str]) -> str:
        """Suggest PoC strategy."""
        if vuln_type == "use-after-free":
            return (
                "1. Create DOM structure that uses vulnerable object\n"
                "2. Set up callback/event handler for the operation\n"
                "3. In callback, remove/destroy the target object\n"
                "4. Continue original operation to access freed memory"
            )
        return "Create HTML/JavaScript that triggers the vulnerable code path"

    def _get_trigger_approach(self, vuln_type: str) -> str:
        """Get trigger approach."""
        return "DOM manipulation with controlled lifecycle events"

    def _calculate_confidence(self, patch_diff: str, vuln_type: str) -> float:
        """Calculate confidence."""
        confidence = 0.5
        if vuln_type != "unknown":
            confidence += 0.2
        if any(re.search(p, patch_diff) for p in self.DOM_PATTERNS):
            confidence += 0.15
        return min(confidence, 1.0)

    def _summarize_patch(self, patch_diff: str) -> str:
        """Summarize patch."""
        lines = patch_diff.split('\n')
        additions = len([l for l in lines if l.startswith('+')])
        deletions = len([l for l in lines if l.startswith('-')])
        files = re.findall(r'diff --git.*?/([^/\s]+\.\w+)', patch_diff)
        return f"Patch modifies {', '.join(set(files)[:5])} (+{additions}/-{deletions} lines)"

    def _assess_difficulty(self, vuln_type: str) -> str:
        """Assess difficulty."""
        return "medium" if vuln_type == "use-after-free" else "low"
