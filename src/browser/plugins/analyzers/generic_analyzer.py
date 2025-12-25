"""
Generic Analyzer Plugin

Fallback analyzer for components without specialized plugins.
Uses LLM for analysis when no specific patterns are known.
"""

import re
from typing import Dict, Any, List
from ..base import AnalyzerPlugin, AnalysisResult


class GenericAnalyzerPlugin(AnalyzerPlugin):
    """
    Generic analyzer plugin for any component.

    Used as fallback when no specialized plugin matches.
    Provides basic analysis based on common patterns.
    """

    name = "generic_analyzer"
    version = "1.0.0"
    description = "Generic analyzer for any browser component"
    supported_components = []  # Matches everything
    supported_vuln_types = []  # Matches everything

    COMMON_VULN_PATTERNS = {
        "use-after-free": [
            r"delete\s+\w+",
            r"free\s*\(",
            r"Release\s*\(",
            r"Destroy\s*\(",
            r"Dispose\s*\(",
        ],
        "out-of-bounds": [
            r"bounds",
            r"index",
            r"length",
            r"size",
            r"offset",
            r"\[\s*\w+\s*\]",
        ],
        "integer-overflow": [
            r"overflow",
            r"underflow",
            r"truncat",
            r"cast",
            r"size_t",
        ],
        "null-dereference": [
            r"null",
            r"nullptr",
            r"NULL",
            r"dereference",
        ],
        "type-confusion": [
            r"static_cast",
            r"dynamic_cast",
            r"reinterpret_cast",
            r"type.*check",
        ],
    }

    def matches(self, component: str, vuln_type: str = None) -> bool:
        """Generic analyzer always matches as fallback."""
        return True  # Matches everything

    def analyze(
        self,
        patch_diff: str,
        cve_info: Dict[str, Any],
        knowledge: str = ""
    ) -> AnalysisResult:
        """Perform generic analysis."""

        component = self._detect_component(patch_diff, cve_info)
        vuln_type = self._detect_vuln_type(patch_diff, cve_info)
        affected_functions = self._extract_affected_functions(patch_diff)
        root_cause = self._analyze_root_cause(patch_diff, vuln_type, cve_info)
        trigger_conditions = self._determine_triggers(patch_diff, vuln_type)

        return AnalysisResult(
            vulnerability_type=vuln_type,
            component=component,
            root_cause=root_cause,
            trigger_conditions=trigger_conditions,
            trigger_approach=f"Trigger {vuln_type} in {component}",
            poc_strategy=self._suggest_poc_strategy(vuln_type, component),
            confidence=0.5,  # Lower confidence for generic analysis
            affected_functions=affected_functions,
            patch_summary=self._summarize_patch(patch_diff),
            exploitation_difficulty="medium",
        )

    def _detect_component(self, patch_diff: str, cve_info: Dict) -> str:
        """Detect component from patch files."""
        files = re.findall(r'diff --git.*?/([^/\s]+)', patch_diff)

        # Check common component paths
        component_paths = {
            "v8": "V8",
            "blink": "Blink",
            "skia": "Skia",
            "pdfium": "PDFium",
            "webrtc": "WebRTC",
            "net": "Network",
            "gpu": "GPU",
        }

        for path, comp in component_paths.items():
            if any(path in f.lower() for f in files):
                return comp

        return cve_info.get("component", "Unknown")

    def _detect_vuln_type(self, patch_diff: str, cve_info: Dict) -> str:
        """Detect vulnerability type."""
        description = cve_info.get("description", "").lower()
        patch_lower = patch_diff.lower()

        # Check description first
        vuln_keywords = {
            "use after free": "use-after-free",
            "uaf": "use-after-free",
            "out of bounds": "out-of-bounds",
            "oob": "out-of-bounds",
            "buffer overflow": "buffer-overflow",
            "heap overflow": "heap-overflow",
            "type confusion": "type-confusion",
            "integer overflow": "integer-overflow",
            "null pointer": "null-dereference",
            "race condition": "race-condition",
        }

        for keyword, vuln_type in vuln_keywords.items():
            if keyword in description:
                return vuln_type

        # Check patch patterns
        for vuln_type, patterns in self.COMMON_VULN_PATTERNS.items():
            if any(re.search(p, patch_lower) for p in patterns):
                return vuln_type

        return "unknown"

    def _extract_affected_functions(self, patch_diff: str) -> List[str]:
        """Extract affected functions."""
        functions = []
        patterns = [
            r"^\+.*?([A-Z][a-zA-Z0-9_]+::[A-Za-z][a-zA-Z0-9_]+)",
            r"^\+.*?function\s+([a-zA-Z_][a-zA-Z0-9_]*)",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, patch_diff, re.MULTILINE)
            functions.extend(matches if not isinstance(matches[0] if matches else "", tuple) else [m[0] for m in matches])

        return list(set(functions))[:10]

    def _analyze_root_cause(self, patch_diff: str, vuln_type: str, cve_info: Dict) -> str:
        """Analyze root cause from CVE description and patch."""
        description = cve_info.get("description", "")
        if description:
            # First sentence often describes the issue
            first_sentence = description.split('.')[0]
            return first_sentence

        return f"{vuln_type} vulnerability in browser component"

    def _determine_triggers(self, patch_diff: str, vuln_type: str) -> List[str]:
        """Determine trigger conditions."""
        triggers = []

        if vuln_type == "use-after-free":
            triggers.append("Trigger object deallocation while reference exists")
            triggers.append("Use callbacks or events to control timing")

        elif vuln_type == "out-of-bounds":
            triggers.append("Craft input with unexpected size/length")
            triggers.append("Manipulate array/buffer indices")

        elif vuln_type == "type-confusion":
            triggers.append("Create type mismatch through interface")
            triggers.append("Trigger incorrect type cast")

        if not triggers:
            triggers.append("Craft input that exercises vulnerable code path")

        return triggers

    def _suggest_poc_strategy(self, vuln_type: str, component: str) -> str:
        """Suggest generic PoC strategy."""
        return (
            f"1. Identify the entry point for {component}\n"
            f"2. Craft input that triggers {vuln_type}\n"
            "3. Verify crash with ASAN build\n"
            "4. Refine PoC for reliable reproduction"
        )

    def _summarize_patch(self, patch_diff: str) -> str:
        """Summarize patch."""
        lines = patch_diff.split('\n')
        additions = len([l for l in lines if l.startswith('+')])
        deletions = len([l for l in lines if l.startswith('-')])
        return f"Patch contains +{additions}/-{deletions} lines"
