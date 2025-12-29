"""
V8 Analyzer Plugin

Specialized analyzer for V8 JavaScript engine vulnerabilities.
Enhanced with DeepPatchAnalyzer for LLM-based semantic analysis.
"""

import re
from typing import Dict, Any, List, Optional
from ..base import AnalyzerPlugin, AnalysisResult


class V8AnalyzerPlugin(AnalyzerPlugin):
    """
    Analyzer plugin specialized for V8 vulnerabilities.

    Handles:
    - JIT compiler bugs (TurboFan, Maglev)
    - Type confusion
    - Bounds check elimination
    - GC-related issues
    - WebAssembly vulnerabilities
    
    Enhanced with DeepPatchAnalyzer for semantic understanding.
    """

    name = "v8_analyzer"
    version = "2.0.0"  # Upgraded with DeepPatchAnalyzer
    description = "Analyzer for V8 JavaScript engine vulnerabilities with LLM support"
    supported_components = ["v8", "javascript", "jit", "turbofan", "maglev", "wasm"]
    supported_vuln_types = [
        "type-confusion",
        "bounds-check-elimination",
        "use-after-free",
        "out-of-bounds",
        "integer-overflow",
    ]

    # V8-specific patterns
    JIT_PATTERNS = [
        r"TurboFan",
        r"Maglev",
        r"Ignition",
        r"OptimizedCompilation",
        r"BytecodeGenerator",
        r"JSCallReducer",
        r"SimplifiedLowering",
        r"EffectControlLinearizer",
    ]

    TYPE_PATTERNS = [
        r"CheckMaps",
        r"MapCheck",
        r"Type.*mismatch",
        r"representation",
        r"ElementsKind",
        r"TransitionArray",
    ]

    GC_PATTERNS = [
        r"IncrementalMarking",
        r"ScavengeJob",
        r"MarkCompact",
        r"Heap::.*",
        r"GCTracer",
        r"EmbedderHeapTracer",
    ]
    
    def __init__(self, llm_service=None):
        """
        Initialize V8 analyzer.
        
        Args:
            llm_service: Optional LLM service for deep analysis
        """
        super().__init__()
        self._deep_analyzer = None
        
        # Initialize DeepPatchAnalyzer if LLM available
        if llm_service:
            try:
                from ...tools.deep_patch_analyzer import DeepPatchAnalyzer
                self._deep_analyzer = DeepPatchAnalyzer(llm_service)
            except ImportError:
                pass  # Fallback to heuristic analysis

    def analyze(
        self,
        patch_diff: str,
        cve_info: Dict[str, Any],
        knowledge: str = ""
    ) -> AnalysisResult:
        """
        Analyze V8 patch and extract vulnerability information.
        
        Enhanced to use DeepPatchAnalyzer when available.
        """
        
        # Try deep analysis first
        if self._deep_analyzer:
            try:
                deep_analysis = self._deep_analyzer.analyze_patch(
                    patch_diff=patch_diff,
                    commit_message=cve_info.get("commit_message", ""),
                    files_changed=cve_info.get("files_changed", []),
                    cve_info=cve_info
                )
                
                # Convert DeepPatchAnalysis to AnalysisResult
                return AnalysisResult(
                    vulnerability_type=deep_analysis.vuln_type,
                    component="V8",
                    root_cause=deep_analysis.root_cause,
                    trigger_conditions=deep_analysis.preconditions,
                    trigger_approach=", ".join(deep_analysis.api_path),
                    poc_strategy=self._format_poc_strategy(deep_analysis.poc_strategy),
                    confidence=deep_analysis.confidence,
                    affected_functions=deep_analysis.api_path,
                    patch_summary=deep_analysis.fix_description,
                    exploitation_difficulty=self._assess_difficulty(deep_analysis.vuln_type),
                )
            except Exception as e:
                # Fallback to heuristic analysis
                print(f"  [V8Analyzer] Deep analysis failed, using heuristics: {e}")
        
        # Heuristic analysis (original logic)
        # Detect vulnerability type
        vuln_type = self._detect_vuln_type(patch_diff, cve_info)

        # Identify affected functions
        affected_functions = self._extract_affected_functions(patch_diff)

        # Analyze root cause
        root_cause = self._analyze_root_cause(patch_diff, vuln_type)

        # Determine trigger conditions
        trigger_conditions = self._determine_triggers(patch_diff, vuln_type)

        # Suggest PoC strategy
        poc_strategy = self._suggest_poc_strategy(vuln_type, affected_functions)

        # Calculate confidence
        confidence = self._calculate_confidence(patch_diff, vuln_type)

        return AnalysisResult(
            vulnerability_type=vuln_type,
            component="V8",
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
        """Detect the vulnerability type from patch and CVE info."""
        description = cve_info.get("description", "").lower()

        # Check for type confusion
        if any(re.search(p, patch_diff, re.I) for p in self.TYPE_PATTERNS):
            return "type-confusion"

        # Check for bounds check elimination
        if "bounds" in patch_diff.lower() or "CheckBounds" in patch_diff:
            return "bounds-check-elimination"

        # Check for UAF/GC issues
        if any(re.search(p, patch_diff, re.I) for p in self.GC_PATTERNS):
            return "use-after-free"

        # Check from description
        if "type confusion" in description:
            return "type-confusion"
        if "out of bounds" in description or "oob" in description:
            return "out-of-bounds"
        if "use after free" in description or "uaf" in description:
            return "use-after-free"
        if "integer overflow" in description:
            return "integer-overflow"

        return "unknown"

    def _extract_affected_functions(self, patch_diff: str) -> List[str]:
        """Extract affected function names from patch."""
        functions = []

        # Match function definitions in diff
        patterns = [
            r"^\+.*?([A-Z][a-zA-Z0-9_]+::[A-Za-z][a-zA-Z0-9_]+)",  # C++ methods
            r"^\+.*?function\s+([a-zA-Z_][a-zA-Z0-9_]*)",  # JS functions
            r"diff --git.*?/([^/]+\.(cc|h|cpp))",  # File names
        ]

        for pattern in patterns:
            matches = re.findall(pattern, patch_diff, re.MULTILINE)
            for match in matches:
                if isinstance(match, tuple):
                    functions.append(match[0])
                else:
                    functions.append(match)

        return list(set(functions))[:10]  # Limit to 10

    def _analyze_root_cause(self, patch_diff: str, vuln_type: str) -> str:
        """Analyze the root cause based on patch changes."""

        if vuln_type == "type-confusion":
            if "CheckMaps" in patch_diff or "MapCheck" in patch_diff:
                return "Missing or incorrect map check allows type confusion during JIT optimization"
            if "ElementsKind" in patch_diff:
                return "Incorrect elements kind transition leads to type confusion"
            return "Type assumption in optimized code doesn't match runtime type"

        if vuln_type == "bounds-check-elimination":
            if "CheckBounds" in patch_diff:
                return "Bounds check incorrectly eliminated during optimization"
            return "Array bounds validation bypassed in optimized code path"

        if vuln_type == "use-after-free":
            if any(re.search(p, patch_diff) for p in self.GC_PATTERNS):
                return "Object freed by garbage collector while still referenced"
            return "Use of object after deallocation"

        if vuln_type == "out-of-bounds":
            return "Array or buffer access beyond allocated bounds"

        return "Vulnerability in V8 JavaScript engine"

    def _determine_triggers(self, patch_diff: str, vuln_type: str) -> List[str]:
        """Determine conditions needed to trigger the vulnerability."""
        triggers = []

        # JIT-related triggers
        if any(re.search(p, patch_diff) for p in self.JIT_PATTERNS):
            triggers.append("Function must be JIT-compiled (call multiple times)")
            triggers.append("Use %OptimizeFunctionOnNextCall() or loop for optimization")

        # Type-specific triggers
        if vuln_type == "type-confusion":
            triggers.append("Create objects with specific map/hidden class")
            triggers.append("Trigger map transition during optimization")

        if vuln_type == "bounds-check-elimination":
            triggers.append("Use typed arrays or regular arrays")
            triggers.append("Create predictable array access pattern")

        if vuln_type == "use-after-free":
            triggers.append("Trigger garbage collection at specific point")
            triggers.append("Use callbacks or promises to control timing")

        if not triggers:
            triggers.append("Execute JavaScript that exercises the vulnerable code path")

        return triggers

    def _suggest_poc_strategy(self, vuln_type: str, functions: List[str]) -> str:
        """Suggest a PoC generation strategy."""

        strategies = {
            "type-confusion": (
                "1. Create object with specific structure\n"
                "2. JIT compile function that accesses object\n"
                "3. Modify object structure after optimization\n"
                "4. Access object through optimized code path"
            ),
            "bounds-check-elimination": (
                "1. Create typed array or array\n"
                "2. JIT compile function with bounds-checked access\n"
                "3. Manipulate length or bounds after optimization\n"
                "4. Trigger out-of-bounds access"
            ),
            "use-after-free": (
                "1. Allocate objects in predictable heap layout\n"
                "2. Create reference to target object\n"
                "3. Trigger GC to free object while keeping reference\n"
                "4. Access freed memory through dangling reference"
            ),
            "out-of-bounds": (
                "1. Create buffer/array with specific size\n"
                "2. Calculate index that bypasses bounds check\n"
                "3. Read/write beyond buffer bounds\n"
                "4. Use OOB access for info leak or corruption"
            ),
        }

        return strategies.get(vuln_type, "Craft JavaScript to trigger vulnerable code path")

    def _get_trigger_approach(self, vuln_type: str) -> str:
        """Get the general approach for triggering the vulnerability."""
        approaches = {
            "type-confusion": "JIT optimization with controlled type transitions",
            "bounds-check-elimination": "Array access after bounds check elimination",
            "use-after-free": "GC-triggered deallocation with dangling reference",
            "out-of-bounds": "Index calculation bypassing bounds validation",
        }
        return approaches.get(vuln_type, "Execute crafted JavaScript code")

    def _calculate_confidence(self, patch_diff: str, vuln_type: str) -> float:
        """Calculate confidence score for the analysis."""
        confidence = 0.5

        # Higher confidence if we detected specific patterns
        if vuln_type != "unknown":
            confidence += 0.2

        # Higher confidence if JIT patterns detected
        if any(re.search(p, patch_diff) for p in self.JIT_PATTERNS):
            confidence += 0.15

        # Higher confidence if clear type or bounds patterns
        if any(re.search(p, patch_diff, re.I) for p in self.TYPE_PATTERNS):
            confidence += 0.1

        return min(confidence, 1.0)

    def _summarize_patch(self, patch_diff: str) -> str:
        """Create a brief summary of the patch."""
        lines = patch_diff.split('\n')
        additions = len([l for l in lines if l.startswith('+')])
        deletions = len([l for l in lines if l.startswith('-')])

        files = re.findall(r'diff --git.*?/([^/\s]+\.\w+)', patch_diff)
        files_str = ", ".join(set(files)[:5])

        return f"Patch modifies {files_str} (+{additions}/-{deletions} lines)"

    def _assess_difficulty(self, vuln_type: str) -> str:
        """Assess exploitation difficulty."""
        difficulties = {
            "type-confusion": "medium",
            "bounds-check-elimination": "medium",
            "use-after-free": "high",
            "out-of-bounds": "low",
            "integer-overflow": "medium",
        }
        return difficulties.get(vuln_type, "medium")
    
    def _format_poc_strategy(self, poc_strategy: Dict[str, str]) -> str:
        """
        Format PoC strategy from DeepPatchAnalysis to string.
        
        Args:
            poc_strategy: Dictionary with setup, trigger, verification
            
        Returns:
            Formatted strategy string
        """
        parts = []
        
        if poc_strategy.get("setup"):
            parts.append(f"Setup: {poc_strategy['setup']}")
        
        if poc_strategy.get("trigger"):
            parts.append(f"Trigger: {poc_strategy['trigger']}")
        
        if poc_strategy.get("verification"):
            parts.append(f"Verification: {poc_strategy['verification']}")
        
        return " | ".join(parts) if parts else "See deep analysis"
