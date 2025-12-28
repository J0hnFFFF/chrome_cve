"""
Deep Patch Analyzer

Uses LLM to deeply understand patch semantics and extract precise vulnerability details.
Enhanced with code context retrieval for better analysis.
"""

import re
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PatchAnalysis:
    """Results from deep patch analysis."""
    root_cause: str
    vuln_type: str
    fix_description: str
    vulnerable_behavior: str
    api_path: List[str]
    preconditions: List[str]
    trigger_values: Dict[str, Any]
    poc_strategy: Dict[str, str]
    confidence: float


class DeepPatchAnalyzer:
    """
    Deep patch analyzer using LLM.
    
    Capabilities:
    - Root cause analysis
    - Trigger path identification
    - PoC strategy generation
    - Code context understanding (NEW)
    """
    
    def __init__(self, llm_service=None, use_code_context: bool = True):
        """
        Initialize analyzer.
        
        Args:
            llm_service: LLM service for semantic analysis
            use_code_context: Whether to fetch code context from Gitiles
        """
        self.llm_service = llm_service
        self.use_code_context = use_code_context
        self._analysis_cache = {}
        
        # Initialize code context fetcher
        self._context_fetcher = None
        if use_code_context:
            try:
                from .code_context_fetcher import CodeContextFetcher
                self._context_fetcher = CodeContextFetcher()
            except ImportError:
                logger.warning("CodeContextFetcher not available")
    
    def analyze_patch(
        self,
        patch_diff: str,
        commit_message: str,
        files_changed: List[str],
        cve_info: Dict[str, Any] = None
    ) -> PatchAnalysis:
        """
        Perform deep analysis of a security patch.
        
        Args:
            patch_diff: The patch diff content
            commit_message: Commit message
            files_changed: List of changed files
            cve_info: Optional CVE information for context
            
        Returns:
            PatchAnalysis with detailed vulnerability information
        """
        # Check cache
        cache_key = self._get_cache_key(patch_diff)
        if cache_key in self._analysis_cache:
            logger.info("Using cached patch analysis")
            return self._analysis_cache[cache_key]
        
        logger.info("Performing deep patch analysis...")
        
        # Step 1: Extract root cause
        root_cause_analysis = self._extract_root_cause(
            patch_diff, commit_message, files_changed, cve_info
        )
        
        # Step 2: Identify trigger path
        trigger_analysis = self._identify_trigger_path(
            patch_diff, root_cause_analysis, files_changed
        )
        
        # Step 3: Generate PoC strategy
        poc_strategy = self._generate_poc_strategy(
            root_cause_analysis, trigger_analysis
        )
        
        # Combine results
        analysis = PatchAnalysis(
            root_cause=root_cause_analysis.get("root_cause", "Unknown"),
            vuln_type=root_cause_analysis.get("vuln_type", "Unknown"),
            fix_description=root_cause_analysis.get("fix_description", ""),
            vulnerable_behavior=root_cause_analysis.get("vulnerable_behavior", ""),
            api_path=trigger_analysis.get("api_path", []),
            preconditions=trigger_analysis.get("preconditions", []),
            trigger_values=trigger_analysis.get("trigger_values", {}),
            poc_strategy=poc_strategy,
            confidence=self._calculate_analysis_confidence(
                root_cause_analysis, trigger_analysis, poc_strategy
            )
        )
        
        # Cache result
        self._analysis_cache[cache_key] = analysis
        
        logger.info(f"Analysis complete: {analysis.vuln_type}, confidence: {analysis.confidence:.2f}")
        
        return analysis
    
    def _extract_root_cause(
        self,
        patch_diff: str,
        commit_message: str,
        files_changed: List[str],
        cve_info: Dict[str, Any] = None
    ) -> Dict[str, str]:
        """
        Extract root cause using LLM analysis.
        
        Enhanced with code context retrieval.
        
        Returns:
            Dictionary with root_cause, vuln_type, fix_description, vulnerable_behavior
        """
        if not self.llm_service:
            # Fallback to simple heuristics
            return self._heuristic_root_cause(patch_diff, commit_message)
        
        # Prepare context
        context = self._prepare_analysis_context(
            patch_diff, commit_message, files_changed, cve_info
        )
        
        # NEW: Fetch function context if available
        function_context = ""
        if self._context_fetcher and cve_info:
            repository = cve_info.get("repository", "chromium/src")
            commit = cve_info.get("commit_hash", "")
            
            if commit:
                try:
                    contexts = self._context_fetcher.fetch_functions_from_diff(
                        repository, commit, patch_diff, max_functions=3
                    )
                    if contexts:
                        function_context = self._context_fetcher.format_context_for_llm(contexts)
                        logger.info(f"Fetched context for {len(contexts)} functions")
                except Exception as e:
                    logger.warning(f"Failed to fetch function context: {e}")
        
        # LLM prompt for root cause analysis (enhanced with function context)
        prompt = f"""Analyze this security patch for a Chrome vulnerability:

Commit Message:
{commit_message[:500]}

Changed Files:
{', '.join(files_changed[:10])}

Patch Diff (first 5000 chars):
{patch_diff[:5000]}"""

        # Add function context if available
        if function_context:
            prompt += f"""

Complete Function Context:
{function_context[:3000]}"""

        prompt += """

Questions:
1. What is the root cause of this vulnerability?
2. What type of vulnerability is this? (buffer overflow, UAF, type confusion, etc.)
3. Which specific code change fixes the vulnerability?
4. What was the vulnerable behavior before the patch?

Provide structured analysis:
<root_cause>Concise description of root cause</root_cause>
<vuln_type>Specific vulnerability type</vuln_type>
<fix_description>What the patch does to fix it</fix_description>
<vulnerable_behavior>How the code behaved before the fix</vulnerable_behavior>"""
        
        try:
            # Call LLM
            response = self.llm_service.generate(prompt, temperature=0.3)
            
            # Parse structured response
            result = {
                "root_cause": self._extract_tag(response, "root_cause"),
                "vuln_type": self._extract_tag(response, "vuln_type"),
                "fix_description": self._extract_tag(response, "fix_description"),
                "vulnerable_behavior": self._extract_tag(response, "vulnerable_behavior"),
            }
            
            return result
            
        except Exception as e:
            logger.error(f"LLM root cause analysis failed: {e}")
            return self._heuristic_root_cause(patch_diff, commit_message)
    
    def _identify_trigger_path(
        self,
        patch_diff: str,
        root_cause_analysis: Dict[str, str],
        files_changed: List[str]
    ) -> Dict[str, Any]:
        """
        Identify trigger path using LLM.
        
        Returns:
            Dictionary with api_path, preconditions, trigger_values
        """
        if not self.llm_service:
            return self._heuristic_trigger_path(patch_diff, files_changed)
        
        prompt = f"""Based on the patch analysis, identify the trigger path:

Root Cause: {root_cause_analysis.get('root_cause', 'Unknown')}
Vulnerability Type: {root_cause_analysis.get('vuln_type', 'Unknown')}

Patch Diff (relevant sections):
{patch_diff[:3000]}

Questions:
1. What API/function needs to be called to reach the vulnerable code?
2. What are the required preconditions?
3. What specific input values trigger the vulnerability?
4. Are there any race conditions or timing requirements?

Provide:
<api_path>Comma-separated function call sequence</api_path>
<preconditions>Numbered list of required setup steps</preconditions>
<trigger_values>Key-value pairs of critical values (format: key=value, one per line)</trigger_values>"""
        
        try:
            response = self.llm_service.generate(prompt, temperature=0.3)
            
            # Parse API path
            api_path_str = self._extract_tag(response, "api_path")
            api_path = [s.strip() for s in api_path_str.split(",")] if api_path_str else []
            
            # Parse preconditions
            preconditions_str = self._extract_tag(response, "preconditions")
            preconditions = [
                line.strip().lstrip("0123456789.-) ")
                for line in preconditions_str.split("\n")
                if line.strip()
            ] if preconditions_str else []
            
            # Parse trigger values
            trigger_values_str = self._extract_tag(response, "trigger_values")
            trigger_values = {}
            if trigger_values_str:
                for line in trigger_values_str.split("\n"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        trigger_values[key.strip()] = value.strip()
            
            return {
                "api_path": api_path,
                "preconditions": preconditions,
                "trigger_values": trigger_values,
            }
            
        except Exception as e:
            logger.error(f"LLM trigger path analysis failed: {e}")
            return self._heuristic_trigger_path(patch_diff, files_changed)
    
    def _generate_poc_strategy(
        self,
        root_cause_analysis: Dict[str, str],
        trigger_analysis: Dict[str, Any]
    ) -> Dict[str, str]:
        """
        Generate PoC strategy using LLM.
        
        Returns:
            Dictionary with setup, trigger, verification steps
        """
        if not self.llm_service:
            return self._heuristic_poc_strategy(root_cause_analysis, trigger_analysis)
        
        prompt = f"""Generate a PoC strategy for this vulnerability:

Vulnerability: {root_cause_analysis.get('vuln_type', 'Unknown')}
Root Cause: {root_cause_analysis.get('root_cause', 'Unknown')}
Trigger Path: {', '.join(trigger_analysis.get('api_path', []))}
Trigger Values: {trigger_analysis.get('trigger_values', {})}

Generate a step-by-step PoC strategy:
1. Setup phase (what objects/state to create)
2. Trigger phase (how to trigger the vulnerability)
3. Verification phase (how to observe the crash/corruption)

Format:
<setup>Detailed setup steps</setup>
<trigger>Exact trigger sequence</trigger>
<verification>How to verify the vulnerability</verification>"""
        
        try:
            response = self.llm_service.generate(prompt, temperature=0.3)
            
            return {
                "setup": self._extract_tag(response, "setup"),
                "trigger": self._extract_tag(response, "trigger"),
                "verification": self._extract_tag(response, "verification"),
            }
            
        except Exception as e:
            logger.error(f"LLM PoC strategy generation failed: {e}")
            return self._heuristic_poc_strategy(root_cause_analysis, trigger_analysis)
    
    # ========== Heuristic Fallbacks ==========
    
    def _heuristic_root_cause(
        self,
        patch_diff: str,
        commit_message: str
    ) -> Dict[str, str]:
        """Heuristic-based root cause extraction (fallback)."""
        # Simple pattern matching
        vuln_type = "Unknown"
        
        if any(keyword in patch_diff.lower() for keyword in ["buffer", "overflow", "oob"]):
            vuln_type = "Buffer Overflow"
        elif any(keyword in patch_diff.lower() for keyword in ["use-after-free", "uaf"]):
            vuln_type = "Use-After-Free"
        elif "type confusion" in patch_diff.lower():
            vuln_type = "Type Confusion"
        
        return {
            "root_cause": "See commit message and patch diff",
            "vuln_type": vuln_type,
            "fix_description": "See patch diff",
            "vulnerable_behavior": "Unknown - LLM analysis recommended",
        }
    
    def _heuristic_trigger_path(
        self,
        patch_diff: str,
        files_changed: List[str]
    ) -> Dict[str, Any]:
        """Heuristic-based trigger path extraction (fallback)."""
        # Extract function names from diff
        functions = []
        for line in patch_diff.split("\n"):
            if line.startswith("@@"):
                match = re.search(r"@@.*@@\s+(.*)", line)
                if match:
                    functions.append(match.group(1).strip())
        
        return {
            "api_path": functions[:3] if functions else ["Unknown"],
            "preconditions": ["See patch analysis"],
            "trigger_values": {},
        }
    
    def _heuristic_poc_strategy(
        self,
        root_cause_analysis: Dict[str, str],
        trigger_analysis: Dict[str, Any]
    ) -> Dict[str, str]:
        """Heuristic-based PoC strategy (fallback)."""
        vuln_type = root_cause_analysis.get("vuln_type", "Unknown")
        
        return {
            "setup": f"Setup for {vuln_type} vulnerability",
            "trigger": f"Call {', '.join(trigger_analysis.get('api_path', ['target function']))}",
            "verification": "Check for crash or ASAN error",
        }
    
    # ========== Helper Methods ==========
    
    def _prepare_analysis_context(
        self,
        patch_diff: str,
        commit_message: str,
        files_changed: List[str],
        cve_info: Dict[str, Any] = None
    ) -> str:
        """Prepare context for LLM analysis."""
        context_parts = [
            f"Commit: {commit_message[:500]}",
            f"Files: {', '.join(files_changed[:10])}",
        ]
        
        if cve_info:
            context_parts.append(f"CVE: {cve_info.get('cve_id', 'Unknown')}")
            context_parts.append(f"Description: {cve_info.get('description', '')[:300]}")
        
        return "\n".join(context_parts)
    
    def _extract_tag(self, text: str, tag: str) -> str:
        """Extract content from XML-style tags."""
        pattern = rf"<{tag}>(.*?)</{tag}>"
        match = re.search(pattern, text, re.DOTALL)
        return match.group(1).strip() if match else ""
    
    def _get_cache_key(self, patch_diff: str) -> str:
        """Generate cache key for patch."""
        import hashlib
        return hashlib.md5(patch_diff.encode()).hexdigest()[:16]
    
    def _calculate_analysis_confidence(
        self,
        root_cause: Dict[str, str],
        trigger: Dict[str, Any],
        poc_strategy: Dict[str, str]
    ) -> float:
        """Calculate confidence score for analysis."""
        confidence = 0.5  # Base confidence
        
        # Boost for detailed root cause
        if root_cause.get("root_cause") and len(root_cause["root_cause"]) > 20:
            confidence += 0.1
        
        # Boost for specific vuln type
        if root_cause.get("vuln_type") and root_cause["vuln_type"] != "Unknown":
            confidence += 0.1
        
        # Boost for API path
        if trigger.get("api_path") and len(trigger["api_path"]) > 0:
            confidence += 0.1
        
        # Boost for trigger values
        if trigger.get("trigger_values") and len(trigger["trigger_values"]) > 0:
            confidence += 0.1
        
        # Boost for detailed PoC strategy
        if poc_strategy.get("setup") and len(poc_strategy["setup"]) > 20:
            confidence += 0.1
        
        return min(confidence, 1.0)
