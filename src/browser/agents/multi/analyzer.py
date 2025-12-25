"""
Analyzer Agent

Performs vulnerability analysis on patches using LLM with tools.
Uses knowledge digestion and ReAct pattern for thorough analysis.
"""

import re
import json
import logging
from typing import Dict, Any, Optional, List

from .base import BaseReproAgent, AgentMessage, AgentState
from ...plugins import get_registry, AnalysisResult
from ...memory import SemanticMemory, LearningEngine

logger = logging.getLogger(__name__)


class AnalyzerAgent(BaseReproAgent):
    """
    Analyzer agent for patch analysis.

    Responsibilities:
    - Analyze patch diffs using LLM
    - Identify vulnerability type
    - Determine root cause
    - Suggest trigger conditions

    Uses:
    - LLMService for intelligent analysis
    - Tools for fetching additional context
    - Knowledge digestion for domain expertise
    """

    name = "analyzer"
    system_prompt_file = "analyzer_system.txt"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.semantic_memory: Optional[SemanticMemory] = None
        self.learning_engine: Optional[LearningEngine] = None

    def set_memory(
        self,
        semantic_memory: SemanticMemory,
        learning_engine: LearningEngine = None,
    ) -> None:
        """Set memory systems for knowledge access."""
        self.semantic_memory = semantic_memory
        self.learning_engine = learning_engine

    def _register_handlers(self) -> None:
        """Register message handlers."""
        self._message_handlers = {
            "analyze": self._handle_analyze,
        }

    def _handle_analyze(self, msg: AgentMessage) -> AgentMessage:
        """Handle analyze request."""
        cve_info = msg.payload.get("cve_info", {})
        patches = msg.payload.get("patches", [])

        try:
            result = self.run({
                "cve_info": cve_info,
                "patches": patches,
            })

            return msg.create_response(
                sender=self.name,
                payload={"result": result},
                success=True,
            )
        except Exception as e:
            logger.exception(f"Analysis failed: {e}")
            return msg.create_response(
                sender=self.name,
                payload={"error": str(e)},
                success=False,
            )

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze patches and identify vulnerability.

        Args:
            context: Contains cve_info, patches

        Returns:
            Analysis result dictionary
        """
        self.set_state(AgentState.RUNNING)

        cve_info = context.get("cve_info", {})
        patches = context.get("patches", [])
        component = cve_info.get("component", "")

        # Get patch diff
        patch_diff = self._combine_patches(patches, cve_info)

        # Check if we have LLM service
        if self._llm_service:
            result = self._analyze_with_llm(cve_info, patch_diff, component)
        else:
            # Fallback to plugin-based analysis
            result = self._analyze_with_plugin(cve_info, patch_diff, component)

        self.set_state(AgentState.COMPLETED)
        return result

    def _analyze_with_llm(
        self,
        cve_info: Dict[str, Any],
        patch_diff: str,
        component: str,
    ) -> Dict[str, Any]:
        """Perform LLM-powered analysis."""
        cve_id = cve_info.get('cve_id', 'unknown')
        print(f"  [Analyzer] Analyzing {cve_id} with LLM...")
        print(f"  [Analyzer] Patch size: {len(patch_diff)} chars, Component: {component}")
        logger.info(f"Analyzing {cve_id} with LLM")

        # Prepare knowledge for digestion
        knowledge_chunks = self._prepare_knowledge(component, cve_info)

        # Create session with knowledge context
        knowledge_context = ""
        if knowledge_chunks:
            knowledge_context = f"Relevant knowledge for {component}:\n" + "\n---\n".join(knowledge_chunks[:3])

        self._create_session(additional_context=knowledge_context)

        # If we have substantial knowledge, digest it first
        if len(knowledge_chunks) > 1:
            logger.debug("Digesting knowledge chunks")
            self._llm_digest_knowledge(knowledge_chunks)

        # Build analysis prompt
        cve_id = cve_info.get("cve_id", "Unknown")
        description = cve_info.get("description", "No description")

        analysis_prompt = f"""Analyze this vulnerability:

CVE ID: {cve_id}
Description: {description}
Component: {component or "Unknown"}

Patch Diff:
```
{patch_diff[:8000]}  # Truncate very long diffs
```

Based on the patch, analyze:
1. What vulnerability type is this?
2. What is the root cause?
3. What are the trigger conditions?
4. How would you approach creating a PoC?

Provide your analysis in this format:
<vulnerability_type>TYPE</vulnerability_type>
<root_cause>EXPLANATION</root_cause>
<trigger_conditions>CONDITIONS</trigger_conditions>
<trigger_approach>APPROACH</trigger_approach>
<poc_strategy>STRATEGY</poc_strategy>
<confidence>0.0-1.0</confidence>"""

        # Get LLM response (with tools for fetching more context)
        print(f"  [Analyzer] Sending to LLM...")
        response = self._llm_chat(analysis_prompt, use_tools=True)
        print(f"  [Analyzer] LLM response received ({len(response)} chars)")

        # Parse response
        result = self._parse_analysis_response(response)
        result["component"] = component or cve_info.get("component", "Unknown")
        print(f"  [Analyzer] Analysis complete: {result.get('vulnerability_type', 'unknown')}")

        return result

    def _analyze_with_plugin(
        self,
        cve_info: Dict[str, Any],
        patch_diff: str,
        component: str,
    ) -> Dict[str, Any]:
        """Fallback to plugin-based analysis."""
        logger.info(f"Analyzing with plugin for component: {component}")

        # Get knowledge context
        knowledge = ""
        if self.learning_engine:
            knowledge = self.learning_engine.get_context_for_analysis(
                component=component,
            )
        elif self.semantic_memory:
            knowledge = self.semantic_memory.get_knowledge_for_context(
                component=component,
            )

        # Find matching plugin
        registry = get_registry()
        plugin = registry.get_analyzer(component)

        if plugin:
            result = plugin.analyze(
                patch_diff=patch_diff,
                cve_info=cve_info,
                knowledge=knowledge,
            )
            return result.to_dict() if hasattr(result, 'to_dict') else result
        else:
            return self._basic_analysis(patch_diff, cve_info)

    def _prepare_knowledge(
        self,
        component: str,
        cve_info: Dict[str, Any],
    ) -> List[str]:
        """Prepare knowledge chunks for digestion."""
        chunks = []

        # Component knowledge
        if self.semantic_memory:
            comp_knowledge = self.semantic_memory.get_component_knowledge(component)
            if comp_knowledge:
                chunks.append(f"Component Knowledge ({component}):\n{comp_knowledge.to_text()}")

            # Vulnerability type knowledge (guess from description)
            description = cve_info.get("description", "").lower()
            vuln_types = []
            if "use after free" in description or "use-after-free" in description:
                vuln_types.append("use-after-free")
            if "type confusion" in description:
                vuln_types.append("type-confusion")
            if "out of bounds" in description or "oob" in description:
                vuln_types.append("out-of-bounds")
            if "heap buffer overflow" in description:
                vuln_types.append("heap-buffer-overflow")
            if "integer overflow" in description:
                vuln_types.append("integer-overflow")

            for vt in vuln_types:
                vt_knowledge = self.semantic_memory.get_vuln_knowledge(vt)
                if vt_knowledge:
                    chunks.append(f"Vulnerability Type Knowledge ({vt}):\n{vt_knowledge.to_text()}")

        # Learning engine context
        if self.learning_engine:
            context = self.learning_engine.get_context_for_analysis(component=component)
            if context:
                chunks.append(f"Historical Analysis Context:\n{context}")

        return chunks

    def _parse_analysis_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM analysis response."""
        result = {
            "vulnerability_type": "unknown",
            "root_cause": "",
            "trigger_conditions": [],
            "trigger_approach": "",
            "poc_strategy": "",
            "confidence": 0.5,
        }

        # Extract XML-style tags
        patterns = {
            "vulnerability_type": r"<vulnerability_type>(.*?)</vulnerability_type>",
            "root_cause": r"<root_cause>(.*?)</root_cause>",
            "trigger_conditions": r"<trigger_conditions>(.*?)</trigger_conditions>",
            "trigger_approach": r"<trigger_approach>(.*?)</trigger_approach>",
            "poc_strategy": r"<poc_strategy>(.*?)</poc_strategy>",
            "confidence": r"<confidence>(.*?)</confidence>",
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if key == "trigger_conditions":
                    # Parse as list
                    result[key] = [c.strip() for c in value.split("\n") if c.strip()]
                elif key == "confidence":
                    try:
                        result[key] = float(value)
                    except ValueError:
                        result[key] = 0.5
                else:
                    result[key] = value

        # If no structured response, try to extract from plain text
        if result["vulnerability_type"] == "unknown":
            result = self._extract_from_plain_text(response, result)

        return result

    def _extract_from_plain_text(
        self,
        response: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Extract analysis from plain text response."""
        response_lower = response.lower()

        # Detect vulnerability type
        vuln_types = {
            "use-after-free": ["use after free", "use-after-free", "uaf"],
            "type-confusion": ["type confusion", "type-confusion"],
            "heap-buffer-overflow": ["heap buffer overflow", "heap-buffer-overflow"],
            "out-of-bounds": ["out of bounds", "oob read", "oob write"],
            "integer-overflow": ["integer overflow", "integer-overflow"],
            "race-condition": ["race condition", "toctou"],
        }

        for vtype, keywords in vuln_types.items():
            if any(kw in response_lower for kw in keywords):
                result["vulnerability_type"] = vtype
                break

        # Use first paragraph as root cause if not found
        if not result["root_cause"]:
            paragraphs = response.split("\n\n")
            if paragraphs:
                result["root_cause"] = paragraphs[0][:500]

        return result

    def _combine_patches(self, patches: list, cve_info: dict) -> str:
        """Combine patch information into single diff."""
        if patches:
            return "\n".join(
                p.get("diff_content", "") if isinstance(p, dict) else str(p)
                for p in patches
            )

        # Try to get from cve_info
        cve_patches = cve_info.get("patches", [])
        if cve_patches:
            return "\n".join(
                p.get("diff_content", "") if isinstance(p, dict) else str(p)
                for p in cve_patches
            )

        return ""

    def _basic_analysis(self, patch_diff: str, cve_info: dict) -> dict:
        """Perform basic analysis without LLM or plugin."""
        description = cve_info.get("description", "")

        # Detect vulnerability type from description
        vuln_type = "unknown"
        if "use after free" in description.lower():
            vuln_type = "use-after-free"
        elif "out of bounds" in description.lower():
            vuln_type = "out-of-bounds"
        elif "type confusion" in description.lower():
            vuln_type = "type-confusion"

        return {
            "vulnerability_type": vuln_type,
            "component": cve_info.get("component", "Unknown"),
            "root_cause": description[:200] if description else "See patch for details",
            "trigger_conditions": ["Execute code that exercises the vulnerable path"],
            "trigger_approach": "Craft input to trigger vulnerability",
            "poc_strategy": "Analyze patch and create triggering input",
            "confidence": 0.3,
        }
