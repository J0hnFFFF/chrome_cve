"""
Generator Agent

Generates PoC based on vulnerability analysis using LLM.
Uses knowledge from similar cases and iterative refinement.
"""

import re
import logging
import concurrent.futures
from typing import Dict, Any, Optional, List

from .base import BaseReproAgent, AgentMessage, AgentState
from ...plugins import get_registry, AnalysisResult, PoCResult
from ...memory import SemanticMemory, EpisodeMemory
from ...tools.regression_test_analyzer import RegressionTestAnalyzer
from ...plugins.generators.helpers.poc_template_library import PoCTemplateLibrary # NEW

logger = logging.getLogger(__name__)


class GeneratorAgent(BaseReproAgent):
    """
    Generator agent for PoC creation.

    Responsibilities:
    - Generate PoC code using LLM
    - Iterate and refine based on feedback
    - Use templates and patterns from similar cases

    Uses:
    - LLMService for intelligent generation
    - Episode memory for similar case lookup
    - Semantic memory for exploitation patterns
    """

    name = "generator"
    system_prompt_file = "generator_system.txt"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.semantic_memory: Optional[SemanticMemory] = None
        self.episode_memory: Optional[EpisodeMemory] = None
        self.max_iterations = 3
        self._regression_analyzer = RegressionTestAnalyzer()

        # NEW: Initialize template library
        self._template_library: Optional[PoCTemplateLibrary] = None
        try:
            self._template_library = PoCTemplateLibrary()
            logger.info(f"Loaded {len(self._template_library.list_templates())} PoC templates")
        except ImportError:
            logger.warning("PoCTemplateLibrary not available. Template-based generation will be skipped.")


    def set_memory(
        self,
        semantic_memory: SemanticMemory = None,
        episode_memory: EpisodeMemory = None,
    ) -> None:
        """Set memory systems."""
        self.semantic_memory = semantic_memory
        self.episode_memory = episode_memory

    def _register_handlers(self) -> None:
        """Register message handlers."""
        self._message_handlers = {
            "generate": self._handle_generate,
            "generate_candidates": self._handle_generate_candidates,
            "refine": self._handle_refine,
        }

    def _handle_generate(self, msg: AgentMessage) -> AgentMessage:
        """Handle generate request."""
        analysis = msg.payload.get("analysis", {})
        cve_info = msg.payload.get("cve_info", {})

        try:
            result = self.run({
                "analysis": analysis,
                "cve_info": cve_info,
            })

            return msg.create_response(
                sender=self.name,
                payload={"result": result},
                success=True,
            )
        except Exception as e:
            logger.exception(f"Generation failed: {e}")
            return msg.create_response(
                sender=self.name,
                payload={"error": str(e)},
                success=False,
            )

    def _handle_generate_candidates(self, msg: AgentMessage) -> AgentMessage:
        """Handle generate_candidates request."""
        analysis = msg.payload.get("analysis", {})
        cve_info = msg.payload.get("cve_info", {})
        num_candidates = msg.payload.get("num_candidates", 3)

        # Convert analysis to AnalysisResult if dict
        from ...plugins.base import AnalysisResult
        if isinstance(analysis, dict):
            analysis_result = AnalysisResult(
                vulnerability_type=analysis.get("vulnerability_type", ""),
                component=analysis.get("component", ""),
                root_cause=analysis.get("root_cause", ""),
                trigger_conditions=analysis.get("trigger_conditions", []),
                trigger_approach=analysis.get("trigger_approach", ""),
                poc_strategy=analysis.get("poc_strategy", ""),
                confidence=analysis.get("confidence", 0.0),
            )
        else:
            analysis_result = analysis

        try:
            candidates = self.generate_candidates(
                analysis=analysis_result,
                cve_info=cve_info,
                num_candidates=num_candidates,
                parallel=parallel
            )

            return msg.create_response(
                sender=self.name,
                payload={"result": candidates},
                success=True,
            )
        except Exception as e:
            logger.exception(f"Candidate generation failed: {e}")
            return msg.create_response(
                sender=self.name,
                payload={"error": str(e)},
                success=False,
            )

    def _handle_refine(self, msg: AgentMessage) -> AgentMessage:
        """Handle refine request (improve existing PoC)."""
        poc = msg.payload.get("poc", {})
        feedback = msg.payload.get("feedback", "")
        analysis = msg.payload.get("analysis", {})

        try:
            result = self.refine(poc, feedback, analysis)
            return msg.create_response(
                sender=self.name,
                payload={"result": result},
                success=True,
            )
        except Exception as e:
            logger.exception(f"Refinement failed: {e}")
            return msg.create_response(
                sender=self.name,
                payload={"error": str(e)},
                success=False,
            )

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate PoC based on analysis.

        Args:
            context: Contains analysis, cve_info

        Returns:
            PoC result dictionary
        """
        self.set_state(AgentState.RUNNING)

        analysis = context.get("analysis", {})
        cve_info = context.get("cve_info", {})

        # Convert analysis to AnalysisResult if dict
        if isinstance(analysis, dict):
            analysis_result = AnalysisResult(
                vulnerability_type=analysis.get("vulnerability_type", ""),
                component=analysis.get("component", ""),
                root_cause=analysis.get("root_cause", ""),
                trigger_conditions=analysis.get("trigger_conditions", []),
                trigger_approach=analysis.get("trigger_approach", ""),
                poc_strategy=analysis.get("poc_strategy", ""),
                confidence=analysis.get("confidence", 0.0),
            )
        else:
            analysis_result = analysis

        # Check if we have LLM service
        if self._llm_service:
            result = self._generate_with_llm(analysis_result, cve_info)
        else:
            # Fallback to plugin-based generation
            result = self._generate_with_plugin(analysis_result, cve_info)

        self.set_state(AgentState.COMPLETED)
        return result

    def _generate_with_llm(
        self,
        analysis: AnalysisResult,
        cve_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate PoC using LLM.
        
        Priority:
        1. Regression test extraction
        2. Template-based generation (Phase 3.1)
        3. LLM generation (fallback)
        """
        cve_id = cve_info.get('cve_id', 'unknown')
        print(f"  [Generator] Generating PoC for {cve_id} with LLM...")
        print(f"  [Generator] Component: {analysis.component}, Type: {analysis.vulnerability_type}")
        logger.info(f"Generating PoC with LLM for {cve_id}")

        # Priority 1: Check for regression tests in patches first
        regression_poc = self._try_extract_regression_test(cve_info)
        if regression_poc:
            print(f"  [Generator] ✓ Found regression test! Using as PoC template")
            # Still use LLM to enhance/explain the test
            return self._enhance_regression_test_with_llm(regression_poc, analysis, cve_id)
        
        # Priority 2: Try template-based generation (Phase 3.1)
        if self._template_library:
            template_poc = self._try_template_generation(analysis, cve_info)
            if template_poc:
                print(f"  [Generator] ✓ Generated PoC from template")
                return template_poc

        # Prepare context from similar cases
        similar_code_examples = self._get_similar_examples(analysis)

        # Prepare knowledge context
        knowledge_context = self._prepare_knowledge_context(analysis)

        # Create session with context
        additional_context = ""
        if knowledge_context:
            additional_context = f"Relevant exploitation knowledge:\n{knowledge_context}"

        self._create_session(additional_context=additional_context)

        # If we have similar examples, provide them
        if similar_code_examples:
            examples_text = "\n\n".join([
                f"Example {i+1}:\n```\n{ex}\n```"
                for i, ex in enumerate(similar_code_examples[:2])
            ])
            self._llm_chat(
                f"Here are some similar PoC examples for reference:\n{examples_text}",
                use_tools=False,
            )

        # Build generation prompt
        cve_id = cve_info.get("cve_id", "Unknown")

        generation_prompt = f"""Generate a PoC for this vulnerability:

CVE ID: {cve_id}
Component: {analysis.component}
Vulnerability Type: {analysis.vulnerability_type}
Root Cause: {analysis.root_cause}

Trigger Conditions:
{chr(10).join('- ' + c for c in analysis.trigger_conditions) if analysis.trigger_conditions else '- See root cause'}

Trigger Approach: {analysis.trigger_approach}
PoC Strategy: {analysis.poc_strategy}

Generate a {"JavaScript" if analysis.component.lower() in ["v8", "javascript"] else "HTML/JavaScript"} PoC that:
1. Sets up the vulnerable condition
2. Triggers the vulnerability
3. Demonstrates the impact (crash, memory corruption, etc.)

Include comments explaining each step."""

        # Get LLM response
        print(f"  [Generator] Sending to LLM...")
        response = self._llm_chat(generation_prompt, use_tools=True)
        print(f"  [Generator] LLM response received ({len(response)} chars)")

        # Parse response
        result = self._parse_generation_response(response, analysis, cve_id)
        print(f"  [Generator] PoC generated: {len(result.get('code', ''))} chars, language: {result.get('language', 'unknown')}")

        return result

    def generate_candidates(
        self,
        analysis: AnalysisResult,
        cve_info: Dict[str, Any],
        num_candidates: int = 3,
        parallel: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Generate multiple candidate PoCs with different strategies.
        
        Args:
            analysis: Vulnerability analysis
            cve_info: CVE information
            num_candidates: Number of candidates to generate (default: 3)
            parallel: Whether to generate in parallel (default: False)
            
        Returns:
            List of PoC result dictionaries
        """
        logger.info(f"[Generator] Generating {num_candidates} candidate PoCs")
        
        # Define different strategies
        strategies = [
            {
                "name": "Direct Trigger",
                "focus": "Directly trigger the vulnerability with minimal setup",
                "style": "concise and focused"
            },
            {
                "name": "Memory Spray",
                "focus": "Use memory spraying techniques to increase reliability",
                "style": "include heap manipulation and GC control"
            },
            {
                "name": "JIT Optimization",
                "focus": "Leverage JIT compilation and optimization",
                "style": "use %OptimizeFunctionOnNextCall and type confusion"
            },
            {
                "name": "Race Condition",
                "focus": "Exploit timing and concurrency issues",
                "style": "use Workers or async operations"
            },
            {
                "name": "Object Confusion",
                "focus": "Create object type confusion scenarios",
                "style": "manipulate prototypes and object layouts"
            },
        ]
        
        # Select strategies based on vulnerability type
        selected_strategies = self._select_strategies(
            analysis.vulnerability_type,
            strategies,
            num_candidates
        )
        
        candidates = []
        
        # Try template-based first
        if self._template_library:
            template_poc = self._try_template_generation(analysis, cve_info)
            if template_poc:
                template_poc["strategy"] = "Template-based"
                candidates.append(template_poc)
                logger.info(f"  [Generator] ✓ Candidate 1: Template-based")
        
        # Generate remaining candidates with different strategies
        def _gen_poc(strat):
            try:
                poc_res = self._generate_with_strategy(analysis, cve_info, strat)
                poc_res["strategy"] = strat["name"]
                return poc_res
            except Exception as e:
                logger.warning(f"  [Generator] ✗ Failed to generate {strat['name']}: {e}")
                return None

        if parallel and len(selected_strategies) > 0:
            logger.info(f"  [Generator] Launching {len(selected_strategies)} strategies in parallel...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(selected_strategies), 5)) as executor:
                futures = [executor.submit(_gen_poc, s) for s in selected_strategies]
                for future in concurrent.futures.as_completed(futures):
                    poc = future.result()
                    if poc:
                        candidates.append(poc)
                        logger.info(f"  [Generator] ✓ Candidate {len(candidates)}: {poc['strategy']}")
                        if len(candidates) >= num_candidates:
                            break
        else:
            for strategy in selected_strategies:
                if len(candidates) >= num_candidates:
                    break
                poc = _gen_poc(strategy)
                if poc:
                    candidates.append(poc)
                    logger.info(f"  [Generator] ✓ Candidate {len(candidates)}: {strategy['name']}")
        
        # If we don't have enough, generate generic ones
        while len(candidates) < num_candidates:
            try:
                poc = self._generate_with_llm(analysis, cve_info)
                poc["strategy"] = f"Generic #{len(candidates) + 1}"
                candidates.append(poc)
            except:
                break
        
        logger.info(f"[Generator] Generated {len(candidates)} candidates")
        return candidates

    def _select_strategies(
        self,
        vuln_type: str,
        all_strategies: List[Dict],
        count: int
    ) -> List[Dict]:
        """
        Select most relevant strategies based on vulnerability type.
        """
        vuln_type_lower = vuln_type.lower()
        
        # Priority mapping
        priority_map = {
            "type-confusion": ["JIT Optimization", "Object Confusion", "Direct Trigger"],
            "use-after-free": ["Memory Spray", "Object Confusion", "Direct Trigger"],
            "race-condition": ["Race Condition", "Direct Trigger", "Memory Spray"],
            "bounds-check": ["JIT Optimization", "Direct Trigger", "Memory Spray"],
        }
        
        # Find matching priorities
        priorities = []
        for key, strats in priority_map.items():
            if key in vuln_type_lower:
                priorities = strats
                break
        
        # Select strategies in priority order
        selected = []
        for priority_name in priorities:
            for strategy in all_strategies:
                if strategy["name"] == priority_name:
                    selected.append(strategy)
                    break
            if len(selected) >= count:
                break
        
        # Fill remaining with other strategies
        for strategy in all_strategies:
            if strategy not in selected:
                selected.append(strategy)
            if len(selected) >= count:
                break
        
        return selected[:count]

    def _generate_with_strategy(
        self,
        analysis: AnalysisResult,
        cve_info: Dict[str, Any],
        strategy: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Generate PoC with a specific strategy.
        """
        # Prepare knowledge context
        knowledge_context = self._prepare_knowledge_context(analysis)
        additional_context = f"Relevant exploitation knowledge:\n{knowledge_context}" if knowledge_context else ""
        
        self._create_session(additional_context=additional_context)
        
        cve_id = cve_info.get("cve_id", "Unknown")
        
        # Strategy-specific prompt
        generation_prompt = f"""Generate a PoC for this vulnerability using the '{strategy['name']}' strategy:

CVE ID: {cve_id}
Component: {analysis.component}
Vulnerability Type: {analysis.vulnerability_type}
Root Cause: {analysis.root_cause}

Strategy Focus: {strategy['focus']}
Style: {strategy['style']}

Trigger Conditions:
{chr(10).join('- ' + c for c in analysis.trigger_conditions) if analysis.trigger_conditions else '- See root cause'}

Generate a {"JavaScript" if analysis.component.lower() in ["v8", "javascript"] else "HTML/JavaScript"} PoC that:
1. Implements the {strategy['name']} approach
2. {strategy['focus']}
3. Demonstrates the impact (crash, memory corruption, etc.)

Include comments explaining each step."""
        
        response = self._llm_chat(generation_prompt, use_tools=True)
        return self._parse_generation_response(response, analysis, cve_id)


    def _generate_with_plugin(
        self,
        analysis: AnalysisResult,
        cve_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Fallback to plugin-based generation."""
        logger.info(f"Generating with plugin for component: {analysis.component}")

        # Get knowledge context
        knowledge = ""
        if self.semantic_memory:
            knowledge = self.semantic_memory.get_knowledge_for_context(
                component=analysis.component,
                vuln_type=analysis.vulnerability_type,
            )

        # Find matching plugin
        registry = get_registry()
        component = analysis.component.lower()

        if component in ["v8", "javascript", "jit", "wasm"]:
            plugin = registry.get_generator("v8")
        else:
            plugin = registry.get_generator("blink")

        if not plugin:
            generators = registry.list_generators()
            if generators:
                plugin = registry.get_generator(generators[0].get("name", ""))

        if plugin:
            result = plugin.generate(
                analysis=analysis,
                cve_info=cve_info,
                knowledge=knowledge,
            )
            return result.to_dict() if hasattr(result, 'to_dict') else result
        else:
            return self._basic_generation(analysis, cve_info)

    def refine(
        self,
        poc: Dict[str, Any],
        feedback: str,
        analysis: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Refine an existing PoC based on feedback.

        Args:
            poc: Current PoC code and metadata
            feedback: Feedback from verification/critic
            analysis: Original analysis (optional)

        Returns:
            Refined PoC result
        """
        self.set_state(AgentState.RUNNING)
        print(f"  [Generator] Refining PoC based on feedback...")

        if not self._llm_service:
            # No LLM, can't refine
            print(f"  [Generator] No LLM service, cannot refine")
            self.set_state(AgentState.COMPLETED)
            return poc

        logger.info("Refining PoC based on feedback")

        # Create or reuse session
        if not self._llm_session:
            self._create_session()

        current_code = poc.get("code", "")

        refine_prompt = f"""The current PoC needs improvement.

Current PoC:
```
{current_code}
```

Feedback:
{feedback}

Please improve the PoC to address the feedback. Keep what works and fix what doesn't."""

        response = self._llm_chat(refine_prompt, use_tools=True)

        # Parse refined code
        result = self._parse_generation_response(
            response,
            analysis if analysis else {},
            poc.get("cve_id", "Unknown"),
        )

        # Mark as refined
        result["refined"] = True
        result["original_code"] = current_code

        self.set_state(AgentState.COMPLETED)
        return result

    def _get_similar_examples(self, analysis: AnalysisResult) -> List[str]:
        """Get similar PoC examples from episode memory."""
        examples = []

        if self.episode_memory:
            cases = self.episode_memory.find_similar(
                component=analysis.component,
                vuln_type=analysis.vulnerability_type,
                limit=3,
            )
            for case in cases:
                if case.poc_result and case.poc_result.get("code"):
                    examples.append(case.poc_result["code"])

        return examples

    def _prepare_knowledge_context(self, analysis: AnalysisResult) -> str:
        """Prepare knowledge context for generation."""
        chunks = []

        if self.semantic_memory:
            # Get component-specific exploitation knowledge
            comp_knowledge = self.semantic_memory.get_component_knowledge(
                analysis.component
            )
            if comp_knowledge and hasattr(comp_knowledge, 'exploitation_primitives'):
                chunks.append(f"Exploitation primitives for {analysis.component}:\n{comp_knowledge.exploitation_primitives}")

            # Get vulnerability type patterns
            vuln_knowledge = self.semantic_memory.get_vuln_knowledge(
                analysis.vulnerability_type
            )
            if vuln_knowledge and hasattr(vuln_knowledge, 'exploitation_patterns'):
                chunks.append(f"Exploitation patterns for {analysis.vulnerability_type}:\n{vuln_knowledge.exploitation_patterns}")

        return "\n\n".join(chunks)

    def _parse_generation_response(
        self,
        response: str,
        analysis: Any,
        cve_id: str,
    ) -> Dict[str, Any]:
        """Parse LLM generation response."""
        result = {
            "code": "",
            "language": "javascript",
            "target_version": "",
            "expected_behavior": "Crash or memory corruption",
            "explanation": "",
            "success": True,
            "notes": [],
        }

        # Try to extract structured output
        code_match = re.search(r"<poc_code>(.*?)</poc_code>", response, re.DOTALL)
        if code_match:
            result["code"] = code_match.group(1).strip()
        else:
            # Try to extract code blocks
            code_blocks = re.findall(r"```(?:javascript|html|js)?\n(.*?)```", response, re.DOTALL)
            if code_blocks:
                # Use the longest code block
                result["code"] = max(code_blocks, key=len).strip()
            else:
                # Use entire response as code
                result["code"] = response.strip()

        # Extract explanation
        explain_match = re.search(r"<explanation>(.*?)</explanation>", response, re.DOTALL)
        if explain_match:
            result["explanation"] = explain_match.group(1).strip()

        # Extract expected behavior
        behavior_match = re.search(r"<expected_behavior>(.*?)</expected_behavior>", response, re.DOTALL)
        if behavior_match:
            result["expected_behavior"] = behavior_match.group(1).strip()

        # Determine language from code content
        if "<html" in result["code"].lower() or "<!doctype" in result["code"].lower():
            result["language"] = "html"
        elif "function" in result["code"] or "const " in result["code"]:
            result["language"] = "javascript"

        # Add metadata
        result["cve_id"] = cve_id
        if isinstance(analysis, AnalysisResult):
            result["component"] = analysis.component
            result["vulnerability_type"] = analysis.vulnerability_type
        elif isinstance(analysis, dict):
            result["component"] = analysis.get("component", "")
            result["vulnerability_type"] = analysis.get("vulnerability_type", "")

        return result

    def _basic_generation(
        self,
        analysis: AnalysisResult,
        cve_info: dict,
    ) -> dict:
        """Generate basic PoC without LLM or plugin."""
        cve_id = cve_info.get("cve_id", "CVE-XXXX-XXXX")

        code = f'''// {cve_id} - PoC
// Component: {analysis.component}
// Vulnerability: {analysis.vulnerability_type}
// Root Cause: {analysis.root_cause}

function poc() {{
    // TODO: Implement based on analysis
    // Trigger: {analysis.trigger_approach}
    // Strategy: {analysis.poc_strategy}

    console.log("PoC for {cve_id}");
}}

poc();
'''

        return {
            "code": code,
            "language": language,
            "confidence": 0.7,
            "description": f"Generated PoC for {analysis.vulnerability_type}",
        }

    def _try_extract_regression_test(self, cve_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Try to extract regression test from patch.
        
        Args:
            cve_info: CVE information including patches
            
        Returns:
            PoC dict from regression test, or None
        """
        patches = cve_info.get("patches", [])
        
        if not patches:
            return None
        
        # Try each patch
        for patch in patches:
            patch_diff = patch.get("diff_content", "")
            if not patch_diff:
                continue
            
            # Extract regression tests
            test_cases = self._regression_analyzer.extract_from_patch(
                patch_diff,
                patch
            )
            
            if test_cases:
                # Use the first regression test found
                test_case = test_cases[0]
                logger.info(f"Found regression test: {test_case.test_name}")
                print(f"    ✓ Found regression test: {test_case.test_name}")
                
                # Convert to PoC
                poc = self._regression_analyzer.convert_to_poc(test_case)
                poc["from_regression_test"] = True
                poc["test_file"] = test_case.file_path
                
                return poc
        
        return None

    def _enhance_regression_test_with_llm(
        self,
        regression_poc: Dict[str, Any],
        analysis: AnalysisResult,
        cve_id: str,
    ) -> Dict[str, Any]:
        """
        Enhance regression test PoC with LLM analysis.
        
        Args:
            regression_poc: PoC extracted from regression test
            analysis: Vulnerability analysis
            cve_id: CVE ID
            
        Returns:
            Enhanced PoC
        """
        if not self._llm_service:
            # No LLM, just return the regression test as-is
            return regression_poc
        
        logger.info("Enhancing regression test with LLM")
        print(f"  [Generator] Enhancing regression test with LLM...")
        
        self._create_session()
        
        test_code = regression_poc.get("code", "")
        test_name = regression_poc.get("test_name", "unknown")
        
        enhance_prompt = f"""I found a regression test for this vulnerability.
Please analyze it and add detailed comments explaining:
1. What vulnerability it's testing
2. How it triggers the vulnerability
3. What the expected behavior is

Regression Test ({test_name}):
```
{test_code[:2000]}
```

Vulnerability Analysis:
- Type: {analysis.vulnerability_type}
- Root Cause: {analysis.root_cause}
- Component: {analysis.component}

Provide the enhanced code with detailed comments."""

        response = self._llm_chat(enhance_prompt, use_tools=False)
        
        # Parse enhanced code
        enhanced = self._parse_generation_response(response, analysis, cve_id)
        
        # Merge with original
        result = regression_poc.copy()
        result.update(enhanced)
        result["enhanced_by_llm"] = True
        result["original_test_code"] = test_code
        
        return result

