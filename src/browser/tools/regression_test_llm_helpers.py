"""
Regression Test LLM Helper Methods

LLM-assisted analysis for regression tests (Phase 2.3).
These methods are part of RegressionTestAnalyzer.
"""

import re
import logging
from typing import Dict, Any, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TestAnalysis:
    """Analysis results from LLM."""
    test_intent: str
    minimal_steps: List[str]
    critical_values: Dict[str, Any]
    simplified_poc: str
    confidence: float


class RegressionTestLLMHelpers:
    """
    LLM helper methods for regression test analysis.
    
    These methods can be mixed into RegressionTestAnalyzer.
    """
    
    def analyze_test_intent(
        self,
        test_case,
        vuln_type: str = None,
        root_cause: str = None
    ) -> TestAnalysis:
        """
        Analyze test intent using LLM.
        
        Args:
            test_case: TestCase to analyze
            vuln_type: Known vulnerability type
            root_cause: Known root cause
            
        Returns:
            TestAnalysis with LLM results
        """
        if not self.llm_service:
            logger.warning("No LLM service available, using heuristics")
            return self._heuristic_analysis(test_case)
        
        # Build prompt
        prompt = self._build_analysis_prompt(test_case, vuln_type, root_cause)
        
        try:
            # Call LLM
            response = self.llm_service.generate(prompt, temperature=0.3)
            
            # Parse response
            test_intent = self._extract_tag(response, "test_intent")
            steps_text = self._extract_tag(response, "minimal_steps")
            values_text = self._extract_tag(response, "critical_values")
            simplified_poc = self._extract_tag(response, "simplified_poc")
            
            minimal_steps = self._parse_steps(steps_text)
            critical_values = self._parse_values(values_text)
            
            return TestAnalysis(
                test_intent=test_intent,
                minimal_steps=minimal_steps,
                critical_values=critical_values,
                simplified_poc=simplified_poc,
                confidence=0.8
            )
            
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return self._heuristic_analysis(test_case)
    
    def _build_analysis_prompt(
        self,
        test_case,
        vuln_type: str = None,
        root_cause: str = None
    ) -> str:
        """Build LLM prompt for test analysis."""
        prompt = f"""Analyze this regression test for a security vulnerability:

Test Name: {test_case.test_name}
Language: {test_case.language}
File: {test_case.file_path}

Test Code:
```{test_case.language}
{test_case.code[:2000]}
```"""

        if vuln_type:
            prompt += f"\n\nKnown Vulnerability Type: {vuln_type}"
        
        if root_cause:
            prompt += f"\nKnown Root Cause: {root_cause}"

        prompt += """

Questions:
1. What is this test trying to trigger/demonstrate?
2. What are the minimal steps to reproduce the vulnerability?
3. What values/operations are critical for triggering?
4. Can this be simplified further while still triggering the bug?

Provide:
<test_intent>What the test is demonstrating</test_intent>
<minimal_steps>
1. Step one
2. Step two
...
</minimal_steps>
<critical_values>
key1=value1
key2=value2
</critical_values>
<simplified_poc>
Simplified standalone PoC code
</simplified_poc>"""

        return prompt
    
    def _heuristic_analysis(self, test_case) -> TestAnalysis:
        """Fallback heuristic analysis when LLM unavailable."""
        # Extract simple patterns
        steps = []
        if "ArrayBuffer" in test_case.code:
            steps.append("Create ArrayBuffer")
        if "slice" in test_case.code:
            steps.append("Call slice method")
        
        return TestAnalysis(
            test_intent=f"Test for {test_case.test_name}",
            minimal_steps=steps if steps else ["See test code"],
            critical_values={},
            simplified_poc=test_case.code,
            confidence=0.3  # Low confidence for heuristics
        )
    
    def _extract_tag(self, text: str, tag: str) -> str:
        """Extract content from XML-style tags."""
        pattern = rf"<{tag}>(.*?)</{tag}>"
        match = re.search(pattern, text, re.DOTALL)
        return match.group(1).strip() if match else ""
    
    def _parse_steps(self, steps_text: str) -> List[str]:
        """Parse numbered steps from text."""
        steps = []
        for line in steps_text.split('\n'):
            line = line.strip()
            if line:
                # Remove numbering
                line = re.sub(r'^\d+\.\s*', '', line)
                line = re.sub(r'^[-*]\s*', '', line)
                if line:
                    steps.append(line)
        return steps
    
    def _parse_values(self, values_text: str) -> Dict[str, Any]:
        """Parse key=value pairs from text."""
        values = {}
        for line in values_text.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                values[key.strip()] = value.strip()
        return values
    
    def generate_minimal_poc(
        self,
        test_case,
        analysis: TestAnalysis
    ) -> Dict[str, Any]:
        """
        Generate minimal PoC from test analysis.
        
        Args:
            test_case: Original test case
            analysis: Test analysis results
            
        Returns:
            Minimal PoC dictionary
        """
        # Use simplified PoC from LLM if available
        if analysis.simplified_poc and len(analysis.simplified_poc) > 20:
            code = analysis.simplified_poc
        else:
            # Fallback to original conversion
            poc = self.convert_to_poc(test_case)
            code = poc.get("code", "")
        
        return {
            "code": code,
            "language": test_case.language,
            "source": "regression_test_llm_simplified",
            "test_name": test_case.test_name,
            "test_intent": analysis.test_intent,
            "minimal_steps": analysis.minimal_steps,
            "critical_values": analysis.critical_values,
            "confidence": analysis.confidence,
        }
