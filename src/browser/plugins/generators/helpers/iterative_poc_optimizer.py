"""
Iterative PoC Optimizer

Uses LLM feedback loop to automatically improve PoCs until they succeed.
"""

import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class OptimizationResult:
    """Result from PoC optimization."""
    final_poc: str
    iterations: int
    success: bool
    improvements: list
    final_error: Optional[str] = None


class IterativePoCOptimizer:
    """
    Iteratively optimizes PoC using LLM feedback.
    
    Process:
    1. Run PoC
    2. If failed, extract error/feedback
    3. Use LLM to analyze and improve
    4. Retry (max 3 iterations)
    """
    
    def __init__(self, llm_service, verifier, max_iterations=3):
        """
        Initialize optimizer.
        
        Args:
            llm_service: LLM service for improvement
            verifier: Verifier for running PoCs
            max_iterations: Maximum optimization iterations
        """
        self.llm_service = llm_service
        self.verifier = verifier
        self.max_iterations = max_iterations
    
    def optimize(
        self,
        initial_poc: str,
        analysis: Dict[str, Any],
        language: str = "javascript"
    ) -> OptimizationResult:
        """
        Optimize PoC through iterative refinement.
        
        Args:
            initial_poc: Initial PoC code
            analysis: Vulnerability analysis context
            language: PoC language
            
        Returns:
            OptimizationResult with final PoC and metadata
        """
        current_poc = initial_poc
        improvements = []
        
        logger.info("Starting iterative PoC optimization...")
        
        for iteration in range(self.max_iterations):
            logger.info(f"Iteration {iteration + 1}/{self.max_iterations}")
            
            # 1. Run PoC
            result = self._run_poc(current_poc, language)
            
            # 2. Check if successful
            if self._is_successful(result):
                logger.info(f"✓ PoC succeeded on iteration {iteration + 1}")
                return OptimizationResult(
                    final_poc=current_poc,
                    iterations=iteration + 1,
                    success=True,
                    improvements=improvements
                )
            
            # 3. Extract feedback
            feedback = self._extract_feedback(result)
            logger.info(f"Feedback: {feedback[:200]}...")
            
            # 4. Use LLM to improve
            if not self.llm_service:
                logger.warning("No LLM service available for optimization")
                break
            
            improved_poc = self._improve_with_llm(
                current_poc, feedback, analysis, iteration
            )
            
            if not improved_poc or improved_poc == current_poc:
                logger.warning("LLM failed to improve PoC")
                break
            
            improvements.append({
                "iteration": iteration + 1,
                "feedback": feedback,
                "changes": "LLM improved code"
            })
            
            current_poc = improved_poc
        
        # Max iterations reached without success
        logger.warning(f"PoC optimization failed after {self.max_iterations} iterations")
        return OptimizationResult(
            final_poc=current_poc,
            iterations=self.max_iterations,
            success=False,
            improvements=improvements,
            final_error=feedback if 'feedback' in locals() else "Unknown error"
        )
    
    def _run_poc(self, poc_code: str, language: str) -> Dict[str, Any]:
        """Run PoC and return result."""
        try:
            # Use verifier to run PoC
            result = self.verifier.verify_poc(poc_code, language)
            return result
        except Exception as e:
            logger.error(f"Error running PoC: {e}")
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "crashed": False
            }
    
    def _is_successful(self, result: Dict[str, Any]) -> bool:
        """
        Determine if PoC execution was successful.
        
        Success indicators:
        - Crash detected
        - ASAN error
        - Non-zero exit code
        - Expected vulnerability behavior
        """
        # 1. Explicit success flag
        if result.get("success"):
            return True
        
        # 2. Crash detected
        if result.get("crashed"):
            return True
        
        # 3. ASAN errors (common vulnerability indicators)
        output = result.get("output", "").lower()
        asan_patterns = [
            "heap-buffer-overflow",
            "heap-use-after-free",
            "stack-buffer-overflow",
            "use-after-free",
            "double-free",
            "asan",
        ]
        
        for pattern in asan_patterns:
            if pattern in output:
                return True
        
        # 4. Non-zero exit code (potential crash)
        if result.get("exit_code", 0) != 0:
            # But not simple syntax errors
            if "syntaxerror" not in output:
                return True
        
        return False
    
    def _extract_feedback(self, result: Dict[str, Any]) -> str:
        """Extract useful feedback from execution result."""
        feedback_parts = []
        
        # Error message
        if result.get("error"):
            feedback_parts.append(f"Error: {result['error']}")
        
        # Output (last 500 chars)
        output = result.get("output", "")
        if output:
            feedback_parts.append(f"Output:\n{output[-500:]}")
        
        # Exit code
        exit_code = result.get("exit_code")
        if exit_code is not None:
            feedback_parts.append(f"Exit code: {exit_code}")
        
        # Stack trace if available
        if "stack_trace" in result:
            feedback_parts.append(f"Stack trace:\n{result['stack_trace'][:300]}")
        
        return "\n\n".join(feedback_parts) if feedback_parts else "No feedback available"
    
    def _improve_with_llm(
        self,
        current_poc: str,
        feedback: str,
        analysis: Dict[str, Any],
        iteration: int
    ) -> Optional[str]:
        """
        Use LLM to improve PoC based on feedback.
        
        Args:
            current_poc: Current PoC code
            feedback: Execution feedback
            analysis: Vulnerability analysis
            iteration: Current iteration number
            
        Returns:
            Improved PoC code or None
        """
        vuln_type = analysis.get("vulnerability_type", "Unknown")
        root_cause = analysis.get("root_cause", "Unknown")
        
        prompt = f"""The current PoC failed. Please analyze the error and provide an improved version.

Current PoC (Iteration {iteration + 1}/{self.max_iterations}):
```javascript
{current_poc[:2000]}
```

Execution Result:
{feedback[:1000]}

Vulnerability Context:
- Type: {vuln_type}
- Root Cause: {root_cause}

Please:
1. Analyze why the PoC failed
2. Identify specific issues (syntax errors, logic errors, missing setup, etc.)
3. Provide a corrected version

Format your response as:
<analysis>
Why it failed and what needs to be fixed
</analysis>

<improved_poc>
Complete improved PoC code
</improved_poc>"""

        try:
            response = self.llm_service.generate(prompt, temperature=0.3)
            
            # Extract improved PoC
            improved = self._extract_tag(response, "improved_poc")
            
            if improved and len(improved) > 20:
                logger.info("LLM provided improved PoC")
                return improved
            else:
                logger.warning("LLM response did not contain valid improved PoC")
                return None
                
        except Exception as e:
            logger.error(f"LLM improvement failed: {e}")
            return None
    
    def _extract_tag(self, text: str, tag: str) -> str:
        """Extract content from XML-style tags."""
        import re
        pattern = rf"<{tag}>(.*?)</{tag}>"
        match = re.search(pattern, text, re.DOTALL)
        return match.group(1).strip() if match else ""
