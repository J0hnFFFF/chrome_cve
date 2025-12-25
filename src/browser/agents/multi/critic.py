"""
Critic Agent

Reviews and evaluates results from other agents using LLM.
Provides intelligent feedback for improvement and decides on retries.
"""

import re
import logging
from typing import Dict, Any, List

from .base import BaseReproAgent, AgentMessage, AgentState

logger = logging.getLogger(__name__)


class CriticAgent(BaseReproAgent):
    """
    Critic agent for result evaluation.

    Responsibilities:
    - Review analysis results using LLM
    - Evaluate PoC quality
    - Assess verification results
    - Provide intelligent feedback
    - Decide on retries

    Uses:
    - LLMService for intelligent review
    - Historical context for consistency
    """

    name = "critic"
    system_prompt_file = "critic_system.txt"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.review_history: List[Dict[str, Any]] = []

    def _register_handlers(self) -> None:
        """Register message handlers."""
        self._message_handlers = {
            "review": self._handle_review,
        }

    def _handle_review(self, msg: AgentMessage) -> AgentMessage:
        """Handle review request."""
        stage = msg.payload.get("stage", "")
        result = msg.payload.get("result", {})
        context = msg.payload.get("context", {})

        try:
            review = self.run({
                "stage": stage,
                "result": result,
                "context": context,
            })

            return msg.create_response(
                sender=self.name,
                payload=review,
                success=True,
            )
        except Exception as e:
            logger.exception(f"Review failed: {e}")
            return msg.create_response(
                sender=self.name,
                payload={"error": str(e)},
                success=False,
            )

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Review a stage result.

        Args:
            context: Contains stage, result, additional context

        Returns:
            Review result with approval and feedback
        """
        self.set_state(AgentState.RUNNING)

        stage = context.get("stage", "")
        result = context.get("result", {})
        additional_context = context.get("context", {})

        # Use LLM for review if available
        if self._llm_service:
            review = self._llm_review(stage, result, additional_context)
        else:
            # Fallback to rule-based review
            if stage == "analysis":
                review = self._review_analysis(result)
            elif stage == "generation":
                review = self._review_generation(result)
            elif stage == "verification":
                review = self._review_verification(result)
            else:
                review = self._generic_review(result)

        # Store review history
        self.review_history.append({
            "stage": stage,
            "review": review,
        })

        self.set_state(AgentState.COMPLETED)
        return review

    def _llm_review(
        self,
        stage: str,
        result: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Use LLM for intelligent review."""
        print(f"  [Critic] Reviewing {stage} result with LLM...")
        logger.info(f"LLM reviewing {stage} result")

        self._create_session()

        # Build stage-specific review prompt
        if stage == "analysis":
            review_prompt = self._build_analysis_review_prompt(result, context)
        elif stage == "generation":
            review_prompt = self._build_generation_review_prompt(result, context)
        elif stage == "verification":
            review_prompt = self._build_verification_review_prompt(result, context)
        else:
            review_prompt = self._build_generic_review_prompt(stage, result)

        response = self._llm_chat(review_prompt, use_tools=False)

        # Parse LLM response
        review = self._parse_review_response(response, stage)
        print(f"  [Critic] Review result: {'APPROVED' if review.get('approved') else 'NEEDS_REVISION'} (score: {review.get('score', 'N/A')})")

        return review

    def _build_analysis_review_prompt(
        self,
        result: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """Build review prompt for analysis stage."""
        cve_info = context.get("cve_info", {})

        # Handle both dict and CVEInfo object
        if hasattr(cve_info, 'cve_id'):
            cve_id = cve_info.cve_id
            description = getattr(cve_info, 'description', 'N/A')
        else:
            cve_id = cve_info.get('cve_id', 'Unknown') if isinstance(cve_info, dict) else 'Unknown'
            description = cve_info.get('description', 'N/A') if isinstance(cve_info, dict) else 'N/A'

        return f"""Review this vulnerability analysis:

CVE: {cve_id}
Expected from CVE description: {str(description)[:500]}

Analysis Result:
- Vulnerability Type: {result.get('vulnerability_type', 'unknown')}
- Component: {result.get('component', 'unknown')}
- Root Cause: {result.get('root_cause', 'N/A')}
- Trigger Conditions: {result.get('trigger_conditions', [])}
- Trigger Approach: {result.get('trigger_approach', 'N/A')}
- PoC Strategy: {result.get('poc_strategy', 'N/A')}
- Confidence: {result.get('confidence', 0)}

Evaluate:
1. Is the vulnerability type correctly identified?
2. Is the root cause analysis accurate and detailed enough?
3. Are the trigger conditions specific enough for PoC generation?
4. Is the PoC strategy actionable?

Provide your assessment:
<assessment>APPROVE/NEEDS_REVISION</assessment>
<score>0-10</score>
<strengths>What was done well</strengths>
<weaknesses>What needs improvement</weaknesses>
<suggestions>Specific suggestions for improvement</suggestions>"""

    def _build_generation_review_prompt(
        self,
        result: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """Build review prompt for generation stage."""
        analysis = context.get("analysis", {})

        return f"""Review this generated PoC:

Target Vulnerability:
- Type: {analysis.get('vulnerability_type', 'unknown')}
- Component: {analysis.get('component', 'unknown')}
- Root Cause: {analysis.get('root_cause', 'N/A')}

Generated PoC:
```
{result.get('code', 'No code')[:3000]}
```

Language: {result.get('language', 'unknown')}
Expected Behavior: {result.get('expected_behavior', 'N/A')}

Evaluate:
1. Does the code target the identified vulnerability?
2. Is the code syntactically correct and runnable?
3. Does it follow the recommended trigger approach?
4. Are there obvious issues or improvements?

Provide your assessment:
<assessment>APPROVE/NEEDS_REVISION</assessment>
<score>0-10</score>
<strengths>What was done well</strengths>
<weaknesses>What needs improvement</weaknesses>
<suggestions>Specific code improvements</suggestions>"""

    def _build_verification_review_prompt(
        self,
        result: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """Build review prompt for verification stage."""
        analysis = context.get("analysis", {})

        return f"""Review this verification result:

Expected Vulnerability: {analysis.get('vulnerability_type', 'unknown')}

Verification Result:
- Success: {result.get('success', False)}
- Crash Detected: {result.get('crash_detected', False)}
- Reproducibility: {result.get('reproducibility', 'N/A')}
- Runs: {result.get('runs_crashed', 0)}/{result.get('runs_attempted', 0)}
- Crash Type: {result.get('crash_type', 'N/A')}

ASAN Report:
{result.get('asan_report', 'None')[:1500]}

Evaluate:
1. Was the expected vulnerability triggered?
2. Is the crash reproducible enough?
3. Does the crash signature match expectations?
4. Should we try to improve the PoC?

Provide your assessment:
<assessment>APPROVE/NEEDS_REVISION</assessment>
<score>0-10</score>
<strengths>What was done well</strengths>
<weaknesses>What needs improvement</weaknesses>
<suggestions>Suggestions for improvement</suggestions>"""

    def _build_generic_review_prompt(
        self,
        stage: str,
        result: Dict[str, Any],
    ) -> str:
        """Build generic review prompt."""
        return f"""Review this {stage} result:

{result}

Provide your assessment:
<assessment>APPROVE/NEEDS_REVISION</assessment>
<score>0-10</score>
<strengths>What was done well</strengths>
<weaknesses>What needs improvement</weaknesses>
<suggestions>Suggestions for improvement</suggestions>"""

    def _parse_review_response(
        self,
        response: str,
        stage: str,
    ) -> Dict[str, Any]:
        """Parse LLM review response."""
        review = {
            "approved": False,
            "stage": stage,
            "issues": [],
            "suggestions": [],
            "score": 0.5,
        }

        # Extract assessment
        assess_match = re.search(r"<assessment>(.*?)</assessment>", response, re.DOTALL | re.IGNORECASE)
        if assess_match:
            assessment = assess_match.group(1).strip().upper()
            review["approved"] = assessment == "APPROVE"

        # Extract score
        score_match = re.search(r"<score>(.*?)</score>", response, re.DOTALL)
        if score_match:
            try:
                score = float(score_match.group(1).strip())
                review["score"] = score / 10.0  # Normalize to 0-1
            except ValueError:
                pass

        # Extract strengths
        strengths_match = re.search(r"<strengths>(.*?)</strengths>", response, re.DOTALL)
        if strengths_match:
            review["strengths"] = strengths_match.group(1).strip()

        # Extract weaknesses as issues
        weak_match = re.search(r"<weaknesses>(.*?)</weaknesses>", response, re.DOTALL)
        if weak_match:
            weaknesses = weak_match.group(1).strip()
            review["issues"] = [w.strip() for w in weaknesses.split("\n") if w.strip()]
            review["weaknesses"] = weaknesses

        # Extract suggestions
        sugg_match = re.search(r"<suggestions>(.*?)</suggestions>", response, re.DOTALL)
        if sugg_match:
            suggestions = sugg_match.group(1).strip()
            review["suggestions"] = [s.strip() for s in suggestions.split("\n") if s.strip()]
            review["feedback"] = suggestions

        # Store raw response for reference
        review["llm_response"] = response

        return review

    def _review_analysis(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based review of analysis result."""
        issues = []
        suggestions = []

        # Check for required fields
        required = ["vulnerability_type", "component", "root_cause"]
        for field in required:
            if not result.get(field):
                issues.append(f"Missing required field: {field}")

        # Check confidence
        confidence = result.get("confidence", 0)
        if confidence < 0.5:
            suggestions.append("Low confidence - consider gathering more information")

        # Check vulnerability type
        vuln_type = result.get("vulnerability_type", "")
        if vuln_type == "unknown":
            issues.append("Vulnerability type not identified")
            suggestions.append("Analyze patch more carefully for vulnerability patterns")

        # Check trigger conditions
        triggers = result.get("trigger_conditions", [])
        if not triggers:
            suggestions.append("Add specific trigger conditions for PoC generation")

        approved = len(issues) == 0

        return {
            "approved": approved,
            "stage": "analysis",
            "issues": issues,
            "suggestions": suggestions,
            "score": confidence,
        }

    def _review_generation(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based review of generation result."""
        issues = []
        suggestions = []

        code = result.get("code", "")
        if not code:
            issues.append("No PoC code generated")
        elif len(code) < 50:
            issues.append("PoC code appears too short")
            suggestions.append("Add more detailed trigger logic")

        # Check for TODO markers
        if "TODO" in code:
            suggestions.append("PoC contains TODO markers - needs completion")

        approved = len(issues) == 0

        return {
            "approved": approved,
            "stage": "generation",
            "issues": issues,
            "suggestions": suggestions,
            "score": 0.7 if approved else 0.3,
        }

    def _review_verification(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based review of verification result."""
        issues = []
        suggestions = []

        success = result.get("success", False)
        reproducibility = result.get("reproducibility", "")

        if not success:
            issues.append("PoC did not trigger crash")
            suggestions.append("Review trigger conditions and refine PoC")

        if reproducibility in ["intermittent", "frequent"]:
            suggestions.append("Crash is not fully consistent - consider stabilization")

        # Check ASAN report
        asan_report = result.get("asan_report", "")
        if success and not asan_report:
            suggestions.append("Consider using ASAN build for better crash analysis")

        return {
            "approved": success,
            "stage": "verification",
            "issues": issues,
            "suggestions": suggestions,
            "score": 1.0 if success else 0.0,
            "crash_confirmed": success,
        }

    def _generic_review(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Generic review for unknown stages."""
        return {
            "approved": True,
            "stage": "unknown",
            "issues": [],
            "suggestions": [],
            "score": 0.5,
        }

    def get_overall_assessment(self) -> Dict[str, Any]:
        """Get overall assessment from all reviews."""
        if not self.review_history:
            return {"status": "no_reviews"}

        stages = {}
        total_score = 0

        for review in self.review_history:
            stage = review.get("stage", "")
            stage_review = review.get("review", {})
            stages[stage] = stage_review
            total_score += stage_review.get("score", 0)

        avg_score = total_score / len(self.review_history)

        all_approved = all(
            r.get("review", {}).get("approved", False)
            for r in self.review_history
        )

        return {
            "overall_approved": all_approved,
            "average_score": avg_score,
            "stages": stages,
            "total_reviews": len(self.review_history),
        }

    def should_retry(self, stage: str) -> bool:
        """Determine if a stage should be retried based on reviews."""
        for review in reversed(self.review_history):
            if review.get("stage") == stage:
                stage_review = review.get("review", {})
                if not stage_review.get("approved", False):
                    # Not approved and has suggestions
                    return bool(stage_review.get("suggestions"))
        return False

    def get_retry_feedback(self, stage: str) -> str:
        """Get feedback for retry attempt."""
        for review in reversed(self.review_history):
            if review.get("stage") == stage:
                stage_review = review.get("review", {})
                suggestions = stage_review.get("suggestions", [])
                feedback = stage_review.get("feedback", "")

                if feedback:
                    return feedback
                if suggestions:
                    return "\n".join(f"- {s}" for s in suggestions)

        return "Please improve based on previous attempt."
