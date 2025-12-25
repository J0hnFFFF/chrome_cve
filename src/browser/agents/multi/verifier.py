"""
Verifier Agent

Verifies PoC by running in target environment.
Uses LLM for intelligent crash analysis and feedback.
"""

import re
import logging
from typing import Dict, Any, Optional

from .base import BaseReproAgent, AgentMessage, AgentState
from ...plugins import get_registry, PoCResult, VerifyResult
from ...tools.execution import D8Executor, ChromeExecutor, ExecutionResult
from ...tools.debug import CrashAnalyzer

logger = logging.getLogger(__name__)


class VerifierAgent(BaseReproAgent):
    """
    Verifier agent for PoC verification.

    Responsibilities:
    - Run PoC in Chrome/d8
    - Detect and analyze crashes
    - Use LLM for intelligent analysis
    - Provide feedback for PoC improvement

    Uses:
    - D8Executor/ChromeExecutor for execution
    - CrashAnalyzer for crash parsing
    - LLMService for intelligent analysis
    """

    name = "verifier"
    system_prompt_file = "verifier_system.txt"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.chrome_path = config.get("chrome_path") if config else None
        self.d8_path = config.get("d8_path") if config else None
        self.timeout = config.get("timeout", 30) if config else 30
        self.num_runs = config.get("num_runs", 3) if config else 3
        self._crash_analyzer = CrashAnalyzer()

    def _register_handlers(self) -> None:
        """Register message handlers."""
        self._message_handlers = {
            "verify": self._handle_verify,
        }

    def _handle_verify(self, msg: AgentMessage) -> AgentMessage:
        """Handle verify request."""
        poc = msg.payload.get("poc", {})
        analysis = msg.payload.get("analysis", {})
        chrome_path = msg.payload.get("chrome_path", self.chrome_path)
        d8_path = msg.payload.get("d8_path", self.d8_path)

        try:
            result = self.run({
                "poc": poc,
                "analysis": analysis,
                "chrome_path": chrome_path,
                "d8_path": d8_path,
            })

            return msg.create_response(
                sender=self.name,
                payload={"result": result},
                success=True,
            )
        except Exception as e:
            logger.exception(f"Verification failed: {e}")
            return msg.create_response(
                sender=self.name,
                payload={"error": str(e)},
                success=False,
            )

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify PoC.

        Args:
            context: Contains poc, analysis, chrome_path, d8_path

        Returns:
            Verification result dictionary
        """
        self.set_state(AgentState.RUNNING)

        poc_data = context.get("poc", {})
        analysis = context.get("analysis", {})
        chrome_path = context.get("chrome_path") or self.chrome_path
        d8_path = context.get("d8_path") or self.d8_path

        # Convert to PoCResult if dict
        if isinstance(poc_data, dict):
            poc = PoCResult(
                code=poc_data.get("code", ""),
                language=poc_data.get("language", "javascript"),
                target_version=poc_data.get("target_version", ""),
                expected_behavior=poc_data.get("expected_behavior", ""),
            )
        else:
            poc = poc_data

        # Execute PoC
        print(f"  [Verifier] Executing PoC ({poc.language})...")
        execution_results = self._execute_poc(poc, d8_path, chrome_path)
        print(f"  [Verifier] Execution complete: {len(execution_results)} runs")

        # Analyze results
        print(f"  [Verifier] Analyzing execution results...")
        result = self._analyze_execution(execution_results, poc, analysis)

        self.set_state(AgentState.COMPLETED)
        return result

    def _execute_poc(
        self,
        poc: PoCResult,
        d8_path: str,
        chrome_path: str,
    ) -> list[ExecutionResult]:
        """Execute PoC multiple times and collect results."""
        results = []

        # Choose executor based on language
        if poc.language == "javascript" and d8_path:
            try:
                executor = D8Executor(d8_path)
                print(f"  [Verifier] Using d8 executor: {d8_path}")
                logger.info(f"Executing PoC in d8 ({self.num_runs} runs)")

                for i in range(self.num_runs):
                    result = executor.execute(poc.code, timeout=self.timeout)
                    results.append(result)
                    logger.debug(f"Run {i+1}: crashed={result.crashed}, exit={result.exit_code}")

            except Exception as e:
                logger.error(f"D8 execution failed: {e}")

        elif chrome_path:
            try:
                executor = ChromeExecutor(chrome_path)
                print(f"  [Verifier] Using Chrome executor: {chrome_path}")
                logger.info(f"Executing PoC in Chrome ({self.num_runs} runs)")

                for i in range(self.num_runs):
                    if poc.language == "javascript":
                        # Wrap JS in HTML
                        html = f"<html><script>{poc.code}</script></html>"
                        result = executor.execute(html, timeout=self.timeout)
                    else:
                        result = executor.execute(poc.code, timeout=self.timeout)
                    results.append(result)
                    logger.debug(f"Run {i+1}: crashed={result.crashed}, exit={result.exit_code}")

            except Exception as e:
                logger.error(f"Chrome execution failed: {e}")

        return results

    def _analyze_execution(
        self,
        results: list[ExecutionResult],
        poc: PoCResult,
        analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Analyze execution results."""
        if not results:
            return {
                "success": False,
                "crash_detected": False,
                "error_message": "No execution results - missing Chrome/d8 path",
                "runs_attempted": 0,
                "runs_crashed": 0,
                "reproducibility": "N/A",
            }

        # Count crashes
        total_runs = len(results)
        crashed_runs = sum(1 for r in results if r.crashed)

        # Collect crash info
        crash_types = []
        crash_addresses = []
        asan_reports = []
        stack_traces = []

        for r in results:
            if r.crashed:
                if r.crash_type:
                    crash_types.append(r.crash_type)
                if r.crash_address:
                    crash_addresses.append(r.crash_address)
                if r.asan_report:
                    asan_reports.append(r.asan_report)
                if r.stack_trace:
                    stack_traces.append(r.stack_trace)

        # Determine reproducibility
        if crashed_runs == total_runs:
            reproducibility = "consistent"
        elif crashed_runs > total_runs / 2:
            reproducibility = "frequent"
        elif crashed_runs > 0:
            reproducibility = "intermittent"
        else:
            reproducibility = "none"

        # Build result
        verification_result = {
            "success": crashed_runs > 0,
            "crash_detected": crashed_runs > 0,
            "runs_attempted": total_runs,
            "runs_crashed": crashed_runs,
            "reproducibility": reproducibility,
            "crash_type": crash_types[0] if crash_types else "",
            "crash_address": crash_addresses[0] if crash_addresses else "",
            "asan_report": asan_reports[0] if asan_reports else "",
            "stack_trace": stack_traces[0] if stack_traces else "",
        }

        # Use LLM for intelligent analysis if available
        if self._llm_service and crashed_runs > 0:
            print(f"  [Verifier] Crash detected! Analyzing with LLM...")
            intelligent_analysis = self._llm_analyze_crash(
                verification_result,
                poc,
                analysis,
            )
            verification_result.update(intelligent_analysis)
            print(f"  [Verifier] LLM verdict: {intelligent_analysis.get('llm_verdict', 'N/A')}")
        elif crashed_runs == 0 and self._llm_service:
            # Get suggestions for why it didn't crash
            print(f"  [Verifier] No crash detected, getting LLM suggestions...")
            suggestions = self._llm_suggest_improvements(poc, analysis, results)
            verification_result["suggestions"] = suggestions

        print(f"  [Verifier] Result: crashes={crashed_runs}/{total_runs}, reproducibility={reproducibility}")
        return verification_result

    def _llm_analyze_crash(
        self,
        verification: Dict[str, Any],
        poc: PoCResult,
        analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Use LLM to analyze crash results."""
        logger.info("Using LLM to analyze crash")

        self._create_session()

        expected_vuln = analysis.get("vulnerability_type", "unknown")

        prompt = f"""Analyze this crash result:

Expected Vulnerability: {expected_vuln}
Crash Type: {verification.get('crash_type', 'unknown')}
Crash Address: {verification.get('crash_address', 'N/A')}
Reproducibility: {verification.get('reproducibility', 'N/A')}

ASAN Report:
{verification.get('asan_report', 'None')[:2000]}

Stack Trace:
{verification.get('stack_trace', 'None')[:2000]}

Questions:
1. Does this crash match the expected vulnerability type?
2. Is this a security-relevant crash?
3. What is the root cause of this crash?
4. Any suggestions for improving the PoC?

Provide your analysis:
<verification_result>SUCCESS/PARTIAL/FAILURE</verification_result>
<crash_analysis>Your analysis</crash_analysis>
<recommendations>Suggestions if any</recommendations>"""

        response = self._llm_chat(prompt, use_tools=False)

        # Parse response
        result = {}

        # Extract verification result
        result_match = re.search(r"<verification_result>(.*?)</verification_result>", response, re.DOTALL)
        if result_match:
            status = result_match.group(1).strip().upper()
            result["llm_verdict"] = status
            if status == "SUCCESS":
                result["vulnerability_confirmed"] = True
            elif status == "PARTIAL":
                result["vulnerability_confirmed"] = False
                result["notes"] = "Crash detected but may not match expected vulnerability"

        # Extract crash analysis
        analysis_match = re.search(r"<crash_analysis>(.*?)</crash_analysis>", response, re.DOTALL)
        if analysis_match:
            result["llm_crash_analysis"] = analysis_match.group(1).strip()

        # Extract recommendations
        rec_match = re.search(r"<recommendations>(.*?)</recommendations>", response, re.DOTALL)
        if rec_match:
            result["recommendations"] = rec_match.group(1).strip()

        return result

    def _llm_suggest_improvements(
        self,
        poc: PoCResult,
        analysis: Dict[str, Any],
        results: list[ExecutionResult],
    ) -> str:
        """Get LLM suggestions for improving non-crashing PoC."""
        logger.info("Getting LLM suggestions for PoC improvement")

        self._create_session()

        # Collect error output
        error_output = ""
        for r in results:
            if r.stderr:
                error_output += r.stderr[:500] + "\n"

        prompt = f"""The PoC did not trigger a crash. Help diagnose why.

Vulnerability Analysis:
- Type: {analysis.get('vulnerability_type', 'unknown')}
- Root Cause: {analysis.get('root_cause', 'unknown')}
- Trigger Approach: {analysis.get('trigger_approach', 'unknown')}

PoC Code:
```
{poc.code[:3000]}
```

Execution Output/Errors:
{error_output[:1000] if error_output else 'No errors, just no crash'}

Why might this PoC not be triggering the vulnerability?
What specific changes would you recommend?

Provide concise, actionable suggestions."""

        response = self._llm_chat(prompt, use_tools=False)
        return response

    def verify_with_plugin(
        self,
        poc: PoCResult,
        d8_path: str = None,
        chrome_path: str = None,
    ) -> Dict[str, Any]:
        """Verify using plugin system (fallback method)."""
        registry = get_registry()

        if poc.language == "javascript" and d8_path:
            plugin = registry.get_verifier("v8")
            if plugin:
                result = plugin.verify(poc=poc, d8_path=d8_path)
                return result.to_dict() if hasattr(result, 'to_dict') else result

        if chrome_path:
            plugin = registry.get_verifier("blink") or registry.get_verifier("chrome")
            if plugin:
                result = plugin.verify(poc=poc, chrome_path=chrome_path)
                return result.to_dict() if hasattr(result, 'to_dict') else result

        return {
            "success": False,
            "error_message": "No suitable verifier plugin found",
        }
