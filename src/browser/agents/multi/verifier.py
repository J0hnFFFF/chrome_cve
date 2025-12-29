"""
Verifier Agent

Verifies PoC by running in target environment.
Uses LLM for intelligent crash analysis and feedback.
"""

import re
import logging
from typing import Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseReproAgent, AgentMessage, AgentState
from ...plugins import get_registry, PoCResult, VerifyResult
from ...tools.execution import D8Executor, ChromeExecutor, ExecutionResult
from ...tools.debug import CrashAnalyzer
from ...tools.environment_manager import EnvironmentManager  # NEW

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
    - EnvironmentManager for auto-detection (NEW)
    """

    name = "verifier"
    system_prompt_file = "verifier_system.txt"

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        
        # NEW: Initialize EnvironmentManager
        self._env_manager = EnvironmentManager(config)
        
        # Try to get paths from config first
        self.chrome_path = config.get("chrome_path") if config else None
        self.d8_path = config.get("d8_path") if config else None
        
        # NEW: If not in config, try auto-detection
        if not self.chrome_path and not self.d8_path:
            logger.info("No binary paths in config, attempting auto-detection...")
            default_env = self._env_manager.get_default_env()
            
            if default_env.is_valid():
                self.d8_path = default_env.d8_path
                self.chrome_path = default_env.chrome_path
                logger.info(f"✓ Auto-detected: d8={self.d8_path}, chrome={self.chrome_path}")
            else:
                logger.warning("⚠️  No binaries found via auto-detection")
        
        self.timeout = config.get("timeout", 30) if config else 30
        self.num_runs = config.get("num_runs", 3) if config else 3
        self._crash_analyzer = CrashAnalyzer()

    def _register_handlers(self) -> None:
        """Register message handlers."""
        self._message_handlers = {
            "verify": self._handle_verify,
            "verify_batch": self._handle_verify_batch,
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

    def _handle_verify_batch(self, msg: AgentMessage) -> AgentMessage:
        """Handle verify_batch request."""
        candidates = msg.payload.get("candidates", [])
        d8_path = msg.payload.get("d8_path", self.d8_path)
        chrome_path = msg.payload.get("chrome_path", self.chrome_path)
        max_workers = msg.payload.get("max_workers", 3)
        timeout = msg.payload.get("timeout", self.timeout)

        try:
            results = self.verify_batch(
                candidates=candidates,
                d8_path=d8_path,
                chrome_path=chrome_path,
                max_workers=max_workers,
                timeout=timeout
            )

            return msg.create_response(
                sender=self.name,
                payload={"result": results},
                success=True,
            )
        except Exception as e:
            logger.exception(f"Batch verification failed: {e}")
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
    
    def verify_differential(
        self,
        poc: PoCResult,
        vulnerable_binary: str,
        fixed_binary: str,
        timeout: int = None
    ) -> Dict[str, Any]:
        """
        Perform differential verification on vulnerable and fixed binaries.
        
        This verifies that:
        1. PoC crashes on vulnerable version
        2. PoC does NOT crash on fixed version
        3. Confirms the patch actually fixed the vulnerability
        
        Args:
            poc: PoC to verify
            vulnerable_binary: Path to vulnerable binary (d8 or chrome)
            fixed_binary: Path to fixed binary
            timeout: Execution timeout (uses default if None)
            
        Returns:
            Differential verification result with comparison
        """
        import os
        from ...tools.execution import D8Executor, ChromeExecutor
        
        logger.info(f"[Verifier] Differential verification: vulnerable vs fixed")
        
        timeout = timeout or self.timeout
        
        # Determine executor type
        is_d8 = vulnerable_binary.endswith('d8.exe') or vulnerable_binary.endswith('d8')
        
        results = {
            "vulnerable": None,
            "fixed": None,
            "patch_effective": False,
            "confidence": 0.0,
            "analysis": ""
        }
        
        try:
            # Test on vulnerable version
            logger.info(f"  Testing on vulnerable binary: {os.path.basename(vulnerable_binary)}")
            if is_d8:
                executor_vuln = D8Executor(vulnerable_binary)
                vuln_result = executor_vuln.execute(poc.code, timeout=timeout)
            else:
                executor_vuln = ChromeExecutor(vulnerable_binary)
                vuln_result = executor_vuln.execute(poc.code, timeout=timeout)
            
            results["vulnerable"] = {
                "crashed": vuln_result.crashed,
                "exit_code": vuln_result.exit_code,
                "crash_type": vuln_result.crash_type,
                "crash_address": vuln_result.crash_address
            }
            
            # Test on fixed version
            logger.info(f"  Testing on fixed binary: {os.path.basename(fixed_binary)}")
            if is_d8:
                executor_fixed = D8Executor(fixed_binary)
                fixed_result = executor_fixed.execute(poc.code, timeout=timeout)
            else:
                executor_fixed = ChromeExecutor(fixed_binary)
                fixed_result = executor_fixed.execute(poc.code, timeout=timeout)
            
            results["fixed"] = {
                "crashed": fixed_result.crashed,
                "exit_code": fixed_result.exit_code,
                "crash_type": fixed_result.crash_type,
                "crash_address": fixed_result.crash_address
            }
            
            # Analyze results
            if vuln_result.crashed and not fixed_result.crashed:
                # Perfect case: crashes on vuln, not on fixed
                results["patch_effective"] = True
                results["confidence"] = 1.0
                results["analysis"] = "✅ Patch is effective: PoC crashes vulnerable version but not fixed version"
                logger.info("  ✅ Differential verification PASSED")
            
            elif vuln_result.crashed and fixed_result.crashed:
                # Both crash - patch may not be effective
                results["patch_effective"] = False
                results["confidence"] = 0.3
                results["analysis"] = "⚠️  Both versions crash - patch may not fix this vulnerability"
                logger.warning("  ⚠️  Both versions crashed")
            
            elif not vuln_result.crashed and not fixed_result.crashed:
                # Neither crash - PoC may be ineffective
                results["patch_effective"] = False
                results["confidence"] = 0.0
                results["analysis"] = "❌ Neither version crashes - PoC may be ineffective"
                logger.warning("  ❌ No crashes detected")
            
            else:
                # Fixed crashes but vuln doesn't - unexpected
                results["patch_effective"] = False
                results["confidence"] = 0.0
                results["analysis"] = "⚠️  Unexpected: fixed version crashes but vulnerable doesn't"
                logger.warning("  ⚠️  Unexpected result pattern")
            
            # Symbolize stack traces if available
            if vuln_result.crashed and vuln_result.stack_trace:
                crash_report = self._crash_analyzer.analyze(vuln_result.stderr)
                if crash_report.stack_trace:
                    symbolized = self._crash_analyzer.symbolize_stack_trace(
                        crash_report.stack_trace,
                        vulnerable_binary
                    )
                    results["vulnerable"]["symbolized_stack"] = [
                        str(frame) for frame in symbolized[:5]
                    ]
            
            return results
            
        except Exception as e:
            logger.error(f"Differential verification failed: {e}")
            return {
                "vulnerable": None,
                "fixed": None,
                "patch_effective": False,
                "confidence": 0.0,
                "analysis": f"Error during differential verification: {str(e)}"
            }

    def verify_batch(
        self,
        candidates: List[Dict[str, Any]],
        d8_path: str = None,
        chrome_path: str = None,
        max_workers: int = 3,
        timeout: int = None
    ) -> Dict[str, Any]:
        """
        Verify multiple candidate PoCs concurrently.
        
        Args:
            candidates: List of PoC dictionaries to verify
            d8_path: Path to d8 executable
            chrome_path: Path to Chrome executable
            max_workers: Maximum number of concurrent verifications
            timeout: Timeout per verification
            
        Returns:
            Dictionary with verification results
        """
        logger.info(f"[Verifier] Batch verification of {len(candidates)} candidates")
        
        d8_path = d8_path or self.d8_path
        chrome_path = chrome_path or self.chrome_path
        timeout = timeout or self.timeout
        
        results = {
            "total": len(candidates),
            "verified": 0,
            "crashed": 0,
            "candidates": [],
            "first_success": None,
            "all_failed": True
        }
        
        def verify_single(index: int, poc: Dict[str, Any]) -> Dict[str, Any]:
            """Verify a single PoC."""
            try:
                logger.info(f"  [Verifier] Verifying candidate #{index + 1}: {poc.get('strategy', 'Unknown')}")
                
                # Create PoCResult
                poc_result = PoCResult(
                    code=poc.get("code", ""),
                    language=poc.get("language", "javascript"),
                    expected_behavior=poc.get("expected_behavior", ""),
                    success=False
                )
                
                # Determine executor
                if poc_result.language == "javascript" and d8_path:
                    executor = D8Executor(d8_path)
                    exec_result = executor.execute(poc_result.code, timeout=timeout)
                elif chrome_path:
                    executor = ChromeExecutor(chrome_path)
                    exec_result = executor.execute(poc_result.code, timeout=timeout)
                else:
                    return {
                        "index": index,
                        "strategy": poc.get("strategy", "Unknown"),
                        "success": False,
                        "crashed": False,
                        "error": "No suitable executor found"
                    }
                
                # Analyze result
                crashed = exec_result.crashed
                
                return {
                    "index": index,
                    "strategy": poc.get("strategy", "Unknown"),
                    "success": True,
                    "crashed": crashed,
                    "exit_code": exec_result.exit_code,
                    "crash_type": exec_result.crash_type if crashed else None,
                    "execution_time": exec_result.execution_time,
                    "poc_code": poc.get("code", "")[:200] + "..." if len(poc.get("code", "")) > 200 else poc.get("code", "")
                }
                
            except Exception as e:
                logger.error(f"  [Verifier] Failed to verify candidate #{index + 1}: {e}")
                return {
                    "index": index,
                    "strategy": poc.get("strategy", "Unknown"),
                    "success": False,
                    "crashed": False,
                    "error": str(e)
                }
        
        # Execute verifications concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_index = {
                executor.submit(verify_single, i, candidate): i
                for i, candidate in enumerate(candidates)
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_index):
                result = future.result()
                results["candidates"].append(result)
                
                if result["success"]:
                    results["verified"] += 1
                    
                if result.get("crashed", False):
                    results["crashed"] += 1
                    results["all_failed"] = False
                    
                    # Mark first successful crash
                    if not results["first_success"]:
                        results["first_success"] = result
                        logger.info(f"  [Verifier] ✓ First crash found: Candidate #{result['index'] + 1} ({result['strategy']})")
        
        # Sort results by index
        results["candidates"].sort(key=lambda x: x["index"])
        
        # Summary
        logger.info(f"[Verifier] Batch verification complete:")
        logger.info(f"  Total: {results['total']}")
        logger.info(f"  Verified: {results['verified']}")
        logger.info(f"  Crashed: {results['crashed']}")
        
        if results["first_success"]:
            logger.info(f"  Best candidate: #{results['first_success']['index'] + 1} ({results['first_success']['strategy']})")
        
        return results

