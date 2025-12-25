"""
D8 Verifier Plugin

Verifies PoC by running in V8's d8 shell.
"""

import os
import re
import subprocess
import tempfile
import time
from typing import Optional
from ..base import VerifierPlugin, PoCResult, VerifyResult
from ...models.verify import CrashInfo


class D8VerifierPlugin(VerifierPlugin):
    """
    Verifier plugin that runs PoC in d8 shell.

    Used for:
    - V8 JavaScript vulnerabilities
    - JIT bugs
    - Pure JS-based PoC
    """

    name = "d8_verifier"
    version = "1.0.0"
    description = "Verifier using V8 d8 shell"
    supported_components = ["v8", "javascript", "jit"]

    D8_FLAGS = [
        "--allow-natives-syntax",  # Allow %OptimizeFunctionOnNextCall etc
        "--expose-gc",  # Allow gc() function
    ]

    def verify(
        self,
        poc: PoCResult,
        chrome_path: str = None,
        d8_path: str = None,
    ) -> VerifyResult:
        """Verify PoC by running in d8."""

        if not d8_path:
            return VerifyResult(
                success=False,
                error_message="d8 path not provided",
            )

        if not os.path.exists(d8_path):
            return VerifyResult(
                success=False,
                error_message=f"d8 not found at {d8_path}",
            )

        # Save PoC to temp file
        poc_file = self._save_poc_to_file(poc)
        if not poc_file:
            return VerifyResult(
                success=False,
                error_message="Failed to save PoC to file",
            )

        try:
            # Run multiple times to check reproducibility
            results = []
            for _ in range(3):
                result = self._run_d8(d8_path, poc_file)
                results.append(result)

            # Analyze results
            return self._aggregate_results(results, d8_path)
        finally:
            if os.path.exists(poc_file):
                os.remove(poc_file)

    def _save_poc_to_file(self, poc: PoCResult) -> Optional[str]:
        """Save PoC to temporary file."""
        try:
            fd, path = tempfile.mkstemp(suffix=".js", prefix="poc_")
            os.close(fd)

            with open(path, 'w', encoding='utf-8') as f:
                f.write(poc.code)

            return path
        except Exception as e:
            print(f"Error saving PoC: {e}")
            return None

    def _run_d8(self, d8_path: str, poc_file: str) -> dict:
        """Run d8 with the PoC file."""
        cmd = [d8_path] + self.D8_FLAGS + [poc_file]

        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "detect_leaks=0:symbolize=1:abort_on_error=1"

        try:
            start_time = time.time()
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )

            stdout, stderr = proc.communicate(timeout=30)
            execution_time = time.time() - start_time

            output = stdout.decode('utf-8', errors='ignore')
            error = stderr.decode('utf-8', errors='ignore')

            crashed = self._detect_crash(proc.returncode, output, error)

            return {
                "crashed": crashed,
                "returncode": proc.returncode,
                "stdout": output,
                "stderr": error,
                "execution_time": execution_time,
            }

        except subprocess.TimeoutExpired:
            proc.kill()
            return {
                "crashed": False,
                "timeout": True,
                "execution_time": 30,
            }
        except Exception as e:
            return {
                "crashed": False,
                "error": str(e),
                "execution_time": 0,
            }

    def _detect_crash(self, returncode: int, stdout: str, stderr: str) -> bool:
        """Detect if d8 crashed."""
        if returncode != 0 and returncode != -9:
            return True

        crash_patterns = [
            r"AddressSanitizer",
            r"SIGSEGV",
            r"SIGABRT",
            r"Fatal error",
            r"Check failed",
            r"DCHECK",
        ]

        combined = stdout + stderr
        for pattern in crash_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                return True

        return False

    def _aggregate_results(self, results: list, d8_path: str) -> VerifyResult:
        """Aggregate multiple run results."""
        total_runs = len(results)
        crashed_runs = sum(1 for r in results if r.get("crashed", False))

        # Determine reproducibility
        if crashed_runs == total_runs:
            reproducibility = "always"
        elif crashed_runs > 0:
            reproducibility = "sometimes"
        else:
            reproducibility = "never"

        # Find first crash for details
        crash_result = next((r for r in results if r.get("crashed")), None)

        if crash_result:
            stderr = crash_result.get("stderr", "")
            return VerifyResult(
                success=True,
                crash_info=self._parse_crash_info(stderr),
                stack_trace=self._extract_stack_trace(stderr),
                asan_report=self._extract_asan_report(stderr),
                reproducibility=reproducibility,
                execution_time=sum(r.get("execution_time", 0) for r in results),
                runs_attempted=total_runs,
                runs_crashed=crashed_runs,
                d8_version=self._get_d8_version(d8_path),
            )
        else:
            return VerifyResult(
                success=False,
                reproducibility=reproducibility,
                runs_attempted=total_runs,
                runs_crashed=crashed_runs,
                d8_version=self._get_d8_version(d8_path),
                error_message="No crash detected in any run",
            )

    def _parse_crash_info(self, stderr: str) -> CrashInfo:
        """Parse crash information."""
        crash_type = ""
        crash_address = ""

        sig_match = re.search(r"(SIGSEGV|SIGABRT|SIGBUS)", stderr)
        if sig_match:
            crash_type = sig_match.group(1)

        addr_match = re.search(r"address\s+(0x[0-9a-f]+)", stderr, re.I)
        if addr_match:
            crash_address = addr_match.group(1)

        return CrashInfo(
            crash_type=crash_type,
            crash_address=crash_address,
        )

    def _extract_stack_trace(self, stderr: str) -> str:
        """Extract stack trace."""
        lines = stderr.split('\n')
        stack_lines = []
        in_stack = False

        for line in lines:
            if re.match(r'\s*#\d+', line):
                in_stack = True
                stack_lines.append(line)
            elif in_stack and line.strip() == "":
                break

        return '\n'.join(stack_lines)

    def _extract_asan_report(self, stderr: str) -> str:
        """Extract ASAN report."""
        if "AddressSanitizer" not in stderr:
            return ""

        lines = stderr.split('\n')
        asan_lines = []
        in_asan = False

        for line in lines:
            if "AddressSanitizer" in line:
                in_asan = True
            if in_asan:
                asan_lines.append(line)
            if in_asan and "SUMMARY" in line:
                break

        return '\n'.join(asan_lines)

    def _get_d8_version(self, d8_path: str) -> str:
        """Get d8 version."""
        try:
            result = subprocess.run(
                [d8_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip()
        except:
            return "unknown"
