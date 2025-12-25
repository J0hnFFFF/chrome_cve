"""
Chrome Verifier Plugin

Verifies PoC by running in Chrome browser.
"""

import os
import re
import subprocess
import tempfile
import time
from typing import Optional
from ..base import VerifierPlugin, PoCResult, VerifyResult


class ChromeVerifierPlugin(VerifierPlugin):
    """
    Verifier plugin that runs PoC in Chrome.

    Used for:
    - Blink/renderer vulnerabilities
    - Full browser vulnerabilities
    - HTML-based PoC
    """

    name = "chrome_verifier"
    version = "1.0.0"
    description = "Verifier using Chrome browser"
    supported_components = ["blink", "dom", "layout", "renderer", "chrome"]

    CHROME_FLAGS = [
        "--no-sandbox",
        "--disable-gpu",
        "--disable-software-rasterizer",
        "--disable-dev-shm-usage",
        "--headless",
        "--disable-extensions",
        "--disable-background-networking",
    ]

    ASAN_FLAGS = [
        "ASAN_OPTIONS=detect_leaks=0:symbolize=1:abort_on_error=1",
    ]

    def verify(
        self,
        poc: PoCResult,
        chrome_path: str = None,
        d8_path: str = None,
    ) -> VerifyResult:
        """Verify PoC by running in Chrome."""

        if not chrome_path:
            return VerifyResult(
                success=False,
                error_message="Chrome path not provided",
            )

        if not os.path.exists(chrome_path):
            return VerifyResult(
                success=False,
                error_message=f"Chrome not found at {chrome_path}",
            )

        # Save PoC to temp file
        poc_file = self._save_poc_to_file(poc)
        if not poc_file:
            return VerifyResult(
                success=False,
                error_message="Failed to save PoC to file",
            )

        try:
            # Run Chrome with PoC
            result = self._run_chrome(chrome_path, poc_file)
            return result
        finally:
            # Cleanup
            if os.path.exists(poc_file):
                os.remove(poc_file)

    def _save_poc_to_file(self, poc: PoCResult) -> Optional[str]:
        """Save PoC to temporary file."""
        try:
            suffix = ".html" if poc.language == "html" else ".js"
            fd, path = tempfile.mkstemp(suffix=suffix, prefix="poc_")
            os.close(fd)

            with open(path, 'w', encoding='utf-8') as f:
                if poc.language == "javascript":
                    # Wrap JS in HTML
                    f.write(f'''<!DOCTYPE html>
<html>
<head><title>PoC</title></head>
<body>
<script>
{poc.code}
</script>
</body>
</html>''')
                else:
                    f.write(poc.code)

            return path
        except Exception as e:
            print(f"Error saving PoC: {e}")
            return None

    def _run_chrome(self, chrome_path: str, poc_file: str) -> VerifyResult:
        """Run Chrome with the PoC file."""
        cmd = [chrome_path] + self.CHROME_FLAGS + [f"file://{poc_file}"]

        env = os.environ.copy()
        for flag in self.ASAN_FLAGS:
            key, value = flag.split("=", 1)
            env[key] = value

        try:
            start_time = time.time()
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )

            # Wait for Chrome with timeout
            stdout, stderr = proc.communicate(timeout=30)
            execution_time = time.time() - start_time

            output = stdout.decode('utf-8', errors='ignore')
            error = stderr.decode('utf-8', errors='ignore')

            # Check for crash
            crashed = self._detect_crash(proc.returncode, output, error)

            if crashed:
                crash_info = self._parse_crash_info(error)
                return VerifyResult(
                    success=True,
                    crash_info=crash_info,
                    stack_trace=self._extract_stack_trace(error),
                    asan_report=self._extract_asan_report(error),
                    reproducibility="once",  # Need multiple runs to confirm
                    execution_time=execution_time,
                    runs_attempted=1,
                    runs_crashed=1,
                    chrome_version=self._get_chrome_version(chrome_path),
                )
            else:
                return VerifyResult(
                    success=False,
                    execution_time=execution_time,
                    runs_attempted=1,
                    runs_crashed=0,
                    chrome_version=self._get_chrome_version(chrome_path),
                    error_message="No crash detected",
                )

        except subprocess.TimeoutExpired:
            proc.kill()
            return VerifyResult(
                success=False,
                error_message="Execution timed out",
                runs_attempted=1,
            )
        except Exception as e:
            return VerifyResult(
                success=False,
                error_message=str(e),
            )

    def _detect_crash(self, returncode: int, stdout: str, stderr: str) -> bool:
        """Detect if Chrome crashed."""
        # Non-zero exit code usually indicates crash
        if returncode != 0 and returncode != -9:  # -9 is our kill
            return True

        # Check for ASAN messages
        asan_patterns = [
            r"AddressSanitizer",
            r"ERROR:.*ASAN",
            r"SUMMARY:.*Sanitizer",
        ]
        for pattern in asan_patterns:
            if re.search(pattern, stderr, re.IGNORECASE):
                return True

        # Check for crash indicators
        crash_patterns = [
            r"SIGSEGV",
            r"SIGABRT",
            r"SIGBUS",
            r"Segmentation fault",
            r"Aborted",
        ]
        for pattern in crash_patterns:
            if re.search(pattern, stderr, re.IGNORECASE):
                return True

        return False

    def _parse_crash_info(self, stderr: str):
        """Parse crash information from stderr."""
        from ..base import VerifyResult
        from ...models.verify import CrashInfo

        crash_type = ""
        crash_address = ""

        # Look for signal type
        sig_match = re.search(r"(SIGSEGV|SIGABRT|SIGBUS)", stderr)
        if sig_match:
            crash_type = sig_match.group(1)

        # Look for address
        addr_match = re.search(r"address\s+(0x[0-9a-f]+)", stderr, re.I)
        if addr_match:
            crash_address = addr_match.group(1)

        return CrashInfo(
            crash_type=crash_type,
            crash_address=crash_address,
        )

    def _extract_stack_trace(self, stderr: str) -> str:
        """Extract stack trace from stderr."""
        lines = stderr.split('\n')
        stack_lines = []
        in_stack = False

        for line in lines:
            if re.match(r'\s*#\d+', line) or 'at 0x' in line:
                in_stack = True
                stack_lines.append(line)
            elif in_stack and line.strip() == "":
                break

        return '\n'.join(stack_lines)

    def _extract_asan_report(self, stderr: str) -> str:
        """Extract ASAN report from stderr."""
        if "AddressSanitizer" not in stderr:
            return ""

        lines = stderr.split('\n')
        asan_lines = []
        in_asan = False

        for line in lines:
            if "AddressSanitizer" in line or "ASAN" in line:
                in_asan = True
            if in_asan:
                asan_lines.append(line)
            if in_asan and "SUMMARY" in line:
                asan_lines.append(line)
                break

        return '\n'.join(asan_lines)

    def _get_chrome_version(self, chrome_path: str) -> str:
        """Get Chrome version."""
        try:
            result = subprocess.run(
                [chrome_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip()
        except:
            return "unknown"
