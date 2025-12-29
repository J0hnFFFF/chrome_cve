"""
Execution Tools

Tools for running PoC in Chrome and d8.
Uses CrashAnalyzer from debug.py for unified crash analysis.
"""

import os
import re
import subprocess
import tempfile
import time
import platform
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

from .debug import CrashAnalyzer, ASANParser


@dataclass
class ExecutionResult:
    """Result of PoC execution."""
    success: bool
    crashed: bool = False
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    execution_time: float = 0.0
    crash_type: str = ""
    crash_address: str = ""
    asan_report: str = ""
    stack_trace: str = ""


class D8Executor:
    """
    Executor for V8's d8 shell.

    Used for testing JavaScript-based PoC.
    """

    DEFAULT_FLAGS = [
        "--allow-natives-syntax",  # Enable %OptimizeFunctionOnNextCall etc
        "--expose-gc",  # Enable gc() function
        "--fuzzing",  # Disable some checks
        "--no-hard-abort",  # Don't abort on failures
    ]

    ASAN_FLAGS = [
        "--no-turbo-escape",  # More predictable for debugging
    ]

    def __init__(self, d8_path: str, flags: List[str] = None):
        self.d8_path = d8_path
        self.flags = flags or self.DEFAULT_FLAGS.copy()
        self._crash_analyzer = CrashAnalyzer()
        self._validate_path()

    def _validate_path(self) -> None:
        """Validate d8 path exists."""
        if not os.path.exists(self.d8_path):
            raise FileNotFoundError(f"d8 not found at: {self.d8_path}")

    def execute(
        self,
        code: str,
        timeout: int = 30,
        env: Dict[str, str] = None,
    ) -> ExecutionResult:
        """
        Execute JavaScript code in d8.

        Args:
            code: JavaScript code to execute
            timeout: Execution timeout in seconds
            env: Additional environment variables

        Returns:
            ExecutionResult with execution details
        """
        # Save code to temp file
        fd, js_path = tempfile.mkstemp(suffix=".js", prefix="poc_")
        os.close(fd)

        try:
            with open(js_path, 'w', encoding='utf-8') as f:
                f.write(code)

            return self.execute_file(js_path, timeout, env)
        finally:
            if os.path.exists(js_path):
                os.remove(js_path)

    def execute_file(
        self,
        file_path: str,
        timeout: int = 30,
        env: Dict[str, str] = None,
    ) -> ExecutionResult:
        """
        Execute a JavaScript file in d8.

        Args:
            file_path: Path to JavaScript file
            timeout: Execution timeout in seconds
            env: Additional environment variables

        Returns:
            ExecutionResult with execution details
        """
        cmd = [self.d8_path] + self.flags + [file_path]

        # Set up environment
        exec_env = os.environ.copy()
        exec_env["ASAN_OPTIONS"] = "detect_leaks=0:symbolize=1:abort_on_error=1"
        if env:
            exec_env.update(env)

        start_time = time.time()

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=exec_env,
                encoding='utf-8',
                errors='ignore',
            )

            stdout, stderr = proc.communicate(timeout=timeout)
            execution_time = time.time() - start_time

            # stdout and stderr are already strings due to encoding parameter
            stdout_str = stdout
            stderr_str = stderr

            # Analyze result
            crashed = self._detect_crash(proc.returncode, stdout_str, stderr_str)

            result = ExecutionResult(
                success=True,
                crashed=crashed,
                exit_code=proc.returncode,
                stdout=stdout_str,
                stderr=stderr_str,
                execution_time=execution_time,
            )

            if crashed:
                # Use unified CrashAnalyzer for detailed analysis
                crash_report = self._crash_analyzer.analyze(stderr_str)
                result.crash_type = crash_report.crash_type or "unknown"
                result.crash_address = crash_report.fault_address
                if crash_report.asan_error:
                    result.asan_report = crash_report.asan_error.summary
                if crash_report.stack_trace:
                    result.stack_trace = "\n".join(str(f) for f in crash_report.stack_trace[:10])

            return result

        except subprocess.TimeoutExpired:
            proc.kill()
            return ExecutionResult(
                success=False,
                crashed=False,
                exit_code=-1,
                stderr="Execution timed out",
                execution_time=timeout,
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                crashed=False,
                exit_code=-1,
                stderr=str(e),
            )

    def _detect_crash(self, returncode: int, stdout: str, stderr: str) -> bool:
        """Detect if d8 crashed."""
        if returncode != 0 and returncode not in [-9, 137]:  # Killed
            return True

        crash_patterns = [
            r"AddressSanitizer",
            r"SIGSEGV",
            r"SIGABRT",
            r"SIGBUS",
            r"Fatal error",
            r"Check failed",
            r"DCHECK",
            r"Segmentation fault",
        ]

        combined = stdout + stderr
        return any(re.search(p, combined, re.I) for p in crash_patterns)

    def get_version(self) -> str:
        """Get d8 version."""
        try:
            result = subprocess.run(
                [self.d8_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip()
        except:
            return "unknown"


class ChromeExecutor:
    """
    Executor for Chrome browser.

    Used for testing HTML/renderer-based PoC.
    """

    DEFAULT_FLAGS = [
        "--no-sandbox",
        "--disable-gpu",
        "--disable-software-rasterizer",
        "--disable-dev-shm-usage",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-translate",
        "--disable-default-apps",
        "--no-first-run",
        "--no-default-browser-check",
    ]

    HEADLESS_FLAGS = [
        "--headless=new",
    ]

    def __init__(
        self,
        chrome_path: str,
        headless: bool = True,
        flags: List[str] = None,
    ):
        self.chrome_path = chrome_path
        self.headless = headless
        self.flags = flags or self.DEFAULT_FLAGS.copy()
        if headless:
            self.flags.extend(self.HEADLESS_FLAGS)
        self._crash_analyzer = CrashAnalyzer()
        self._validate_path()

    def _validate_path(self) -> None:
        """Validate Chrome path exists."""
        if not os.path.exists(self.chrome_path):
            raise FileNotFoundError(f"Chrome not found at: {self.chrome_path}")

    def execute(
        self,
        html_content: str,
        timeout: int = 30,
        env: Dict[str, str] = None,
    ) -> ExecutionResult:
        """
        Execute HTML content in Chrome.

        Args:
            html_content: HTML content to load
            timeout: Execution timeout in seconds
            env: Additional environment variables

        Returns:
            ExecutionResult with execution details
        """
        # Save HTML to temp file
        fd, html_path = tempfile.mkstemp(suffix=".html", prefix="poc_")
        os.close(fd)

        try:
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            return self.execute_file(html_path, timeout, env)
        finally:
            if os.path.exists(html_path):
                os.remove(html_path)

    def execute_file(
        self,
        file_path: str,
        timeout: int = 30,
        env: Dict[str, str] = None,
    ) -> ExecutionResult:
        """
        Execute an HTML file in Chrome.

        Args:
            file_path: Path to HTML file
            timeout: Execution timeout in seconds
            env: Additional environment variables

        Returns:
            ExecutionResult with execution details
        """
        url = f"file://{os.path.abspath(file_path)}"
        cmd = [self.chrome_path] + self.flags + [url]

        # Set up environment
        exec_env = os.environ.copy()
        exec_env["ASAN_OPTIONS"] = "detect_leaks=0:symbolize=1:abort_on_error=1"
        if env:
            exec_env.update(env)

        start_time = time.time()

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=exec_env,
                encoding='utf-8',
                errors='ignore',
            )

            stdout, stderr = proc.communicate(timeout=timeout)
            execution_time = time.time() - start_time

            # stdout and stderr are already strings due to encoding parameter
            stdout_str = stdout
            stderr_str = stderr

            crashed = self._detect_crash(proc.returncode, stdout_str, stderr_str)

            result = ExecutionResult(
                success=True,
                crashed=crashed,
                exit_code=proc.returncode,
                stdout=stdout_str,
                stderr=stderr_str,
                execution_time=execution_time,
            )

            if crashed:
                # Use unified CrashAnalyzer for detailed analysis
                crash_report = self._crash_analyzer.analyze(stderr_str)
                result.crash_type = crash_report.crash_type or "unknown"
                result.crash_address = crash_report.fault_address
                if crash_report.asan_error:
                    result.asan_report = crash_report.asan_error.summary
                if crash_report.stack_trace:
                    result.stack_trace = "\n".join(str(f) for f in crash_report.stack_trace[:10])

            return result

        except subprocess.TimeoutExpired:
            proc.kill()
            return ExecutionResult(
                success=False,
                crashed=False,
                exit_code=-1,
                stderr="Execution timed out",
                execution_time=timeout,
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                crashed=False,
                exit_code=-1,
                stderr=str(e),
            )

    def _detect_crash(self, returncode: int, stdout: str, stderr: str) -> bool:
        """Detect if Chrome crashed."""
        if returncode != 0 and returncode not in [-9, 137, 0]:
            return True

        crash_patterns = [
            r"AddressSanitizer",
            r"SIGSEGV",
            r"SIGABRT",
            r"Renderer crash",
            r"Aw, Snap!",
        ]

        combined = stdout + stderr
        return any(re.search(p, combined, re.I) for p in crash_patterns)

    def get_version(self) -> str:
        """Get Chrome version."""
        try:
            result = subprocess.run(
                [self.chrome_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip()
        except:
            return "unknown"


class MultiVersionTester:
    """
    Tests PoC across multiple Chrome/d8 versions.

    Useful for:
    - Confirming vulnerability exists in claimed versions
    - Verifying fix in patched versions
    - Finding exact version boundaries
    """

    def __init__(self, versions_dir: str = "./volumes/chrome"):
        self.versions_dir = versions_dir

    def test_poc_versions(
        self,
        poc_code: str,
        versions: List[str],
        poc_type: str = "js",
        timeout: int = 30,
    ) -> Dict[str, ExecutionResult]:
        """
        Test PoC across multiple versions.

        Args:
            poc_code: PoC code to test
            versions: List of version strings
            poc_type: Type of PoC ("js" or "html")
            timeout: Execution timeout per version

        Returns:
            Dict mapping version to ExecutionResult
        """
        results = {}

        for version in versions:
            print(f"  Testing version {version}...")

            if poc_type == "js":
                result = self._test_d8(poc_code, version, timeout)
            else:
                result = self._test_chrome(poc_code, version, timeout)

            results[version] = result

            status = "CRASH" if result.crashed else "OK"
            print(f"    {status} (exit: {result.exit_code})")

        return results

    def _test_d8(
        self,
        code: str,
        version: str,
        timeout: int,
    ) -> ExecutionResult:
        """Test in d8 for a specific version."""
        d8_path = self._find_d8(version)
        if not d8_path:
            return ExecutionResult(
                success=False,
                stderr=f"d8 not found for version {version}",
            )

        try:
            executor = D8Executor(d8_path)
            return executor.execute(code, timeout)
        except Exception as e:
            return ExecutionResult(success=False, stderr=str(e))

    def _test_chrome(
        self,
        code: str,
        version: str,
        timeout: int,
    ) -> ExecutionResult:
        """Test in Chrome for a specific version."""
        chrome_path = self._find_chrome(version)
        if not chrome_path:
            return ExecutionResult(
                success=False,
                stderr=f"Chrome not found for version {version}",
            )

        try:
            executor = ChromeExecutor(chrome_path)
            return executor.execute(code, timeout)
        except Exception as e:
            return ExecutionResult(success=False, stderr=str(e))

    def _find_d8(self, version: str) -> Optional[str]:
        """Find d8 executable for version."""
        from pathlib import Path

        version_dir = Path(self.versions_dir) / f"chrome-{version}"
        if not version_dir.exists():
            return None

        # Look for d8
        for d8 in version_dir.rglob("d8*"):
            if d8.is_file():
                return str(d8)

        return None

    def _find_chrome(self, version: str) -> Optional[str]:
        """Find Chrome executable for version."""
        from pathlib import Path

        version_dir = Path(self.versions_dir) / f"chrome-{version}"
        if not version_dir.exists():
            return None

        # Look for Chrome
        if platform.system() == "Windows":
            for chrome in version_dir.rglob("chrome.exe"):
                return str(chrome)
        else:
            for chrome in version_dir.rglob("chrome"):
                if chrome.is_file():
                    return str(chrome)

        return None

    def find_boundary_version(
        self,
        poc_code: str,
        vulnerable_version: str,
        fixed_version: str,
        poc_type: str = "js",
    ) -> Optional[str]:
        """
        Find the exact version where vulnerability was fixed.

        Uses binary search between vulnerable and fixed versions.
        """
        # This would require a list of all versions between the two
        # For now, return None as placeholder
        return None
