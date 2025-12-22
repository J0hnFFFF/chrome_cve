"""
Chrome execution and crash detection tools.

Tools for downloading Chrome versions, running PoCs, and analyzing crashes.
"""

import os
import subprocess
import tempfile
import json
import re
from typing import Optional, Dict, Any
from agentlib.lib import tools


# Chrome version info API
CHROME_VERSIONS_API = "https://chromiumdash.appspot.com/fetch_releases"
CHROME_SNAPSHOTS = "https://commondatastorage.googleapis.com/chromium-browser-snapshots"


@tools.tool
def list_chrome_versions(channel: str = "Stable", platform: str = "Linux", limit: int = 10) -> str:
    """
    List available Chrome versions for a platform.

    :param channel: Release channel (Stable, Beta, Dev, Canary)
    :param platform: Platform (Linux, Windows, Mac)
    :param limit: Maximum versions to return
    :return: List of versions with details
    """
    import requests

    try:
        # Map platform names
        platform_map = {
            "Linux": "linux",
            "Windows": "win64",
            "Mac": "mac",
        }
        plat = platform_map.get(platform, "linux")

        response = requests.get(
            f"{CHROME_VERSIONS_API}?channel={channel}&platform={plat}&num={limit}",
            timeout=30
        )

        if response.status_code == 200:
            versions = response.json()
            result = f"Chrome {channel} versions for {platform}:\n\n"
            for v in versions[:limit]:
                result += f"  Version: {v.get('version', 'N/A')}\n"
                result += f"  Chromium: {v.get('chromium_main_branch_position', 'N/A')}\n"
                result += f"  Date: {v.get('time', 'N/A')[:10]}\n\n"
            return result
        else:
            return f"Error: Failed to fetch versions, status={response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"


@tools.tool
def download_chrome_version(version: str, platform: str = "linux64", output_dir: str = "/tmp/chrome") -> str:
    """
    Download a specific Chrome/Chromium version.

    :param version: Chrome version number or Chromium position number
    :param platform: Platform (linux64, win64, mac)
    :param output_dir: Directory to save the download
    :return: Path to the downloaded Chrome executable
    """
    os.makedirs(output_dir, exist_ok=True)

    # Try using puppeteer's browser download tool (most reliable)
    try:
        result = subprocess.run(
            ["npx", "@puppeteer/browsers", "install", f"chrome@{version}", f"--path={output_dir}"],
            capture_output=True,
            text=True,
            timeout=600  # 10 min timeout for download
        )

        if result.returncode == 0:
            # Find the chrome executable
            for root, dirs, files in os.walk(output_dir):
                for f in files:
                    if f in ["chrome", "chrome.exe", "Google Chrome"]:
                        chrome_path = os.path.join(root, f)
                        return f"Chrome downloaded successfully: {chrome_path}"

            return f"Download completed but chrome executable not found in {output_dir}"
        else:
            return f"Error downloading Chrome: {result.stderr}"

    except FileNotFoundError:
        return "Error: npx not found. Install Node.js and run: npm install -g @anthropic-ai/puppeteer"
    except subprocess.TimeoutExpired:
        return "Error: Download timed out"
    except Exception as e:
        return f"Error: {str(e)}"


@tools.tool
def find_chrome_executable(search_dir: str = "/tmp/chrome") -> str:
    """
    Find Chrome executable in a directory.

    :param search_dir: Directory to search
    :return: Path to Chrome executable or error
    """
    chrome_names = ["chrome", "chrome.exe", "Google Chrome", "chromium", "chromium-browser"]

    for root, dirs, files in os.walk(search_dir):
        for name in chrome_names:
            if name in files:
                path = os.path.join(root, name)
                if os.access(path, os.X_OK):
                    return f"Found Chrome: {path}"

    return f"Chrome executable not found in {search_dir}"


@tools.tool
def run_chrome_with_poc(
    chrome_path: str,
    poc_path: str,
    timeout: int = 30,
    extra_args: str = ""
) -> str:
    """
    Run Chrome with a PoC file and detect crashes.

    :param chrome_path: Path to Chrome executable
    :param poc_path: Path to PoC HTML file
    :param timeout: Timeout in seconds
    :param extra_args: Additional Chrome command line arguments
    :return: Execution result with crash information
    """
    # Convert to absolute path for file:// URL
    poc_abs_path = os.path.abspath(poc_path)
    poc_url = f"file://{poc_abs_path}"

    # Chrome flags for testing
    chrome_flags = [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-gpu",
        "--disable-software-rasterizer",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-translate",
        "--disable-extensions",
        "--enable-logging=stderr",
        "--v=1",
    ]

    if extra_args:
        chrome_flags.extend(extra_args.split())

    cmd = [chrome_path] + chrome_flags + [poc_url]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "DISPLAY": os.environ.get("DISPLAY", ":0")}
        )

        crashed = result.returncode != 0

        # Check for crash indicators in stderr
        crash_indicators = [
            "SIGSEGV", "SIGABRT", "SIGILL", "SIGFPE", "SIGBUS",
            "CHECK failed", "FATAL", "DCHECK failed",
            "Renderer crash", "GPU process crash",
            "AddressSanitizer", "MemorySanitizer", "UndefinedBehaviorSanitizer"
        ]

        crash_signals = []
        for indicator in crash_indicators:
            if indicator in result.stderr:
                crash_signals.append(indicator)

        # Analyze crash type
        crash_type = "none"
        if crashed or crash_signals:
            if "SIGSEGV" in result.stderr:
                crash_type = "segmentation_fault"
            elif "SIGABRT" in result.stderr:
                crash_type = "abort"
            elif "CHECK failed" in result.stderr or "DCHECK failed" in result.stderr:
                crash_type = "assertion_failure"
            elif "AddressSanitizer" in result.stderr:
                crash_type = "asan_error"
            elif crash_signals:
                crash_type = "crash_detected"
            else:
                crash_type = "abnormal_exit"

        return f"""
=== Chrome Execution Result ===

Return Code: {result.returncode}
Crashed: {crashed or bool(crash_signals)}
Crash Type: {crash_type}
Crash Signals: {crash_signals if crash_signals else "None"}

=== STDERR (last 2000 chars) ===
{result.stderr[-2000:] if result.stderr else "(empty)"}

=== STDOUT (last 500 chars) ===
{result.stdout[-500:] if result.stdout else "(empty)"}
"""

    except subprocess.TimeoutExpired:
        return f"""
=== Chrome Execution Result ===

Timeout: Process did not finish within {timeout} seconds
Crashed: Unknown (timeout)

Note: Timeout may indicate hang, infinite loop, or slow execution.
"""
    except Exception as e:
        return f"Error running Chrome: {str(e)}"


@tools.tool
def create_poc_file(content: str, filename: str = "poc.html", output_dir: str = "/tmp/poc") -> str:
    """
    Create a PoC file (HTML/JS).

    :param content: PoC content (HTML/JS code)
    :param filename: Output filename
    :param output_dir: Output directory
    :return: Path to created file
    """
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return f"PoC file created: {filepath}"
    except Exception as e:
        return f"Error creating PoC file: {str(e)}"


@tools.tool
def test_poc_reproducibility(
    chrome_path: str,
    poc_path: str,
    runs: int = 5,
    timeout: int = 30
) -> str:
    """
    Test if a PoC crash is reproducible by running multiple times.

    :param chrome_path: Path to Chrome executable
    :param poc_path: Path to PoC file
    :param runs: Number of test runs
    :param timeout: Timeout per run
    :return: Reproducibility analysis
    """
    results = []

    for i in range(runs):
        result = run_chrome_with_poc.func(chrome_path, poc_path, timeout)
        crashed = "Crashed: True" in result
        results.append(crashed)

    crash_count = sum(results)
    reproducibility = crash_count / runs * 100

    return f"""
=== Reproducibility Test ===

Total Runs: {runs}
Crashes: {crash_count}
Reproducibility: {reproducibility:.1f}%

Results: {['CRASH' if r else 'OK' for r in results]}

Assessment: {"Reliably reproducible" if reproducibility >= 80 else "Partially reproducible" if reproducibility >= 40 else "Not reliably reproducible"}
"""


@tools.tool
def analyze_crash_log(log_content: str) -> str:
    """
    Analyze Chrome crash log to extract useful information.

    :param log_content: Crash log content
    :return: Analyzed crash information
    """
    analysis = {
        "crash_type": "unknown",
        "crash_address": None,
        "faulting_function": None,
        "backtrace": [],
        "registers": {},
    }

    # Detect crash type
    if "SIGSEGV" in log_content:
        analysis["crash_type"] = "SIGSEGV (Segmentation Fault)"
    elif "SIGABRT" in log_content:
        analysis["crash_type"] = "SIGABRT (Abort)"
    elif "CHECK failed" in log_content:
        analysis["crash_type"] = "Assertion Failure"
    elif "AddressSanitizer" in log_content:
        # Parse ASAN error type
        asan_match = re.search(r'AddressSanitizer: (\w+)', log_content)
        if asan_match:
            analysis["crash_type"] = f"ASAN: {asan_match.group(1)}"

    # Extract crash address
    addr_match = re.search(r'(?:pc|ip|address)[:\s]+(0x[0-9a-fA-F]+)', log_content, re.I)
    if addr_match:
        analysis["crash_address"] = addr_match.group(1)

    # Extract faulting function (from stack trace)
    func_patterns = [
        r'#0\s+.*?\s+in\s+(\S+)',  # ASAN format
        r'\[0\]\s+(\S+)',  # Chrome format
        r'(?:at|in)\s+(\w+::\w+)',  # Common C++ format
    ]
    for pattern in func_patterns:
        match = re.search(pattern, log_content)
        if match:
            analysis["faulting_function"] = match.group(1)
            break

    return f"""
=== Crash Analysis ===

Crash Type: {analysis['crash_type']}
Crash Address: {analysis['crash_address'] or 'Unknown'}
Faulting Function: {analysis['faulting_function'] or 'Unknown'}

Raw indicators found:
- SIGSEGV: {"Yes" if "SIGSEGV" in log_content else "No"}
- SIGABRT: {"Yes" if "SIGABRT" in log_content else "No"}
- ASAN Error: {"Yes" if "AddressSanitizer" in log_content else "No"}
- CHECK/DCHECK: {"Yes" if "CHECK failed" in log_content or "DCHECK failed" in log_content else "No"}
"""
