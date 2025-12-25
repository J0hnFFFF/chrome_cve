"""
Debug Tools

Tools for analyzing crashes, ASAN reports, and stack traces.
"""

import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class ASANError:
    """Parsed ASAN error information."""
    error_type: str = ""  # heap-buffer-overflow, use-after-free, etc.
    operation: str = ""  # READ, WRITE
    size: int = 0  # Access size
    address: str = ""  # Fault address
    thread: str = ""  # Thread info
    stack_trace: List[str] = field(default_factory=list)
    allocation_trace: List[str] = field(default_factory=list)
    deallocation_trace: List[str] = field(default_factory=list)
    summary: str = ""


@dataclass
class StackFrame:
    """Single stack frame."""
    index: int = 0
    address: str = ""
    function: str = ""
    file: str = ""
    line: int = 0
    module: str = ""

    def __str__(self) -> str:
        if self.file and self.line:
            return f"#{self.index} {self.function} at {self.file}:{self.line}"
        elif self.function:
            return f"#{self.index} {self.function}"
        else:
            return f"#{self.index} {self.address}"


@dataclass
class CrashReport:
    """Complete crash report."""
    crash_type: str = ""  # SIGSEGV, SIGABRT, etc.
    signal_code: str = ""
    fault_address: str = ""
    registers: Dict[str, str] = field(default_factory=dict)
    stack_trace: List[StackFrame] = field(default_factory=list)
    asan_error: Optional[ASANError] = None
    raw_output: str = ""


class ASANParser:
    """
    Parser for AddressSanitizer reports.

    Extracts structured information from ASAN output.
    """

    # ASAN error type patterns
    ERROR_PATTERNS = {
        "heap-buffer-overflow": r"heap-buffer-overflow",
        "heap-use-after-free": r"heap-use-after-free",
        "stack-buffer-overflow": r"stack-buffer-overflow",
        "stack-use-after-return": r"stack-use-after-return",
        "stack-use-after-scope": r"stack-use-after-scope",
        "use-after-poison": r"use-after-poison",
        "container-overflow": r"container-overflow",
        "global-buffer-overflow": r"global-buffer-overflow",
        "double-free": r"double-free",
        "alloc-dealloc-mismatch": r"alloc-dealloc-mismatch",
        "memcpy-param-overlap": r"memcpy-param-overlap",
        "new-delete-type-mismatch": r"new-delete-type-mismatch",
        "SEGV": r"SEGV on unknown address",
    }

    def parse(self, asan_output: str) -> Optional[ASANError]:
        """
        Parse ASAN output into structured ASANError.

        Args:
            asan_output: Raw ASAN output text

        Returns:
            ASANError with parsed information or None
        """
        if "AddressSanitizer" not in asan_output and "ASAN" not in asan_output:
            return None

        error = ASANError()

        # Detect error type
        for error_type, pattern in self.ERROR_PATTERNS.items():
            if re.search(pattern, asan_output, re.I):
                error.error_type = error_type
                break

        # Extract operation and size
        op_match = re.search(
            r"(READ|WRITE) of size (\d+)",
            asan_output
        )
        if op_match:
            error.operation = op_match.group(1)
            error.size = int(op_match.group(2))

        # Extract address
        addr_match = re.search(
            r"on (?:unknown )?address (0x[0-9a-f]+)",
            asan_output,
            re.I
        )
        if addr_match:
            error.address = addr_match.group(1)

        # Extract thread info
        thread_match = re.search(r"(thread T\d+)", asan_output)
        if thread_match:
            error.thread = thread_match.group(1)

        # Extract stack traces
        error.stack_trace = self._extract_stack_section(
            asan_output, "at pc", "previously allocated"
        )
        error.allocation_trace = self._extract_stack_section(
            asan_output, "previously allocated", "previously freed"
        )
        error.deallocation_trace = self._extract_stack_section(
            asan_output, "previously freed", "SUMMARY"
        )

        # Extract summary
        summary_match = re.search(
            r"SUMMARY: AddressSanitizer: ([^\n]+)",
            asan_output
        )
        if summary_match:
            error.summary = summary_match.group(1)

        return error

    def _extract_stack_section(
        self,
        text: str,
        start_marker: str,
        end_marker: str,
    ) -> List[str]:
        """Extract stack frames between markers."""
        frames = []

        # Find section
        start_idx = text.find(start_marker)
        end_idx = text.find(end_marker, start_idx + 1) if start_idx >= 0 else -1

        if start_idx < 0:
            return frames

        section = text[start_idx:end_idx] if end_idx > 0 else text[start_idx:]

        # Extract frame lines
        for match in re.finditer(r'#\d+\s+0x[0-9a-f]+\s+[^\n]+', section, re.I):
            frames.append(match.group(0))

        return frames

    def get_vulnerability_type(self, asan_error: ASANError) -> str:
        """
        Map ASAN error type to vulnerability classification.

        Returns common vulnerability type name.
        """
        mapping = {
            "heap-buffer-overflow": "out-of-bounds-write",
            "heap-use-after-free": "use-after-free",
            "stack-buffer-overflow": "stack-buffer-overflow",
            "use-after-poison": "use-after-free",
            "double-free": "double-free",
            "SEGV": "null-dereference",
        }

        return mapping.get(asan_error.error_type, asan_error.error_type)


class StackTraceParser:
    """
    Parser for stack traces from crashes.

    Handles various stack trace formats.
    """

    # Patterns for different stack trace formats
    PATTERNS = [
        # ASAN format: #0 0x55555... in function file:line
        r'#(\d+)\s+(0x[0-9a-f]+)\s+in\s+([^\s]+)\s+([^\s:]+):(\d+)',

        # GDB format: #0 function (args) at file:line
        r'#(\d+)\s+(?:0x[0-9a-f]+\s+in\s+)?([^\s(]+)\s*\([^)]*\)\s+at\s+([^:]+):(\d+)',

        # Simple format: #0 0x... function
        r'#(\d+)\s+(0x[0-9a-f]+)\s+([^\s]+)',

        # V8 format: at function (file:line)
        r'at\s+([^\s(]+)\s+\(([^:]+):(\d+)',
    ]

    def parse(self, stack_output: str) -> List[StackFrame]:
        """
        Parse stack trace output into StackFrame objects.

        Args:
            stack_output: Raw stack trace text

        Returns:
            List of StackFrame objects
        """
        frames = []
        lines = stack_output.split('\n')

        for line in lines:
            frame = self._parse_line(line)
            if frame:
                frames.append(frame)

        return frames

    def _parse_line(self, line: str) -> Optional[StackFrame]:
        """Parse a single stack trace line."""
        line = line.strip()
        if not line:
            return None

        # Try ASAN format
        match = re.match(
            r'#(\d+)\s+(0x[0-9a-f]+)\s+in\s+([^\s]+)\s+([^\s:]+):(\d+)',
            line
        )
        if match:
            return StackFrame(
                index=int(match.group(1)),
                address=match.group(2),
                function=match.group(3),
                file=match.group(4),
                line=int(match.group(5)),
            )

        # Try GDB format
        match = re.match(
            r'#(\d+)\s+(?:0x[0-9a-f]+\s+in\s+)?([^\s(]+)\s*\([^)]*\)\s+at\s+([^:]+):(\d+)',
            line
        )
        if match:
            return StackFrame(
                index=int(match.group(1)),
                function=match.group(2),
                file=match.group(3),
                line=int(match.group(4)),
            )

        # Try simple format
        match = re.match(r'#(\d+)\s+(0x[0-9a-f]+)\s+(.+)', line)
        if match:
            return StackFrame(
                index=int(match.group(1)),
                address=match.group(2),
                function=match.group(3).strip(),
            )

        return None

    def find_crash_location(self, frames: List[StackFrame]) -> Optional[StackFrame]:
        """Find the most relevant crash location frame."""
        for frame in frames:
            # Skip runtime/library functions
            skip_patterns = [
                r'^__asan_',
                r'^__sanitizer_',
                r'^malloc',
                r'^free',
                r'^operator new',
                r'^operator delete',
                r'^_start',
                r'^__libc_',
            ]

            if any(re.match(p, frame.function) for p in skip_patterns):
                continue

            return frame

        return frames[0] if frames else None


class CrashAnalyzer:
    """
    Comprehensive crash analyzer.

    Combines ASAN parsing, stack trace analysis, and crash classification.
    """

    def __init__(self):
        self.asan_parser = ASANParser()
        self.stack_parser = StackTraceParser()

    def analyze(self, crash_output: str) -> CrashReport:
        """
        Analyze crash output and produce structured report.

        Args:
            crash_output: Raw crash output (stderr)

        Returns:
            CrashReport with complete analysis
        """
        report = CrashReport(raw_output=crash_output)

        # Detect crash type from signals
        signal_match = re.search(r'(SIGSEGV|SIGABRT|SIGBUS|SIGFPE)', crash_output)
        if signal_match:
            report.crash_type = signal_match.group(1)

        # Extract fault address
        addr_match = re.search(
            r'(?:fault|at|address)\s+(0x[0-9a-f]+)',
            crash_output,
            re.I
        )
        if addr_match:
            report.fault_address = addr_match.group(1)

        # Parse ASAN if present
        report.asan_error = self.asan_parser.parse(crash_output)

        # Parse stack trace
        report.stack_trace = self.stack_parser.parse(crash_output)

        # Infer crash type from ASAN if not already set
        if not report.crash_type and report.asan_error:
            report.crash_type = report.asan_error.error_type

        return report

    def get_summary(self, report: CrashReport) -> str:
        """Generate human-readable summary of crash."""
        parts = []

        parts.append(f"Crash Type: {report.crash_type or 'Unknown'}")

        if report.fault_address:
            parts.append(f"Fault Address: {report.fault_address}")

        if report.asan_error:
            asan = report.asan_error
            if asan.operation and asan.size:
                parts.append(f"Operation: {asan.operation} of {asan.size} bytes")
            if asan.summary:
                parts.append(f"ASAN: {asan.summary}")

        if report.stack_trace:
            crash_frame = self.stack_parser.find_crash_location(report.stack_trace)
            if crash_frame:
                parts.append(f"Location: {crash_frame}")

        return "\n".join(parts)

    def is_exploitable(self, report: CrashReport) -> Dict[str, Any]:
        """
        Assess if crash is potentially exploitable.

        Returns assessment with reasoning.
        """
        assessment = {
            "exploitable": False,
            "confidence": "low",
            "reasons": [],
        }

        if report.asan_error:
            error_type = report.asan_error.error_type

            # Highly exploitable
            if error_type in ["heap-use-after-free", "heap-buffer-overflow"]:
                assessment["exploitable"] = True
                assessment["confidence"] = "high"
                assessment["reasons"].append(
                    f"{error_type} is typically exploitable for code execution"
                )

            # Potentially exploitable
            elif error_type in ["stack-buffer-overflow", "double-free"]:
                assessment["exploitable"] = True
                assessment["confidence"] = "medium"
                assessment["reasons"].append(
                    f"{error_type} may be exploitable depending on context"
                )

            # Write operation
            if report.asan_error.operation == "WRITE":
                assessment["exploitable"] = True
                assessment["confidence"] = "high"
                assessment["reasons"].append(
                    "Write primitive can enable memory corruption"
                )

        # Check for controlled address
        if report.fault_address:
            addr = int(report.fault_address, 16) if report.fault_address.startswith("0x") else 0
            if addr < 0x1000:  # Null page
                assessment["reasons"].append("Near-null dereference, limited impact")
            elif addr > 0x7f0000000000:  # User-controlled region
                assessment["exploitable"] = True
                assessment["reasons"].append("Fault address in user-controllable range")

        return assessment
