"""
Verification Data Models

Data structures for PoC verification results.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class CrashInfo:
    """Information about a crash."""
    crash_type: str = ""  # SIGSEGV, SIGABRT, etc.
    crash_address: str = ""
    crash_reason: str = ""
    faulting_instruction: str = ""
    registers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "crash_type": self.crash_type,
            "crash_address": self.crash_address,
            "crash_reason": self.crash_reason,
            "faulting_instruction": self.faulting_instruction,
            "registers": self.registers,
        }


@dataclass
class VerifyResult:
    """Complete verification result."""
    success: bool
    crash_info: Optional[CrashInfo] = None
    stack_trace: str = ""
    asan_report: str = ""
    reproducibility: str = ""  # always, sometimes, never

    # Execution details
    execution_time: float = 0.0
    runs_attempted: int = 1
    runs_crashed: int = 0
    chrome_version: str = ""
    d8_version: str = ""

    # Error handling
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "crash_info": self.crash_info.to_dict() if self.crash_info else None,
            "stack_trace": self.stack_trace,
            "asan_report": self.asan_report,
            "reproducibility": self.reproducibility,
            "execution_time": self.execution_time,
            "runs_attempted": self.runs_attempted,
            "runs_crashed": self.runs_crashed,
            "chrome_version": self.chrome_version,
            "d8_version": self.d8_version,
            "error_message": self.error_message,
        }

    @property
    def crash_rate(self) -> float:
        """Calculate crash rate."""
        if self.runs_attempted == 0:
            return 0.0
        return self.runs_crashed / self.runs_attempted
