"""
Data Models for Chrome CVE Reproducer

Core data structures used across the framework:
- CVEInfo: Complete CVE information
- AnalysisResult: Vulnerability analysis output
- PoCResult: PoC generation output
- VerifyResult: Verification output
- Message: Inter-agent communication
"""

from .cve import CVEInfo, PatchInfo
from .analysis import AnalysisResult, VulnerabilityType
from .poc import PoCResult, PoCType
from .verify import VerifyResult, CrashInfo
from .message import Message, MessageType

__all__ = [
    'CVEInfo',
    'PatchInfo',
    'AnalysisResult',
    'VulnerabilityType',
    'PoCResult',
    'PoCType',
    'VerifyResult',
    'CrashInfo',
    'Message',
    'MessageType',
]
