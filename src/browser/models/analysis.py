"""
Analysis Data Models

Data structures for vulnerability analysis results.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class VulnerabilityType(Enum):
    """Common vulnerability types in browser."""
    UAF = "use-after-free"
    OOB_READ = "out-of-bounds-read"
    OOB_WRITE = "out-of-bounds-write"
    TYPE_CONFUSION = "type-confusion"
    INTEGER_OVERFLOW = "integer-overflow"
    RACE_CONDITION = "race-condition"
    BUFFER_OVERFLOW = "buffer-overflow"
    HEAP_OVERFLOW = "heap-overflow"
    STACK_OVERFLOW = "stack-overflow"
    NULL_DEREF = "null-dereference"
    DOUBLE_FREE = "double-free"
    UNINITIALIZED_MEMORY = "uninitialized-memory"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, s: str) -> "VulnerabilityType":
        """Parse vulnerability type from string."""
        s_lower = s.lower().replace(" ", "-").replace("_", "-")
        for vt in cls:
            if vt.value in s_lower or s_lower in vt.value:
                return vt
        return cls.UNKNOWN


@dataclass
class AnalysisResult:
    """Complete vulnerability analysis result."""
    vulnerability_type: str
    component: str
    root_cause: str
    trigger_conditions: List[str] = field(default_factory=list)
    trigger_approach: str = ""
    poc_strategy: str = ""
    confidence: float = 0.0

    # Additional analysis details
    affected_functions: List[str] = field(default_factory=list)
    patch_summary: str = ""
    exploitation_difficulty: str = ""  # low, medium, high
    prerequisites: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_type": self.vulnerability_type,
            "component": self.component,
            "root_cause": self.root_cause,
            "trigger_conditions": self.trigger_conditions,
            "trigger_approach": self.trigger_approach,
            "poc_strategy": self.poc_strategy,
            "confidence": self.confidence,
            "affected_functions": self.affected_functions,
            "patch_summary": self.patch_summary,
            "exploitation_difficulty": self.exploitation_difficulty,
            "prerequisites": self.prerequisites,
        }

    def get_vuln_type_enum(self) -> VulnerabilityType:
        """Get the vulnerability type as enum."""
        return VulnerabilityType.from_string(self.vulnerability_type)
