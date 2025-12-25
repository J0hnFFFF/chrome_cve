"""
Intel Source Base Classes

Defines the abstract interface for all intelligence sources.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime


@dataclass
class IntelResult:
    """Result from an intelligence source."""
    source: str
    data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error: str = ""

    @property
    def success(self) -> bool:
        return not self.error and bool(self.data)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "data": self.data,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "error": self.error,
        }


class IntelSource(ABC):
    """
    Base class for intelligence sources.

    All intel sources must implement the collect() method.
    """

    name: str = "base_source"
    tier: int = 1  # 1=required, 2=important, 3=supplementary
    timeout: int = 30

    @abstractmethod
    def collect(self, cve_id: str) -> IntelResult:
        """
        Collect intelligence for a CVE.

        Args:
            cve_id: The CVE ID to collect intelligence for

        Returns:
            IntelResult with collected data
        """
        pass

    def get_info(self) -> Dict[str, Any]:
        """Get source metadata."""
        return {
            "name": self.name,
            "tier": self.tier,
            "timeout": self.timeout,
        }
