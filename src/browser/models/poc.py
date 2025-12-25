"""
PoC Data Models

Data structures for PoC generation results.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class PoCType(Enum):
    """Types of PoC."""
    JAVASCRIPT = "javascript"
    HTML = "html"
    HTML_JS = "html+javascript"
    WASM = "webassembly"
    MIXED = "mixed"


@dataclass
class PoCResult:
    """Complete PoC generation result."""
    code: str
    language: str  # javascript, html, etc.
    poc_type: PoCType = PoCType.JAVASCRIPT
    target_version: str = ""
    expected_behavior: str = ""
    success: bool = False

    # Generation metadata
    iterations: int = 1
    strategy_used: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "language": self.language,
            "poc_type": self.poc_type.value,
            "target_version": self.target_version,
            "expected_behavior": self.expected_behavior,
            "success": self.success,
            "iterations": self.iterations,
            "strategy_used": self.strategy_used,
            "notes": self.notes,
        }

    def save_to_file(self, path: str) -> None:
        """Save PoC code to file."""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self.code)
