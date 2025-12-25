"""
Episode Memory (案例库)

Stores and retrieves CVE reproduction cases.
Enables experience reuse across similar CVEs.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
from pathlib import Path


@dataclass
class CVECase:
    """
    A complete CVE reproduction case.

    Captures the full process from CVE to PoC,
    including successes and failures.
    """
    cve_id: str
    component: str
    vulnerability_type: str

    # Process record
    analysis_result: Dict[str, Any] = field(default_factory=dict)
    poc_result: Dict[str, Any] = field(default_factory=dict)
    verify_result: Dict[str, Any] = field(default_factory=dict)

    # Success metrics
    success: bool = False
    iterations: int = 0
    total_time: float = 0.0
    total_cost: float = 0.0

    # Lessons learned
    key_insights: List[str] = field(default_factory=list)
    failed_approaches: List[str] = field(default_factory=list)
    successful_strategy: str = ""

    # Metadata
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "component": self.component,
            "vulnerability_type": self.vulnerability_type,
            "analysis_result": self.analysis_result,
            "poc_result": self.poc_result,
            "verify_result": self.verify_result,
            "success": self.success,
            "iterations": self.iterations,
            "total_time": self.total_time,
            "total_cost": self.total_cost,
            "key_insights": self.key_insights,
            "failed_approaches": self.failed_approaches,
            "successful_strategy": self.successful_strategy,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CVECase":
        return cls(**d)

    def get_summary(self) -> str:
        """Get a summary for LLM context."""
        status = "Success" if self.success else "Failed"
        return f"""
## Case: {self.cve_id}
- Component: {self.component}
- Vulnerability: {self.vulnerability_type}
- Status: {status}
- Iterations: {self.iterations}

### Key Insights:
{chr(10).join('- ' + i for i in self.key_insights)}

### Successful Strategy:
{self.successful_strategy}
"""


class EpisodeMemory:
    """
    Manages CVE case storage and retrieval.

    Features:
    - Store successful and failed cases
    - Retrieve similar cases for new CVEs
    - Extract lessons learned
    """

    def __init__(self, storage_path: str = "./volumes/memory/episodes"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._cases: Dict[str, CVECase] = {}
        self._load_all()

    def _load_all(self) -> None:
        """Load all cases from storage."""
        for file in self.storage_path.glob("*.json"):
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    case = CVECase.from_dict(data)
                    self._cases[case.cve_id] = case
            except Exception as e:
                print(f"Warning: Failed to load case from {file}: {e}")

    def save(self, case: CVECase) -> None:
        """Save a case to storage."""
        case.updated_at = datetime.now().isoformat()
        self._cases[case.cve_id] = case

        file_path = self.storage_path / f"{case.cve_id}.json"
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(case.to_dict(), f, indent=2)

    def get(self, cve_id: str) -> Optional[CVECase]:
        """Get a case by CVE ID."""
        return self._cases.get(cve_id)

    def find_similar(
        self,
        component: str = None,
        vuln_type: str = None,
        limit: int = 5,
        success_only: bool = True,
    ) -> List[CVECase]:
        """
        Find similar cases.

        Args:
            component: Filter by component
            vuln_type: Filter by vulnerability type
            limit: Maximum number of results
            success_only: Only return successful cases

        Returns:
            List of matching cases
        """
        matches = []

        for case in self._cases.values():
            if success_only and not case.success:
                continue

            score = 0
            if component and component.lower() in case.component.lower():
                score += 2
            if vuln_type and vuln_type.lower() in case.vulnerability_type.lower():
                score += 2

            if score > 0:
                matches.append((score, case))

        # Sort by score descending
        matches.sort(key=lambda x: x[0], reverse=True)
        return [case for _, case in matches[:limit]]

    def get_all_cases(self) -> List[CVECase]:
        """Get all stored cases."""
        return list(self._cases.values())

    def get_success_rate(self, component: str = None) -> float:
        """Calculate success rate for a component."""
        cases = self._cases.values()
        if component:
            cases = [c for c in cases if component.lower() in c.component.lower()]

        if not cases:
            return 0.0

        successful = sum(1 for c in cases if c.success)
        return successful / len(list(cases))
