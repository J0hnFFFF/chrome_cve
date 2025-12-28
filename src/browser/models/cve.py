"""
CVE Data Models

Core data structures for CVE information.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class PatchInfo:
    """Information about a patch commit."""
    commit_hash: str
    repository: str  # e.g., "chromium/src", "v8/v8"
    message: str = ""
    files_changed: List[str] = field(default_factory=list)
    diff_content: str = ""
    regression_tests: str = ""  # Content of associated regression test files

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commit_hash": self.commit_hash,
            "repository": self.repository,
            "message": self.message,
            "files_changed": self.files_changed,
            "diff_content": self.diff_content,
            "regression_tests": self.regression_tests,
        }


@dataclass
class CVEInfo:
    """Complete CVE information aggregated from multiple sources."""
    cve_id: str
    description: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    cwe_ids: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    patches: List[PatchInfo] = field(default_factory=list)
    bug_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    component: str = ""  # V8, Blink, etc.

    # Intel source tracking
    sources: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cwe_ids": self.cwe_ids,
            "affected_versions": self.affected_versions,
            "fixed_versions": self.fixed_versions,
            "patches": [p.to_dict() for p in self.patches],
            "bug_ids": self.bug_ids,
            "references": self.references,
            "component": self.component,
            "sources": self.sources,
            "confidence": self.confidence,
        }

    def to_knowledge_text(self) -> str:
        """Convert to text format for LLM consumption."""
        text = f"""
# CVE Information: {self.cve_id}

## Summary
- **Severity**: {self.severity} (CVSS: {self.cvss_score})
- **Component**: {self.component}
- **CWE**: {', '.join(self.cwe_ids) or 'Not specified'}

## Description
{self.description}

## Patches
"""
        for i, patch in enumerate(self.patches, 1):
            text += f"""
### Patch {i}: {patch.commit_hash[:12]}
- **Repository**: {patch.repository}
- **Files Changed**: {len(patch.files_changed)}
  {chr(10).join('  - ' + f for f in patch.files_changed[:10])}

**Commit Message**:
{patch.message[:500]}{'...' if len(patch.message) > 500 else ''}
"""

        if self.bug_ids:
            text += f"""
## Related Bugs
{chr(10).join('- https://bugs.chromium.org/p/chromium/issues/detail?id=' + bid for bid in self.bug_ids)}
"""

        return text
