"""
Expert Feedback Recording System

Records expert reviews and modifications for continuous improvement (Phase 5.3.3).
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ExpertFeedback:
    """Expert feedback on a PoC."""
    cve_id: str
    timestamp: str
    expert: str
    quality_score: int  # 1-5
    success: bool
    modifications: str
    failure_reason: Optional[str] = None
    suggestions: Optional[str] = None
    time_spent_minutes: Optional[int] = None


class FeedbackStore:
    """
    Stores and retrieves expert feedback.
    
    Features:
    - JSON-based storage
    - Query by CVE, expert, date
    - Statistics and analytics
    """
    
    def __init__(self, storage_dir: str = None):
        """
        Initialize feedback store.
        
        Args:
            storage_dir: Directory for storing feedback
        """
        self.storage_dir = storage_dir or os.path.join(
            os.path.expanduser("~"), ".chrome_cve_cache", "feedback"
        )
        os.makedirs(self.storage_dir, exist_ok=True)
        self._index_file = os.path.join(self.storage_dir, "index.json")
        self._load_index()
    
    def record_feedback(self, feedback: ExpertFeedback) -> bool:
        """
        Record expert feedback.
        
        Args:
            feedback: ExpertFeedback object
            
        Returns:
            True if successful
        """
        try:
            # Generate filename
            filename = f"{feedback.cve_id}_{feedback.timestamp.replace(':', '-')}.json"
            filepath = os.path.join(self.storage_dir, filename)
            
            # Save feedback
            with open(filepath, 'w') as f:
                json.dump(asdict(feedback), f, indent=2)
            
            # Update index
            self._add_to_index(feedback, filename)
            
            logger.info(f"Recorded feedback for {feedback.cve_id} by {feedback.expert}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to record feedback: {e}")
            return False
    
    def get_feedback(
        self,
        cve_id: str = None,
        expert: str = None,
        min_score: int = None
    ) -> List[ExpertFeedback]:
        """
        Query feedback.
        
        Args:
            cve_id: Filter by CVE ID
            expert: Filter by expert name
            min_score: Minimum quality score
            
        Returns:
            List of matching feedback
        """
        results = []
        
        for entry in self._index:
            # Apply filters
            if cve_id and entry["cve_id"] != cve_id:
                continue
            if expert and entry["expert"] != expert:
                continue
            if min_score and entry.get("quality_score", 0) < min_score:
                continue
            
            # Load full feedback
            filepath = os.path.join(self.storage_dir, entry["filename"])
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        results.append(ExpertFeedback(**data))
                except:
                    pass
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get feedback statistics."""
        if not self._index:
            return {"total": 0}
        
        total = len(self._index)
        successful = sum(1 for e in self._index if e.get("success"))
        avg_score = sum(e.get("quality_score", 0) for e in self._index) / total if total > 0 else 0
        
        # Expert stats
        experts = {}
        for entry in self._index:
            expert = entry.get("expert", "unknown")
            if expert not in experts:
                experts[expert] = {"count": 0, "successful": 0}
            experts[expert]["count"] += 1
            if entry.get("success"):
                experts[expert]["successful"] += 1
        
        return {
            "total": total,
            "successful": successful,
            "success_rate": successful / total if total > 0 else 0,
            "average_score": avg_score,
            "experts": experts
        }
    
    def get_common_modifications(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most common modifications."""
        modifications = {}
        
        for entry in self._index:
            mod = entry.get("modifications", "").lower()
            if mod:
                modifications[mod] = modifications.get(mod, 0) + 1
        
        # Sort by frequency
        sorted_mods = sorted(
            modifications.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [
            {"modification": mod, "count": count}
            for mod, count in sorted_mods[:limit]
        ]
    
    def _load_index(self):
        """Load feedback index."""
        if os.path.exists(self._index_file):
            try:
                with open(self._index_file, 'r') as f:
                    self._index = json.load(f)
            except:
                self._index = []
        else:
            self._index = []
    
    def _add_to_index(self, feedback: ExpertFeedback, filename: str):
        """Add feedback to index."""
        self._index.append({
            "cve_id": feedback.cve_id,
            "timestamp": feedback.timestamp,
            "expert": feedback.expert,
            "quality_score": feedback.quality_score,
            "success": feedback.success,
            "filename": filename
        })
        
        # Save index
        try:
            with open(self._index_file, 'w') as f:
                json.dump(self._index, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save index: {e}")


def create_feedback(
    cve_id: str,
    expert: str,
    quality_score: int,
    success: bool,
    modifications: str = "",
    failure_reason: str = None,
    suggestions: str = None
) -> ExpertFeedback:
    """Helper function to create feedback."""
    return ExpertFeedback(
        cve_id=cve_id,
        timestamp=datetime.now().isoformat(),
        expert=expert,
        quality_score=quality_score,
        success=success,
        modifications=modifications,
        failure_reason=failure_reason,
        suggestions=suggestions
    )
