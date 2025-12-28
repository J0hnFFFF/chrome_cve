"""
Expert Review CLI Interface

Command-line interface for expert PoC review (Phase 5.3.1).
"""

import os
import sys
import tempfile
import subprocess
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ReviewResult:
    """Result of expert review."""
    action: str  # accept, edit, reject
    modified_code: Optional[str] = None
    feedback: Optional[str] = None
    quality_score: Optional[int] = None


class ExpertReviewCLI:
    """
    CLI interface for expert PoC review.
    
    Features:
    - Interactive review prompts
    - Code editor integration
    - Feedback collection
    """
    
    def __init__(self, feedback_store=None):
        """
        Initialize review CLI.
        
        Args:
            feedback_store: FeedbackStore instance
        """
        self.feedback_store = feedback_store
        self.editor = os.environ.get("EDITOR", "notepad" if sys.platform == "win32" else "vi")
    
    def request_review(
        self,
        poc_code: str,
        cve_id: str,
        metadata: Dict[str, Any] = None
    ) -> ReviewResult:
        """
        Request expert review of PoC.
        
        Args:
            poc_code: PoC code to review
            cve_id: CVE ID
            metadata: Additional metadata
            
        Returns:
            ReviewResult with action and modifications
        """
        print("\n" + "="*70)
        print(f"PoC Review Required: {cve_id}")
        print("="*70)
        
        # Show metadata
        if metadata:
            print("\nMetadata:")
            for key, value in metadata.items():
                print(f"  {key}: {value}")
        
        # Show PoC code (first 20 lines)
        print("\nGenerated PoC (preview):")
        print("-"*70)
        lines = poc_code.split('\n')
        for i, line in enumerate(lines[:20], 1):
            print(f"{i:3d} | {line}")
        if len(lines) > 20:
            print(f"... ({len(lines) - 20} more lines)")
        print("-"*70)
        
        # Review options
        print("\nReview Options:")
        print("  1. Accept and verify")
        print("  2. Edit PoC")
        print("  3. Reject and regenerate")
        print("  4. Add feedback only")
        print("  5. Skip review")
        
        while True:
            choice = input("\nChoice [1-5]: ").strip()
            
            if choice == "1":
                return self._handle_accept(poc_code, cve_id)
            elif choice == "2":
                return self._handle_edit(poc_code, cve_id)
            elif choice == "3":
                return self._handle_reject(poc_code, cve_id)
            elif choice == "4":
                return self._handle_feedback(poc_code, cve_id)
            elif choice == "5":
                return ReviewResult(action="skip")
            else:
                print("Invalid choice. Please enter 1-5.")
    
    def _handle_accept(self, poc_code: str, cve_id: str) -> ReviewResult:
        """Handle accept action."""
        print("\n✓ PoC accepted")
        
        # Optional feedback
        feedback = input("Add feedback (optional): ").strip()
        score = self._get_quality_score()
        
        if self.feedback_store and score:
            from .feedback_store import create_feedback
            fb = create_feedback(
                cve_id=cve_id,
                expert=self._get_expert_name(),
                quality_score=score,
                success=True,
                modifications="None (accepted as-is)",
                suggestions=feedback if feedback else None
            )
            self.feedback_store.record_feedback(fb)
        
        return ReviewResult(
            action="accept",
            feedback=feedback if feedback else None,
            quality_score=score
        )
    
    def _handle_edit(self, poc_code: str, cve_id: str) -> ReviewResult:
        """Handle edit action."""
        print("\n[*] Opening editor...")
        
        # Create temp file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.js',
            delete=False
        ) as f:
            f.write(poc_code)
            temp_file = f.name
        
        try:
            # Open editor
            subprocess.call([self.editor, temp_file])
            
            # Read modified code
            with open(temp_file, 'r') as f:
                modified_code = f.read()
            
            # Check if modified
            if modified_code == poc_code:
                print("\n[!] No changes made")
                return ReviewResult(action="skip")
            
            print("\n✓ PoC modified")
            
            # Get feedback
            modifications = input("Describe modifications: ").strip()
            score = self._get_quality_score()
            
            if self.feedback_store and score:
                from .feedback_store import create_feedback
                fb = create_feedback(
                    cve_id=cve_id,
                    expert=self._get_expert_name(),
                    quality_score=score,
                    success=True,
                    modifications=modifications
                )
                self.feedback_store.record_feedback(fb)
            
            return ReviewResult(
                action="edit",
                modified_code=modified_code,
                feedback=modifications,
                quality_score=score
            )
            
        finally:
            # Cleanup
            if os.path.exists(temp_file):
                os.remove(temp_file)
    
    def _handle_reject(self, poc_code: str, cve_id: str) -> ReviewResult:
        """Handle reject action."""
        print("\n✗ PoC rejected")
        
        reason = input("Rejection reason: ").strip()
        suggestions = input("Suggestions for regeneration: ").strip()
        
        if self.feedback_store:
            from .feedback_store import create_feedback
            fb = create_feedback(
                cve_id=cve_id,
                expert=self._get_expert_name(),
                quality_score=1,
                success=False,
                failure_reason=reason,
                suggestions=suggestions
            )
            self.feedback_store.record_feedback(fb)
        
        return ReviewResult(
            action="reject",
            feedback=reason,
            quality_score=1
        )
    
    def _handle_feedback(self, poc_code: str, cve_id: str) -> ReviewResult:
        """Handle feedback-only action."""
        print("\n[*] Collecting feedback...")
        
        feedback = input("Feedback: ").strip()
        score = self._get_quality_score()
        
        if self.feedback_store and score:
            from .feedback_store import create_feedback
            fb = create_feedback(
                cve_id=cve_id,
                expert=self._get_expert_name(),
                quality_score=score,
                success=False,
                suggestions=feedback
            )
            self.feedback_store.record_feedback(fb)
        
        return ReviewResult(
            action="feedback",
            feedback=feedback,
            quality_score=score
        )
    
    def _get_quality_score(self) -> Optional[int]:
        """Get quality score from user."""
        while True:
            score_str = input("Quality score (1-5, or skip): ").strip()
            if not score_str:
                return None
            try:
                score = int(score_str)
                if 1 <= score <= 5:
                    return score
                print("Score must be between 1 and 5")
            except ValueError:
                print("Invalid score")
    
    def _get_expert_name(self) -> str:
        """Get expert name."""
        return os.environ.get("USER", "expert")
