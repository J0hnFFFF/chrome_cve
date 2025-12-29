"""
Expert Review CLI Interface

Command-line interface for expert PoC review (Phase 5.3.1).
"""

import os
import sys
import tempfile
import subprocess
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

# Rich library for enhanced CLI
try:
    from rich.console import Console
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.prompt import Prompt, Confirm
    from rich.markdown import Markdown
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None

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
        self.console = Console() if RICH_AVAILABLE else None
        self.use_rich = RICH_AVAILABLE
    
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
        if self.use_rich:
            return self._request_review_rich(poc_code, cve_id, metadata)
        else:
            return self._request_review_plain(poc_code, cve_id, metadata)
    
    def _request_review_rich(self, poc_code: str, cve_id: str, metadata: Dict[str, Any] = None) -> ReviewResult:
        """Rich-enhanced review interface."""
        console = self.console
        
        # Header
        console.print()
        console.print(Panel(
            f"[bold cyan]PoC Review Required[/bold cyan]\n[yellow]{cve_id}[/yellow]",
            box=box.DOUBLE,
            expand=False
        ))
        
        # Metadata table
        if metadata:
            table = Table(title="Metadata", box=box.SIMPLE, show_header=False)
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="white")
            
            for key, value in metadata.items():
                # Handle different value types
                if isinstance(value, (list, dict)):
                    value_str = str(value)[:100]
                else:
                    value_str = str(value)
                table.add_row(key, value_str)
            
            console.print(table)
            console.print()
        
        # Syntax-highlighted code
        syntax = Syntax(
            poc_code,
            "javascript",
            theme="monokai",
            line_numbers=True,
            word_wrap=False
        )
        console.print(Panel(
            syntax,
            title="[bold]Generated PoC[/bold]",
            border_style="green"
        ))
        
        # Review options
        console.print("\n[bold]Review Options:[/bold]")
        options_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        options_table.add_column("Key", style="bold cyan")
        options_table.add_column("Action", style="white")
        
        options_table.add_row("1", "✓ Accept and verify")
        options_table.add_row("2", "✎ Edit PoC")
        options_table.add_row("3", "✗ Reject and regenerate")
        options_table.add_row("4", "💬 Add feedback only")
        options_table.add_row("5", "⏭  Skip review")
        options_table.add_row("D", "📄 View details")
        options_table.add_row("S", "🔍 View similar cases")
        
        console.print(options_table)
        
        while True:
            choice = Prompt.ask(
                "\n[bold cyan]Choice[/bold cyan]",
                choices=["1", "2", "3", "4", "5", "d", "D", "s", "S"],
                default="1"
            ).upper()
            
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
            elif choice == "D":
                self._show_details(metadata)
            elif choice == "S":
                self._show_similar_cases(cve_id)
            else:
                console.print("[red]Invalid choice. Please select from the options.[/red]")
    
    def _request_review_plain(self, poc_code: str, cve_id: str, metadata: Dict[str, Any] = None) -> ReviewResult:
        """Plain text review interface (fallback)."""
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
    
    def _show_details(self, metadata: Dict[str, Any] = None) -> None:
        """Show detailed information about the PoC."""
        if not self.use_rich:
            print("\n[Details view requires Rich library]")
            return
        
        console = self.console
        console.print("\n[bold cyan]Detailed Information[/bold cyan]")
        
        if metadata:
            # Analysis details
            if "analysis" in metadata:
                analysis = metadata["analysis"]
                console.print(Panel(
                    f"""[bold]Vulnerability Type:[/bold] {analysis.get('vulnerability_type', 'N/A')}
[bold]Component:[/bold] {analysis.get('component', 'N/A')}
[bold]Root Cause:[/bold] {analysis.get('root_cause', 'N/A')}
[bold]Confidence:[/bold] {analysis.get('confidence', 0):.2f}""",
                    title="Analysis",
                    border_style="blue"
                ))
            
            # Verification details
            if "verification" in metadata:
                verification = metadata["verification"]
                console.print(Panel(
                    f"""[bold]Success:[/bold] {verification.get('success', False)}
[bold]Crash Detected:[/bold] {verification.get('crash_detected', False)}
[bold]Crash Type:[/bold] {verification.get('crash_type', 'N/A')}
[bold]Reproducibility:[/bold] {verification.get('reproducibility', 'N/A')}""",
                    title="Verification",
                    border_style="yellow"
                ))
        
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()
    
    def _show_similar_cases(self, cve_id: str) -> None:
        """Show similar cases from episode memory."""
        if not self.use_rich:
            print("\n[Similar cases view requires Rich library]")
            return
        
        console = self.console
        console.print("\n[bold cyan]Similar Cases[/bold cyan]")
        
        # This would query EpisodeMemory in a real implementation
        # For now, show a placeholder
        table = Table(title="Similar CVEs", box=box.ROUNDED)
        table.add_column("CVE ID", style="cyan")
        table.add_column("Similarity", style="green")
        table.add_column("Success", style="yellow")
        table.add_column("Strategy", style="white")
        
        # Placeholder data
        table.add_row("CVE-2021-XXXX", "0.85", "✓", "JIT Optimization")
        table.add_row("CVE-2020-YYYY", "0.72", "✓", "Memory Spray")
        table.add_row("CVE-2019-ZZZZ", "0.68", "✗", "Direct Trigger")
        
        console.print(table)
        console.print("\n[dim italic]Note: This is a placeholder. Real implementation would query EpisodeMemory.[/dim italic]")
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()
 
         d e f   d i s p l a y _ b a t c h _ r e s u l t s ( s e l f ,   b a t c h _ r e s u l t s :   D i c t [ s t r ,   A n y ] )   - >   N o n e :  
                 " " "  
                 D i s p l a y   b a t c h   v e r i f i c a t i o n   r e s u l t s   i n   a   f o r m a t t e d   t a b l e .  
                  
                 A r g s :  
                         b a t c h _ r e s u l t s :   R e s u l t s   f r o m   V e r i f i e r A g e n t . v e r i f y _ b a t c h  
                 " " "  
                 i f   n o t   s e l f . u s e _ r i c h :  
                         s e l f . _ d i s p l a y _ b a t c h _ r e s u l t s _ p l a i n ( b a t c h _ r e s u l t s )  
                         r e t u r n  
                  
                 c o n s o l e   =   s e l f . c o n s o l e  
                  
                 #   S u m m a r y   p a n e l  
                 t o t a l   =   b a t c h _ r e s u l t s . g e t ( " t o t a l " ,   0 )  
                 c r a s h e d   =   b a t c h _ r e s u l t s . g e t ( " c r a s h e d " ,   0 )  
                 v e r i f i e d   =   b a t c h _ r e s u l t s . g e t ( " v e r i f i e d " ,   0 )  
                  
                 s u m m a r y   =   f " " " [ b o l d ] T o t a l   C a n d i d a t e s : [ / b o l d ]   { t o t a l }  
 [ b o l d ] V e r i f i e d : [ / b o l d ]   { v e r i f i e d }  
 [ b o l d ] C r a s h e d : [ / b o l d ]   { c r a s h e d }  
 [ b o l d ] S u c c e s s   R a t e : [ / b o l d ]   { ( c r a s h e d / t o t a l * 1 0 0 )   i f   t o t a l   >   0   e l s e   0 : . 1 f } % " " "  
                  
                 c o n s o l e . p r i n t ( P a n e l (  
                         s u m m a r y ,  
                         t i t l e = " [ b o l d   c y a n ] B a t c h   V e r i f i c a t i o n   S u m m a r y [ / b o l d   c y a n ] " ,  
                         b o r d e r _ s t y l e = " c y a n " ,  
                         b o x = b o x . D O U B L E  
                 ) )  
                  
                 #   R e s u l t s   t a b l e  
                 t a b l e   =   T a b l e ( t i t l e = " C a n d i d a t e   R e s u l t s " ,   b o x = b o x . R O U N D E D ,   s h o w _ l i n e s = T r u e )  
                 t a b l e . a d d _ c o l u m n ( " # " ,   s t y l e = " c y a n " ,   j u s t i f y = " c e n t e r " )  
                 t a b l e . a d d _ c o l u m n ( " S t r a t e g y " ,   s t y l e = " y e l l o w " )  
                 t a b l e . a d d _ c o l u m n ( " S t a t u s " ,   j u s t i f y = " c e n t e r " )  
                 t a b l e . a d d _ c o l u m n ( " C r a s h   T y p e " ,   s t y l e = " m a g e n t a " )  
                 t a b l e . a d d _ c o l u m n ( " T i m e   ( s ) " ,   j u s t i f y = " r i g h t " ,   s t y l e = " g r e e n " )  
                  
                 f o r   c a n d i d a t e   i n   b a t c h _ r e s u l t s . g e t ( " c a n d i d a t e s " ,   [ ] ) :  
                         i d x   =   c a n d i d a t e . g e t ( " i n d e x " ,   0 )   +   1  
                         s t r a t e g y   =   c a n d i d a t e . g e t ( " s t r a t e g y " ,   " U n k n o w n " )  
                         c r a s h e d   =   c a n d i d a t e . g e t ( " c r a s h e d " ,   F a l s e )  
                         c r a s h _ t y p e   =   c a n d i d a t e . g e t ( " c r a s h _ t y p e " ,   " N / A " )  
                         e x e c _ t i m e   =   c a n d i d a t e . g e t ( " e x e c u t i o n _ t i m e " ,   0 )  
                          
                         #   S t a t u s   w i t h   e m o j i  
                         i f   c r a s h e d :  
                                 s t a t u s   =   " [ g r e e n ] A�? C r a s h e d [ / g r e e n ] "  
                         e l i f   c a n d i d a t e . g e t ( " s u c c e s s " ,   F a l s e ) :  
                                 s t a t u s   =   " [ y e l l o w ] <�? N o   C r a s h [ / y e l l o w ] "  
                         e l s e :  
                                 s t a t u s   =   " [ r e d ] A�? F a i l e d [ / r e d ] "  
                          
                         t a b l e . a d d _ r o w (  
                                 s t r ( i d x ) ,  
                                 s t r a t e g y ,  
                                 s t a t u s ,  
                                 c r a s h _ t y p e   i f   c r a s h e d   e l s e   " - " ,  
                                 f " { e x e c _ t i m e : . 2 f } "  
                         )  
                  
                 c o n s o l e . p r i n t ( t a b l e )  
                  
                 #   B e s t   c a n d i d a t e   h i g h l i g h t  
                 i f   b a t c h _ r e s u l t s . g e t ( " f i r s t _ s u c c e s s " ) :  
                         b e s t   =   b a t c h _ r e s u l t s [ " f i r s t _ s u c c e s s " ]  
                         c o n s o l e . p r i n t ( P a n e l (  
                                 f " " " [ b o l d   g r e e n ] B e s t   C a n d i d a t e :   # { b e s t [ ' i n d e x ' ]   +   1 } [ / b o l d   g r e e n ]  
 [ b o l d ] S t r a t e g y : [ / b o l d ]   { b e s t [ ' s t r a t e g y ' ] }  
 [ b o l d ] C r a s h   T y p e : [ / b o l d ]   { b e s t . g e t ( ' c r a s h _ t y p e ' ,   ' N / A ' ) }  
 [ b o l d ] E x e c u t i o n   T i m e : [ / b o l d ]   { b e s t . g e t ( ' e x e c u t i o n _ t i m e ' ,   0 ) : . 2 f } s " " " ,  
                                 t i t l e = " A�? S u c c e s s f u l   C r a s h " ,  
                                 b o r d e r _ s t y l e = " g r e e n "  
                         ) )  
          
         d e f   _ d i s p l a y _ b a t c h _ r e s u l t s _ p l a i n ( s e l f ,   b a t c h _ r e s u l t s :   D i c t [ s t r ,   A n y ] )   - >   N o n e :  
                 " " " P l a i n   t e x t   d i s p l a y   o f   b a t c h   r e s u l t s . " " "  
                 p r i n t ( " \ n "   +   " = " * 7 0 )  
                 p r i n t ( " B a t c h   V e r i f i c a t i o n   R e s u l t s " )  
                 p r i n t ( " = " * 7 0 )  
                  
                 t o t a l   =   b a t c h _ r e s u l t s . g e t ( " t o t a l " ,   0 )  
                 c r a s h e d   =   b a t c h _ r e s u l t s . g e t ( " c r a s h e d " ,   0 )  
                 v e r i f i e d   =   b a t c h _ r e s u l t s . g e t ( " v e r i f i e d " ,   0 )  
                  
                 p r i n t ( f " \ n T o t a l   C a n d i d a t e s :   { t o t a l } " )  
                 p r i n t ( f " V e r i f i e d :   { v e r i f i e d } " )  
                 p r i n t ( f " C r a s h e d :   { c r a s h e d } " )  
                 p r i n t ( f " S u c c e s s   R a t e :   { ( c r a s h e d / t o t a l * 1 0 0 )   i f   t o t a l   >   0   e l s e   0 : . 1 f } % " )  
                  
                 p r i n t ( " \ n C a n d i d a t e   R e s u l t s : " )  
                 p r i n t ( " - " * 7 0 )  
                 f o r   c a n d i d a t e   i n   b a t c h _ r e s u l t s . g e t ( " c a n d i d a t e s " ,   [ ] ) :  
                         i d x   =   c a n d i d a t e . g e t ( " i n d e x " ,   0 )   +   1  
                         s t r a t e g y   =   c a n d i d a t e . g e t ( " s t r a t e g y " ,   " U n k n o w n " )  
                         c r a s h e d   =   c a n d i d a t e . g e t ( " c r a s h e d " ,   F a l s e )  
                         s t a t u s   =   " C R A S H E D "   i f   c r a s h e d   e l s e   " N O   C R A S H "  
                         p r i n t ( f "     # { i d x }   { s t r a t e g y : 2 0 s }   -   { s t a t u s } " )  
                 p r i n t ( " - " * 7 0 )  
                  
                 i f   b a t c h _ r e s u l t s . g e t ( " f i r s t _ s u c c e s s " ) :  
                         b e s t   =   b a t c h _ r e s u l t s [ " f i r s t _ s u c c e s s " ]  
                         p r i n t ( f " \ n A�? B e s t :   # { b e s t [ ' i n d e x ' ]   +   1 }   ( { b e s t [ ' s t r a t e g y ' ] } ) " )  
  
         d e f   v i e w _ s o u r c e ( s e l f ,   f i l e _ p a t h :   s t r ,   l i n e _ n u m b e r :   i n t   =   N o n e ,   c o n t e x t _ l i n e s :   i n t   =   1 0 )   - >   N o n e :  
                 " " "  
                 V i e w   s o u r c e   c o d e   f r o m   C h r o m i u m   r e p o s i t o r y .  
                  
                 A r g s :  
                         f i l e _ p a t h :   P a t h   t o   s o u r c e   f i l e   ( e . g . ,   v 8 / s r c / c o m p i l e r / j s - c a l l - r e d u c e r . c c )  
                         l i n e _ n u m b e r :   O p t i o n a l   l i n e   n u m b e r   t o   h i g h l i g h t  
                         c o n t e x t _ l i n e s :   N u m b e r   o f   l i n e s   t o   s h o w   a r o u n d   t h e   t a r g e t   l i n e  
                 " " "  
                 i f   n o t   s e l f . u s e _ r i c h :  
                         s e l f . _ v i e w _ s o u r c e _ p l a i n ( f i l e _ p a t h ,   l i n e _ n u m b e r ,   c o n t e x t _ l i n e s )  
                         r e t u r n  
                  
                 c o n s o l e   =   s e l f . c o n s o l e  
                  
                 #   F e t c h   s o u r c e   f i l e  
                 f r o m   . . t o o l s . c h r o m i u m _ t o o l s   i m p o r t   f e t c h _ c h r o m i u m _ f i l e  
                  
                 c o n s o l e . p r i n t ( f " \ n [ c y a n ] F e t c h i n g   s o u r c e : [ / c y a n ]   { f i l e _ p a t h } " )  
                  
                 t r y :  
                         c o n t e n t   =   f e t c h _ c h r o m i u m _ f i l e . f u n c ( f i l e _ p a t h )  
                          
                         i f   c o n t e n t . s t a r t s w i t h ( " E r r o r : " ) :  
                                 c o n s o l e . p r i n t ( f " [ r e d ] { c o n t e n t } [ / r e d ] " )  
                                 r e t u r n  
                          
                         l i n e s   =   c o n t e n t . s p l i t ( ' \ n ' )  
                          
                         #   D e t e r m i n e   r a n g e   t o   d i s p l a y  
                         i f   l i n e _ n u m b e r :  
                                 s t a r t   =   m a x ( 0 ,   l i n e _ n u m b e r   -   c o n t e x t _ l i n e s   -   1 )  
                                 e n d   =   m i n ( l e n ( l i n e s ) ,   l i n e _ n u m b e r   +   c o n t e x t _ l i n e s )  
                                 d i s p l a y _ l i n e s   =   l i n e s [ s t a r t : e n d ]  
                                 s t a r t _ l i n e _ n u m   =   s t a r t   +   1  
                                 h i g h l i g h t _ l i n e   =   l i n e _ n u m b e r   -   s t a r t  
                         e l s e :  
                                 #   S h o w   f i r s t   5 0   l i n e s   i f   n o   l i n e   n u m b e r   s p e c i f i e d  
                                 d i s p l a y _ l i n e s   =   l i n e s [ : 5 0 ]  
                                 s t a r t _ l i n e _ n u m   =   1  
                                 h i g h l i g h t _ l i n e   =   N o n e  
                          
                         #   C r e a t e   s y n t a x   o b j e c t  
                         s y n t a x   =   S y n t a x (  
                                 ' \ n ' . j o i n ( d i s p l a y _ l i n e s ) ,  
                                 " c p p " ,     #   M o s t   C h r o m i u m   f i l e s   a r e   C + +  
                                 t h e m e = " m o n o k a i " ,  
                                 l i n e _ n u m b e r s = T r u e ,  
                                 s t a r t _ l i n e = s t a r t _ l i n e _ n u m ,  
                                 h i g h l i g h t _ l i n e s = { l i n e _ n u m b e r }   i f   l i n e _ n u m b e r   e l s e   s e t ( ) ,  
                                 w o r d _ w r a p = F a l s e  
                         )  
                          
                         t i t l e   =   f " [ b o l d ] { f i l e _ p a t h } [ / b o l d ] "  
                         i f   l i n e _ n u m b e r :  
                                 t i t l e   + =   f "   [ y e l l o w ] @   L i n e   { l i n e _ n u m b e r } [ / y e l l o w ] "  
                          
                         c o n s o l e . p r i n t ( P a n e l (  
                                 s y n t a x ,  
                                 t i t l e = t i t l e ,  
                                 b o r d e r _ s t y l e = " b l u e " ,  
                                 e x p a n d = F a l s e  
                         ) )  
                          
                         c o n s o l e . p r i n t ( f " \ n [ d i m ] S h o w i n g   l i n e s   { s t a r t _ l i n e _ n u m } - { s t a r t _ l i n e _ n u m   +   l e n ( d i s p l a y _ l i n e s )   -   1 }   o f   { l e n ( l i n e s ) } [ / d i m ] " )  
                          
                 e x c e p t   E x c e p t i o n   a s   e :  
                         c o n s o l e . p r i n t ( f " [ r e d ] E r r o r   f e t c h i n g   s o u r c e :   { s t r ( e ) } [ / r e d ] " )  
                  
                 c o n s o l e . p r i n t ( " \ n [ d i m ] P r e s s   E n t e r   t o   c o n t i n u e . . . [ / d i m ] " )  
                 i n p u t ( )  
          
         d e f   _ v i e w _ s o u r c e _ p l a i n ( s e l f ,   f i l e _ p a t h :   s t r ,   l i n e _ n u m b e r :   i n t   =   N o n e ,   c o n t e x t _ l i n e s :   i n t   =   1 0 )   - >   N o n e :  
                 " " " P l a i n   t e x t   s o u r c e   v i e w e r . " " "  
                 f r o m   . . t o o l s . c h r o m i u m _ t o o l s   i m p o r t   f e t c h _ c h r o m i u m _ f i l e  
                  
                 p r i n t ( f " \ n F e t c h i n g   s o u r c e :   { f i l e _ p a t h } " )  
                  
                 t r y :  
                         c o n t e n t   =   f e t c h _ c h r o m i u m _ f i l e . f u n c ( f i l e _ p a t h )  
                          
                         i f   c o n t e n t . s t a r t s w i t h ( " E r r o r : " ) :  
                                 p r i n t ( c o n t e n t )  
                                 r e t u r n  
                          
                         l i n e s   =   c o n t e n t . s p l i t ( ' \ n ' )  
                          
                         i f   l i n e _ n u m b e r :  
                                 s t a r t   =   m a x ( 0 ,   l i n e _ n u m b e r   -   c o n t e x t _ l i n e s   -   1 )  
                                 e n d   =   m i n ( l e n ( l i n e s ) ,   l i n e _ n u m b e r   +   c o n t e x t _ l i n e s )  
                                 d i s p l a y _ l i n e s   =   l i n e s [ s t a r t : e n d ]  
                                 s t a r t _ l i n e _ n u m   =   s t a r t   +   1  
                         e l s e :  
                                 d i s p l a y _ l i n e s   =   l i n e s [ : 5 0 ]  
                                 s t a r t _ l i n e _ n u m   =   1  
                          
                         p r i n t ( f " \ n { f i l e _ p a t h } "   +   ( f "   @   L i n e   { l i n e _ n u m b e r } "   i f   l i n e _ n u m b e r   e l s e   " " ) )  
                         p r i n t ( " - "   *   7 0 )  
                          
                         f o r   i ,   l i n e   i n   e n u m e r a t e ( d i s p l a y _ l i n e s ,   s t a r t = s t a r t _ l i n e _ n u m ) :  
                                 m a r k e r   =   " > > > "   i f   i   = =   l i n e _ n u m b e r   e l s e   "       "  
                                 p r i n t ( f " { m a r k e r }   { i : 4 d }   |   { l i n e } " )  
                          
                         p r i n t ( " - "   *   7 0 )  
                         p r i n t ( f " S h o w i n g   l i n e s   { s t a r t _ l i n e _ n u m } - { s t a r t _ l i n e _ n u m   +   l e n ( d i s p l a y _ l i n e s )   -   1 }   o f   { l e n ( l i n e s ) } " )  
                          
                 e x c e p t   E x c e p t i o n   a s   e :  
                         p r i n t ( f " E r r o r   f e t c h i n g   s o u r c e :   { s t r ( e ) } " )  
                  
                 p r i n t ( " \ n P r e s s   E n t e r   t o   c o n t i n u e . . . " )  
                 i n p u t ( )  
          
         d e f   v i e w _ s t a c k _ t r a c e _ s o u r c e ( s e l f ,   s t a c k _ t r a c e :   L i s t [ D i c t [ s t r ,   A n y ] ] )   - >   N o n e :  
                 " " "  
                 I n t e r a c t i v e   v i e w e r   f o r   s t a c k   t r a c e   w i t h   s o u r c e   c o d e .  
                  
                 A r g s :  
                         s t a c k _ t r a c e :   L i s t   o f   s t a c k   f r a m e s   w i t h   f i l e ,   l i n e ,   f u n c t i o n   i n f o  
                 " " "  
                 i f   n o t   s e l f . u s e _ r i c h :  
                         s e l f . _ v i e w _ s t a c k _ t r a c e _ p l a i n ( s t a c k _ t r a c e )  
                         r e t u r n  
                  
                 c o n s o l e   =   s e l f . c o n s o l e  
                  
                 #   D i s p l a y   s t a c k   t r a c e   t a b l e  
                 t a b l e   =   T a b l e ( t i t l e = " S t a c k   T r a c e " ,   b o x = b o x . R O U N D E D )  
                 t a b l e . a d d _ c o l u m n ( " # " ,   s t y l e = " c y a n " ,   j u s t i f y = " c e n t e r " )  
                 t a b l e . a d d _ c o l u m n ( " F u n c t i o n " ,   s t y l e = " y e l l o w " )  
                 t a b l e . a d d _ c o l u m n ( " F i l e " ,   s t y l e = " g r e e n " )  
                 t a b l e . a d d _ c o l u m n ( " L i n e " ,   s t y l e = " m a g e n t a " ,   j u s t i f y = " r i g h t " )  
                  
                 f o r   i ,   f r a m e   i n   e n u m e r a t e ( s t a c k _ t r a c e [ : 2 0 ] ) :     #   L i m i t   t o   t o p   2 0  
                         t a b l e . a d d _ r o w (  
                                 s t r ( i ) ,  
                                 f r a m e . g e t ( " f u n c t i o n " ,   " ? ? " ) ,  
                                 f r a m e . g e t ( " f i l e " ,   " ? ? " ) ,  
                                 s t r ( f r a m e . g e t ( " l i n e " ,   " ? " ) )  
                         )  
                  
                 c o n s o l e . p r i n t ( t a b l e )  
                  
                 #   I n t e r a c t i v e   s e l e c t i o n  
                 w h i l e   T r u e :  
                         c h o i c e   =   P r o m p t . a s k (  
                                 " \ n [ c y a n ] E n t e r   f r a m e   n u m b e r   t o   v i e w   s o u r c e ,   o r   ' q '   t o   q u i t [ / c y a n ] " ,  
                                 d e f a u l t = " q "  
                         )  
                          
                         i f   c h o i c e . l o w e r ( )   = =   ' q ' :  
                                 b r e a k  
                          
                         t r y :  
                                 f r a m e _ i d x   =   i n t ( c h o i c e )  
                                 i f   0   < =   f r a m e _ i d x   <   l e n ( s t a c k _ t r a c e ) :  
                                         f r a m e   =   s t a c k _ t r a c e [ f r a m e _ i d x ]  
                                         f i l e _ p a t h   =   f r a m e . g e t ( " f i l e " )  
                                         l i n e _ n u m   =   f r a m e . g e t ( " l i n e " )  
                                          
                                         i f   f i l e _ p a t h   a n d   l i n e _ n u m :  
                                                 s e l f . v i e w _ s o u r c e ( f i l e _ p a t h ,   l i n e _ n u m )  
                                         e l s e :  
                                                 c o n s o l e . p r i n t ( " [ y e l l o w ] N o   s o u r c e   l o c a t i o n   a v a i l a b l e   f o r   t h i s   f r a m e [ / y e l l o w ] " )  
                                 e l s e :  
                                         c o n s o l e . p r i n t ( f " [ r e d ] I n v a l i d   f r a m e   n u m b e r .   C h o o s e   0 - { l e n ( s t a c k _ t r a c e ) - 1 } [ / r e d ] " )  
                         e x c e p t   V a l u e E r r o r :  
                                 c o n s o l e . p r i n t ( " [ r e d ] I n v a l i d   i n p u t .   E n t e r   a   n u m b e r   o r   ' q ' [ / r e d ] " )  
          
         d e f   _ v i e w _ s t a c k _ t r a c e _ p l a i n ( s e l f ,   s t a c k _ t r a c e :   L i s t [ D i c t [ s t r ,   A n y ] ] )   - >   N o n e :  
                 " " " P l a i n   t e x t   s t a c k   t r a c e   v i e w e r . " " "  
                 p r i n t ( " \ n S t a c k   T r a c e : " )  
                 p r i n t ( " - "   *   7 0 )  
                  
                 f o r   i ,   f r a m e   i n   e n u m e r a t e ( s t a c k _ t r a c e [ : 2 0 ] ) :  
                         p r i n t ( f "     { i : 2 d } .   { f r a m e . g e t ( ' f u n c t i o n ' ,   ' ? ? ' ) : 3 0 s }   { f r a m e . g e t ( ' f i l e ' ,   ' ? ? ' ) } : { f r a m e . g e t ( ' l i n e ' ,   ' ? ' ) } " )  
                  
                 p r i n t ( " - "   *   7 0 )  
                  
                 w h i l e   T r u e :  
                         c h o i c e   =   i n p u t ( " \ n E n t e r   f r a m e   n u m b e r   t o   v i e w   s o u r c e ,   o r   ' q '   t o   q u i t :   " ) . s t r i p ( )  
                          
                         i f   c h o i c e . l o w e r ( )   = =   ' q ' :  
                                 b r e a k  
                          
                         t r y :  
                                 f r a m e _ i d x   =   i n t ( c h o i c e )  
                                 i f   0   < =   f r a m e _ i d x   <   l e n ( s t a c k _ t r a c e ) :  
                                         f r a m e   =   s t a c k _ t r a c e [ f r a m e _ i d x ]  
                                         f i l e _ p a t h   =   f r a m e . g e t ( " f i l e " )  
                                         l i n e _ n u m   =   f r a m e . g e t ( " l i n e " )  
                                          
                                         i f   f i l e _ p a t h   a n d   l i n e _ n u m :  
                                                 s e l f . _ v i e w _ s o u r c e _ p l a i n ( f i l e _ p a t h ,   l i n e _ n u m )  
                                         e l s e :  
                                                 p r i n t ( " N o   s o u r c e   l o c a t i o n   a v a i l a b l e   f o r   t h i s   f r a m e " )  
                                 e l s e :  
                                         p r i n t ( f " I n v a l i d   f r a m e   n u m b e r .   C h o o s e   0 - { l e n ( s t a c k _ t r a c e ) - 1 } " )  
                         e x c e p t   V a l u e E r r o r :  
                                 p r i n t ( " I n v a l i d   i n p u t .   E n t e r   a   n u m b e r   o r   ' q ' " )  
 