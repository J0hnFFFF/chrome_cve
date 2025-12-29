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

    def display_batch_results(self, batch_results: Dict[str, Any]) -> None:
        """
        Display batch verification results in a formatted table.
        
        Args:
            batch_results: Results from VerifierAgent.verify_batch
        """
        if not self.use_rich:
            self._display_batch_results_plain(batch_results)
            return
        
        console = self.console
        
        # Summary panel
        total = batch_results.get("total", 0)
        crashed = batch_results.get("crashed", 0)
        verified = batch_results.get("verified", 0)
        
        summary = f"""[bold]Total Candidates:[/bold] {total}
[bold]Verified:[/bold] {verified}
[bold]Crashed:[/bold] {crashed}
[bold]Success Rate:[/bold] {(crashed/total*100) if total > 0 else 0:.1f}%"""
        
        console.print(Panel(
            summary,
            title="[bold cyan]Batch Verification Summary[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE
        ))
        
        # Results table
        table = Table(title="Candidate Results", box=box.ROUNDED, show_lines=True)
        table.add_column("#", style="cyan", justify="center")
        table.add_column("Strategy", style="yellow")
        table.add_column("Status", justify="center")
        table.add_column("Crash Type", style="magenta")
        table.add_column("Time (s)", justify="right", style="green")
        
        for candidate in batch_results.get("candidates", []):
            idx = candidate.get("index", 0) + 1
            strategy = candidate.get("strategy", "Unknown")
            crashed = candidate.get("crashed", False)
            crash_type = candidate.get("crash_type", "N/A")
            exec_time = candidate.get("execution_time", 0)
            
            # Status with emoji
            if crashed:
                status = "[green]A�?Crashed[/green]"
            elif candidate.get("success", False):
                status = "[yellow]<�?No Crash[/yellow]"
            else:
                status = "[red]A�?Failed[/red]"
            
            table.add_row(
                str(idx),
                strategy,
                status,
                crash_type if crashed else "-",
                f"{exec_time:.2f}"
            )
        
        console.print(table)
        
        # Best candidate highlight
        if batch_results.get("first_success"):
            best = batch_results["first_success"]
            console.print(Panel(
                f"""[bold green]Best Candidate: #{best['index'] + 1}[/bold green]
[bold]Strategy:[/bold] {best['strategy']}
[bold]Crash Type:[/bold] {best.get('crash_type', 'N/A')}
[bold]Execution Time:[/bold] {best.get('execution_time', 0):.2f}s""",
                title="A�?Successful Crash",
                border_style="green"
            ))
    
    def _display_batch_results_plain(self, batch_results: Dict[str, Any]) -> None:
        """Plain text display of batch results."""
        print("\n" + "="*70)
        print("Batch Verification Results")
        print("="*70)
        
        total = batch_results.get("total", 0)
        crashed = batch_results.get("crashed", 0)
        verified = batch_results.get("verified", 0)
        
        print(f"\nTotal Candidates: {total}")
        print(f"Verified: {verified}")
        print(f"Crashed: {crashed}")
        print(f"Success Rate: {(crashed/total*100) if total > 0 else 0:.1f}%")
        
        print("\nCandidate Results:")
        print("-"*70)
        for candidate in batch_results.get("candidates", []):
            idx = candidate.get("index", 0) + 1
            strategy = candidate.get("strategy", "Unknown")
            crashed = candidate.get("crashed", False)
            status = "CRASHED" if crashed else "NO CRASH"
            print(f"  #{idx} {strategy:20s} - {status}")
        print("-"*70)
        
        if batch_results.get("first_success"):
            best = batch_results["first_success"]
            print(f"\nA�?Best: #{best['index'] + 1} ({best['strategy']})")

    def view_source(self, file_path: str, line_number: int = None, context_lines: int = 10) -> None:
        """
        View source code from Chromium repository.
        
        Args:
            file_path: Path to source file (e.g., v8/src/compiler/js-call-reducer.cc)
            line_number: Optional line number to highlight
            context_lines: Number of lines to show around the target line
        """
        if not self.use_rich:
            self._view_source_plain(file_path, line_number, context_lines)
            return
        
        console = self.console
        
        # Fetch source file
        from ..tools.chromium_tools import fetch_chromium_file
        
        console.print(f"\n[cyan]Fetching source:[/cyan] {file_path}")
        
        try:
            content = fetch_chromium_file.func(file_path)
            
            if content.startswith("Error:"):
                console.print(f"[red]{content}[/red]")
                return
            
            lines = content.split('\n')
            
            # Determine range to display
            if line_number:
                start = max(0, line_number - context_lines - 1)
                end = min(len(lines), line_number + context_lines)
                display_lines = lines[start:end]
                start_line_num = start + 1
                highlight_line = line_number - start
            else:
                # Show first 50 lines if no line number specified
                display_lines = lines[:50]
                start_line_num = 1
                highlight_line = None
            
            # Create syntax object
            syntax = Syntax(
                '\n'.join(display_lines),
                "cpp",  # Most Chromium files are C++
                theme="monokai",
                line_numbers=True,
                start_line=start_line_num,
                highlight_lines={line_number} if line_number else set(),
                word_wrap=False
            )
            
            title = f"[bold]{file_path}[/bold]"
            if line_number:
                title += f" [yellow]@ Line {line_number}[/yellow]"
            
            console.print(Panel(
                syntax,
                title=title,
                border_style="blue",
                expand=False
            ))
            
            console.print(f"\n[dim]Showing lines {start_line_num}-{start_line_num + len(display_lines) - 1} of {len(lines)}[/dim]")
            
        except Exception as e:
            console.print(f"[red]Error fetching source: {str(e)}[/red]")
        
        console.print("\n[dim]Press Enter to continue...[/dim]")
        input()
    
    def _view_source_plain(self, file_path: str, line_number: int = None, context_lines: int = 10) -> None:
        """Plain text source viewer."""
        from ..tools.chromium_tools import fetch_chromium_file
        
        print(f"\nFetching source: {file_path}")
        
        try:
            content = fetch_chromium_file.func(file_path)
            
            if content.startswith("Error:"):
                print(content)
                return
            
            lines = content.split('\n')
            
            if line_number:
                start = max(0, line_number - context_lines - 1)
                end = min(len(lines), line_number + context_lines)
                display_lines = lines[start:end]
                start_line_num = start + 1
            else:
                display_lines = lines[:50]
                start_line_num = 1
            
            print(f"\n{file_path}" + (f" @ Line {line_number}" if line_number else ""))
            print("-" * 70)
            
            for i, line in enumerate(display_lines, start=start_line_num):
                marker = ">>>" if i == line_number else "   "
                print(f"{marker} {i:4d} | {line}")
            
            print("-" * 70)
            print(f"Showing lines {start_line_num}-{start_line_num + len(display_lines) - 1} of {len(lines)}")
            
        except Exception as e:
            print(f"Error fetching source: {str(e)}")
        
        print("\nPress Enter to continue...")
        input()
    
    def view_stack_trace_source(self, stack_trace: List[Dict[str, Any]]) -> None:
        """
        Interactive viewer for stack trace with source code.
        
        Args:
            stack_trace: List of stack frames with file, line, function info
        """
        if not self.use_rich:
            self._view_stack_trace_plain(stack_trace)
            return
        
        console = self.console
        
        # Display stack trace table
        table = Table(title="Stack Trace", box=box.ROUNDED)
        table.add_column("#", style="cyan", justify="center")
        table.add_column("Function", style="yellow")
        table.add_column("File", style="green")
        table.add_column("Line", style="magenta", justify="right")
        
        for i, frame in enumerate(stack_trace[:20]):  # Limit to top 20
            table.add_row(
                str(i),
                frame.get("function", "??"),
                frame.get("file", "??"),
                str(frame.get("line", "?"))
            )
        
        console.print(table)
        
        # Interactive selection
        while True:
            choice = Prompt.ask(
                "\n[cyan]Enter frame number to view source, or 'q' to quit[/cyan]",
                default="q"
            )
            
            if choice.lower() == 'q':
                break
            
            try:
                frame_idx = int(choice)
                if 0 <= frame_idx < len(stack_trace):
                    frame = stack_trace[frame_idx]
                    file_path = frame.get("file")
                    line_num = frame.get("line")
                    
                    if file_path and line_num:
                        self.view_source(file_path, line_num)
                    else:
                        console.print("[yellow]No source location available for this frame[/yellow]")
                else:
                    console.print(f"[red]Invalid frame number. Choose 0-{len(stack_trace)-1}[/red]")
            except ValueError:
                console.print("[red]Invalid input. Enter a number or 'q'[/red]")
    
    def _view_stack_trace_plain(self, stack_trace: List[Dict[str, Any]]) -> None:
        """Plain text stack trace viewer."""
        print("\nStack Trace:")
        print("-" * 70)
        
        for i, frame in enumerate(stack_trace[:20]):
            print(f"  {i:2d}. {frame.get('function', '??'):30s} {frame.get('file', '??')}:{frame.get('line', '?')}")
        
        print("-" * 70)
        
        while True:
            choice = input("\nEnter frame number to view source, or 'q' to quit: ").strip()
            
            if choice.lower() == 'q':
                break
            
            try:
                frame_idx = int(choice)
                if 0 <= frame_idx < len(stack_trace):
                    frame = stack_trace[frame_idx]
                    file_path = frame.get("file")
                    line_num = frame.get("line")
                    
                    if file_path and line_num:
                        self._view_source_plain(file_path, line_num)
                    else:
                        print("No source location available for this frame")
                else:
                    print(f"Invalid frame number. Choose 0-{len(stack_trace)-1}")
            except ValueError:
                print("Invalid input. Enter a number or 'q'")
