"""
Rich Console Utilities

Provides a global Rich console instance for consistent formatting across the application.
"""

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# Global console instance
console = Console()

def create_progress():
    """Create a Rich progress bar with custom styling."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console
    )

def print_section(title: str, style: str = "bold cyan"):
    """Print a section header."""
    console.print(f"\n[{style}]{'='*60}[/{style}]")
    console.print(f"[{style}]{title}[/{style}]")
    console.print(f"[{style}]{'='*60}[/{style}]\n")

def print_stage(stage_name: str, icon: str = "▶"):
    """Print a stage indicator."""
    console.print(f"\n[bold yellow]{icon} [Stage] {stage_name}[/bold yellow]")

def print_success(message: str):
    """Print a success message."""
    console.print(f"[green]✓[/green] {message}")

def print_error(message: str):
    """Print an error message."""
    console.print(f"[red]✗[/red] {message}")

def print_warning(message: str):
    """Print a warning message."""
    console.print(f"[yellow]⚠[/yellow] {message}")

def print_info(message: str):
    """Print an info message."""
    console.print(f"[cyan]ℹ[/cyan] {message}")

def create_status_table(data: dict, title: str = "Status") -> Table:
    """Create a status table."""
    table = Table(title=title, box=box.ROUNDED, show_header=False)
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", style="yellow")
    
    for key, value in data.items():
        table.add_row(key, str(value))
    
    return table

def print_panel(content, title: str = None, style: str = "cyan"):
    """Print content in a panel."""
    console.print(Panel(content, title=title, border_style=style))
