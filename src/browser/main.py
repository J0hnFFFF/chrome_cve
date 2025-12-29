"""
Chrome CVE Reproduction Framework

Multi-agent based CVE reproduction pipeline.

Usage:
    python main.py --cve CVE-2024-XXXX [options]
"""

# Fix Windows GBK encoding issue FIRST - before any imports
import os
import sys
os.environ['PYTHONIOENCODING'] = 'utf-8'

# Suppress LangChain deprecation warnings from agentlib
# This is a third-party library issue, not ours
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning, module='agentlib')

# Also set for subprocess
if sys.platform == 'win32':
    import subprocess
    # Monkey patch Popen to always use UTF-8
    _original_popen_init = subprocess.Popen.__init__
    def _patched_popen_init(self, *args, **kwargs):
        if 'encoding' not in kwargs and 'universal_newlines' not in kwargs and 'text' not in kwargs:
            if kwargs.get('stdout') == subprocess.PIPE or kwargs.get('stderr') == subprocess.PIPE:
                kwargs['encoding'] = 'utf-8'
                kwargs['errors'] = 'ignore'
        return _original_popen_init(self, *args, **kwargs)
    subprocess.Popen.__init__ = _patched_popen_init

import argparse
import logging
from typing import Optional

# ============================================================================
# Logging Setup
# ============================================================================

class ColoredFormatter(logging.Formatter):
    """Colored log formatter for console output."""

    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Configure logging with console and optional file output."""
    logger = logging.getLogger("cve_reproducer")
    logger.setLevel(getattr(logging, level.upper()))

    # Console handler with colors
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColoredFormatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    ))
    logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))
        logger.addHandler(file_handler)

    return logger


# ============================================================================
# CLI
# ============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        description="Chrome CVE Reproduction Framework (Multi-Agent)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --cve CVE-2024-1234
  %(prog)s --cve CVE-2024-1234 --verbose
  %(prog)s --cve CVE-2024-1234 --config custom.yaml --output ./my_output
        """
    )

    # Required
    parser.add_argument("--cve", type=str, help="CVE ID to reproduce (e.g., CVE-2024-1234)")
    parser.add_argument("--commit", type=str, default=None, help="Direct commit hash (skip intel collection)")

    # Configuration
    parser.add_argument("--config", type=str, default=None, help="Path to config file (YAML)")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output directory")

    # LLM
    parser.add_argument("--model", type=str, default=None, help="LLM model name (e.g., gpt-4o, claude-3-sonnet, deepseek-chat)")

    # Execution
    parser.add_argument("--chrome-path", type=str, default=None, help="Path to Chrome executable")
    parser.add_argument("--d8-path", type=str, default=None, help="Path to d8 executable")
    parser.add_argument("--timeout", type=int, default=60, help="Execution timeout in seconds")
    parser.add_argument("--num-candidates", type=int, default=3, help="Number of PoC candidates to generate")
    parser.add_argument("--parallel", action="store_true", help="Run candidates generation and verification in parallel")
    parser.add_argument("--asan", action="store_true", help="Enable ASAN checks and use ASAN-instrumented binaries")

    # Differential Analysis
    parser.add_argument("--differential", action="store_true", help="Enable differential analysis between versions")
    parser.add_argument("--vulnerable-version", type=str, default=None, help="Specific vulnerable version/commit")
    parser.add_argument("--fixed-version", type=str, default=None, help="Specific fixed version/commit")

    # Environment
    parser.add_argument("--use-wsl", action="store_true", help="Use WSL for binary execution")

    # Output options
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    parser.add_argument("--log-file", type=str, default=None, help="Log file path")

    # Utility
    parser.add_argument("--version", action="version", version="Chrome CVE Reproducer v3.0")

    return parser


def print_banner():
    """Print ASCII banner."""
    print("""
 ██████╗██╗   ██╗███████╗    ██████╗ ███████╗██████╗ ██████╗  ██████╗
██╔════╝██║   ██║██╔════╝    ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗
██║     ██║   ██║█████╗      ██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║
██║     ╚██╗ ██╔╝██╔══╝      ██╔══██╗██╔══╝  ██╔═══╝ ██╔══██╗██║   ██║
╚██████╗ ╚████╔╝ ███████╗    ██║  ██║███████╗██║     ██║  ██║╚██████╔╝
 ╚═════╝  ╚═══╝  ╚══════╝    ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝
    """)


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # CVE is required
    if not args.cve:
        parser.print_help()
        print("\nError: --cve is required")
        return 1

    # Setup logging
    log_level = "DEBUG" if args.debug else ("INFO" if args.verbose else "WARNING")
    logger = setup_logging(log_level, args.log_file)

    # Print banner
    print_banner()
    print(f"Target: {args.cve}\n")

    # Initialize pipeline
    try:
        from .pipeline import CVEReproductionPipeline
        
        pipeline = CVEReproductionPipeline(
            cve_id=args.cve,
            config_path=args.config,
            output_dir=args.output,
            chrome_path=args.chrome_path,
            d8_path=args.d8_path,
            model=args.model,
            commit=args.commit,
            # Phase 6 additions
            num_candidates=args.num_candidates,
            parallel=args.parallel,
            asan=args.asan,
            differential=args.differential,
            vulnerable_version=args.vulnerable_version,
            fixed_version=args.fixed_version,
            use_wsl=args.use_wsl,
        )

        results = pipeline.run()
        return 0 if results.get("success") else 1

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 130

    except Exception as e:
        logger.exception(f"Pipeline failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
