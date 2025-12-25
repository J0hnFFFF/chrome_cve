"""
Chrome CVE Reproduction Framework

Multi-agent based CVE reproduction pipeline.

Usage:
    python main.py --cve CVE-2024-XXXX [options]
"""

import argparse
import logging
import sys
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

    # Output options
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    parser.add_argument("--log-file", type=str, default=None, help="Log file path")

    # Utility
    parser.add_argument("--version", action="version", version="Chrome CVE Reproducer v2.0")

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

    # Run pipeline
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
