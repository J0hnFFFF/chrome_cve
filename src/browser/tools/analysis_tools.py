"""
Analysis Tools for Patch Verification

Provides tools for verifying patch effectiveness through binary comparison
and crash correlation.
"""

import os
import subprocess
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PatchVerificationReport:
    """Report of patch verification results."""
    patch_effective: bool
    vulnerable_crashed: bool
    fixed_crashed: bool
    crash_in_patched_function: bool
    patched_functions: List[str]
    crash_location: Optional[str]
    details: str


def verify_patch_effectiveness(
    vulnerable_binary: str,
    fixed_binary: str,
    poc_code: str,
    crash_report: Any = None,
    timeout: int = 30
) -> PatchVerificationReport:
    """
    Verify that a patch effectively fixes the vulnerability.
    
    This function:
    1. Runs PoC on vulnerable binary (should crash)
    2. Runs PoC on fixed binary (should not crash)
    3. Compares binaries to identify patched functions
    4. Correlates crash location with patched functions
    
    Args:
        vulnerable_binary: Path to vulnerable binary (pre-patch)
        fixed_binary: Path to fixed binary (post-patch)
        poc_code: PoC code to test
        crash_report: Optional CrashReport from vulnerable run
        timeout: Execution timeout in seconds
        
    Returns:
        PatchVerificationReport with verification results
    """
    from ..tools.execution import execute_poc
    from ..tools.debug import CrashAnalyzer
    
    logger.info(f"Verifying patch effectiveness...")
    logger.info(f"  Vulnerable: {vulnerable_binary}")
    logger.info(f"  Fixed: {fixed_binary}")
    
    # Step 1: Run on vulnerable binary
    logger.info("Step 1: Testing vulnerable binary...")
    vuln_result = execute_poc(poc_code, vulnerable_binary, timeout=timeout)
    vuln_crashed = vuln_result.get("crashed", False)
    
    if not vuln_crashed:
        logger.warning("PoC did not crash on vulnerable binary!")
        return PatchVerificationReport(
            patch_effective=False,
            vulnerable_crashed=False,
            fixed_crashed=False,
            crash_in_patched_function=False,
            patched_functions=[],
            crash_location=None,
            details="PoC failed to trigger vulnerability on pre-patch binary"
        )
    
    # Analyze crash
    analyzer = CrashAnalyzer()
    if not crash_report and vuln_result.get("output"):
        crash_report = analyzer.analyze(vuln_result["output"])
    
    crash_location = None
    if crash_report and crash_report.stack_trace:
        # Get top frame location
        top_frame = crash_report.stack_trace[0]
        crash_location = f"{top_frame.get('function', '??')} at {top_frame.get('file', '??')}:{top_frame.get('line', '?')}"
    
    logger.info(f"  Vulnerable binary crashed: {crash_report.crash_type if crash_report else 'Unknown'}")
    if crash_location:
        logger.info(f"  Crash location: {crash_location}")
    
    # Step 2: Run on fixed binary
    logger.info("Step 2: Testing fixed binary...")
    fixed_result = execute_poc(poc_code, fixed_binary, timeout=timeout)
    fixed_crashed = fixed_result.get("crashed", False)
    
    logger.info(f"  Fixed binary crashed: {fixed_crashed}")
    
    # Step 3: Compare binaries to find patched functions
    logger.info("Step 3: Identifying patched functions...")
    patched_functions = _identify_patched_functions(vulnerable_binary, fixed_binary)
    
    if patched_functions:
        logger.info(f"  Found {len(patched_functions)} patched functions:")
        for func in patched_functions[:5]:
            logger.info(f"    - {func}")
    else:
        logger.warning("  Could not identify patched functions")
    
    # Step 4: Correlate crash with patch
    crash_in_patched = False
    if crash_location and patched_functions:
        # Check if crash function is in patched functions
        crash_func = crash_location.split(" at ")[0] if " at " in crash_location else crash_location
        crash_in_patched = any(crash_func in pf or pf in crash_func for pf in patched_functions)
        logger.info(f"  Crash in patched function: {crash_in_patched}")
    
    # Determine patch effectiveness
    patch_effective = vuln_crashed and not fixed_crashed
    
    # Build details
    details_parts = []
    details_parts.append(f"Vulnerable binary: {'CRASHED' if vuln_crashed else 'NO CRASH'}")
    details_parts.append(f"Fixed binary: {'CRASHED' if fixed_crashed else 'NO CRASH'}")
    
    if crash_location:
        details_parts.append(f"Crash location: {crash_location}")
    
    if patched_functions:
        details_parts.append(f"Patched functions: {', '.join(patched_functions[:3])}")
        if len(patched_functions) > 3:
            details_parts.append(f"  (and {len(patched_functions) - 3} more)")
    
    if patch_effective:
        details_parts.append("✓ Patch is EFFECTIVE - vulnerability fixed")
    else:
        if not vuln_crashed:
            details_parts.append("✗ PoC did not trigger on vulnerable binary")
        elif fixed_crashed:
            details_parts.append("✗ PoC still crashes on fixed binary - patch may be incomplete")
    
    return PatchVerificationReport(
        patch_effective=patch_effective,
        vulnerable_crashed=vuln_crashed,
        fixed_crashed=fixed_crashed,
        crash_in_patched_function=crash_in_patched,
        patched_functions=patched_functions,
        crash_location=crash_location,
        details="\n".join(details_parts)
    )


def _identify_patched_functions(
    vulnerable_binary: str,
    fixed_binary: str
) -> List[str]:
    """
    Identify functions that were modified between two binaries.
    
    Uses various strategies:
    1. Ghidra binary diff (if available)
    2. Simple size comparison
    3. Symbol table diff
    
    Args:
        vulnerable_binary: Path to pre-patch binary
        fixed_binary: Path to post-patch binary
        
    Returns:
        List of function names that were modified
    """
    patched_functions = []
    
    # Strategy 1: Try Ghidra comparison (if available)
    try:
        patched_functions = _ghidra_compare_binaries(vulnerable_binary, fixed_binary)
        if patched_functions:
            return patched_functions
    except Exception as e:
        logger.debug(f"Ghidra comparison failed: {e}")
    
    # Strategy 2: Symbol table comparison (simpler fallback)
    try:
        patched_functions = _compare_symbol_tables(vulnerable_binary, fixed_binary)
        if patched_functions:
            return patched_functions
    except Exception as e:
        logger.debug(f"Symbol table comparison failed: {e}")
    
    # Strategy 3: Heuristic based on file size
    try:
        vuln_size = os.path.getsize(vulnerable_binary)
        fixed_size = os.path.getsize(fixed_binary)
        size_diff = abs(fixed_size - vuln_size)
        
        if size_diff > 0:
            logger.info(f"Binary size difference: {size_diff} bytes")
            # Return a generic indicator
            return ["<modified_functions>"]
    except Exception as e:
        logger.debug(f"Size comparison failed: {e}")
    
    return []


def _ghidra_compare_binaries(
    binary1: str,
    binary2: str
) -> List[str]:
    """
    Use Ghidra to compare two binaries and identify changed functions.
    
    Note: This requires Ghidra to be installed and configured.
    Currently returns empty list as placeholder.
    
    Args:
        binary1: First binary path
        binary2: Second binary path
        
    Returns:
        List of changed function names
    """
    # Placeholder for Ghidra integration
    # Real implementation would:
    # 1. Check if Ghidra is available
    # 2. Run Ghidra headless analyzer on both binaries
    # 3. Use Ghidra's diff tool to compare
    # 4. Extract changed function names
    
    logger.debug("Ghidra binary comparison not yet implemented")
    return []


def _compare_symbol_tables(
    binary1: str,
    binary2: str
) -> List[str]:
    """
    Compare symbol tables of two binaries using nm or similar tools.
    
    Args:
        binary1: First binary path
        binary2: Second binary path
        
    Returns:
        List of functions with different sizes/addresses
    """
    changed_functions = []
    
    try:
        # Try using nm (Unix) or dumpbin (Windows)
        if os.name == 'nt':
            # Windows: use dumpbin if available
            return _compare_with_dumpbin(binary1, binary2)
        else:
            # Unix: use nm
            return _compare_with_nm(binary1, binary2)
    except Exception as e:
        logger.debug(f"Symbol table comparison error: {e}")
    
    return changed_functions


def _compare_with_nm(binary1: str, binary2: str) -> List[str]:
    """Compare using nm tool (Unix)."""
    try:
        # Get symbols from both binaries
        result1 = subprocess.run(
            ["nm", "-C", "-S", binary1],
            capture_output=True,
            text=True,
            timeout=30
        )
        result2 = subprocess.run(
            ["nm", "-C", "-S", binary2],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result1.returncode != 0 or result2.returncode != 0:
            return []
        
        # Parse symbols (simplified)
        symbols1 = set(result1.stdout.split('\n'))
        symbols2 = set(result2.stdout.split('\n'))
        
        # Find differences
        diff = symbols1.symmetric_difference(symbols2)
        
        # Extract function names
        changed = []
        for line in diff:
            parts = line.split()
            if len(parts) >= 3 and parts[1] in ['T', 't']:  # Text/code symbols
                changed.append(parts[-1])
        
        return changed[:20]  # Limit to 20
        
    except Exception as e:
        logger.debug(f"nm comparison failed: {e}")
        return []


def _compare_with_dumpbin(binary1: str, binary2: str) -> List[str]:
    """Compare using dumpbin tool (Windows)."""
    # Placeholder for Windows implementation
    logger.debug("dumpbin comparison not yet implemented")
    return []


def generate_patch_verification_report(
    report: PatchVerificationReport,
    output_format: str = "markdown"
) -> str:
    """
    Generate a formatted patch verification report.
    
    Args:
        report: PatchVerificationReport object
        output_format: "markdown" or "text"
        
    Returns:
        Formatted report string
    """
    if output_format == "markdown":
        return _generate_markdown_report(report)
    else:
        return _generate_text_report(report)


def _generate_markdown_report(report: PatchVerificationReport) -> str:
    """Generate Markdown formatted report."""
    lines = []
    lines.append("# Patch Verification Report\n")
    
    # Summary
    lines.append("## Summary\n")
    if report.patch_effective:
        lines.append("✅ **Patch is EFFECTIVE** - Vulnerability successfully fixed\n")
    else:
        lines.append("❌ **Patch verification FAILED**\n")
    
    # Test Results
    lines.append("## Test Results\n")
    lines.append("| Binary | Crashed | Status |")
    lines.append("|--------|---------|--------|")
    lines.append(f"| Vulnerable | {'Yes' if report.vulnerable_crashed else 'No'} | {'✓ Expected' if report.vulnerable_crashed else '✗ Unexpected'} |")
    lines.append(f"| Fixed | {'Yes' if report.fixed_crashed else 'No'} | {'✓ Expected' if not report.fixed_crashed else '✗ Unexpected'} |\n")
    
    # Crash Location
    if report.crash_location:
        lines.append("## Crash Location\n")
        lines.append(f"```\n{report.crash_location}\n```\n")
    
    # Patched Functions
    if report.patched_functions:
        lines.append("## Patched Functions\n")
        for func in report.patched_functions[:10]:
            lines.append(f"- `{func}`")
        if len(report.patched_functions) > 10:
            lines.append(f"\n*...and {len(report.patched_functions) - 10} more*\n")
    
    # Correlation
    if report.crash_in_patched_function:
        lines.append("\n## Correlation\n")
        lines.append("✅ Crash occurred in a patched function - Strong evidence of patch effectiveness\n")
    
    # Details
    lines.append("## Details\n")
    lines.append(f"```\n{report.details}\n```\n")
    
    return "\n".join(lines)


def _generate_text_report(report: PatchVerificationReport) -> str:
    """Generate plain text report."""
    return f"""
Patch Verification Report
{'='*70}

Summary: {'EFFECTIVE' if report.patch_effective else 'FAILED'}

Test Results:
  Vulnerable binary: {'CRASHED' if report.vulnerable_crashed else 'NO CRASH'}
  Fixed binary: {'CRASHED' if report.fixed_crashed else 'NO CRASH'}

{f'Crash Location: {report.crash_location}' if report.crash_location else ''}

{f'Patched Functions ({len(report.patched_functions)}):' if report.patched_functions else ''}
{chr(10).join(f'  - {func}' for func in report.patched_functions[:10])}

Details:
{report.details}
{'='*70}
"""

# ============================================================================
# CodeQL Analysis Tools
# ============================================================================

def codeql_create_database(source_path: str, database_path: str = None) -> bool:
    """Create a CodeQL database for the source code."""
    from ..services.codeql_service import CodeQLService
    service = CodeQLService(source_path, database_path)
    return service.create_database()

def codeql_run_custom_query(source_path: str, query: str, database_path: str = None) -> Any:
    """Run a custom CodeQL query."""
    from ..services.codeql_service import CodeQLService
    service = CodeQLService(source_path, database_path)
    return service.run_query(query)

def codeql_find_function_calls(source_path: str, function_name: str, database_path: str = None) -> Any:
    """Find all calls to a specific function using CodeQL."""
    from ..services.codeql_service import CodeQLService
    service = CodeQLService(source_path, database_path)
    return service.find_function_calls(function_name)

def codeql_find_callers(source_path: str, function_name: str, database_path: str = None) -> Any:
    """Find all callers of a specific function using CodeQL."""
    from ..services.codeql_service import CodeQLService
    service = CodeQLService(source_path, database_path)
    return service.find_callers(function_name)

def codeql_find_callees(source_path: str, function_name: str, database_path: str = None) -> Any:
    """Find all functions called by a specific function using CodeQL."""
    from ..services.codeql_service import CodeQLService
    service = CodeQLService(source_path, database_path)
    return service.find_callees(function_name)

def codeql_analyze_taint_flow(source_path: str, source_function: str, sink_pattern: str, database_path: str = None) -> Any:
    """Analyze taint flow via CodeQL."""
    from ..services.codeql_service import CodeQLService
    service = CodeQLService(source_path, database_path)
    return service.analyze_taint_flow(source_function, sink_pattern)

def codeql_find_memory_operations(source_path: str, file_pattern: str, database_path: str = None) -> Any:
    """Find memory operations using CodeQL."""
    from ..services.codeql_service import CodeQLService
    service = CodeQLService(source_path, database_path)
    return service.find_memory_operations(file_pattern)


# ============================================================================
# Ghidra Analysis Tools
# ============================================================================

def ghidra_analyze_binary(binary_path: str) -> bool:
    """Perform basic Ghidra analysis on a binary."""
    from ..services.ghidra_service import GhidraService
    service = GhidraService()
    return service.analyze_binary(binary_path)

def ghidra_decompile_function(binary_path: str, function_name: str) -> Any:
    """Decompile a function using Ghidra."""
    from ..services.ghidra_service import GhidraService
    service = GhidraService()
    return service.decompile_function(binary_path, function_name)

def ghidra_list_functions(binary_path: str) -> Any:
    """List all functions in a binary using Ghidra."""
    from ..services.ghidra_service import GhidraService
    service = GhidraService()
    return service.list_functions(binary_path)

def ghidra_compare_binaries(binary1_path: str, binary2_path: str) -> Any:
    """Compare two binaries using Ghidra binary diffing logic."""
    from ..services.ghidra_service import GhidraService
    service = GhidraService()
    return service.compare_binaries(binary1_path, binary2_path)


# ============================================================================
# Utility & Status
# ============================================================================

def check_analysis_tools_status() -> Dict[str, bool]:
    """Check availability of CodeQL and Ghidra."""
    try:
        from ..services.codeql_service import CodeQLService
        from ..services.ghidra_service import GhidraService
        
        codeql = CodeQLService("")
        ghidra = GhidraService()
        
        return {
            "codeql": codeql.is_available(),
            "ghidra": ghidra.is_available()
        }
    except Exception:
        return {"codeql": False, "ghidra": False}

# Tool collections
CODEQL_TOOLS = [
    codeql_find_function_calls,
    codeql_find_callers,
    codeql_find_callees,
    codeql_analyze_taint_flow,
    codeql_find_memory_operations,
    codeql_run_custom_query,
    codeql_create_database,
]

GHIDRA_TOOLS = [
    ghidra_decompile_function,
    ghidra_list_functions,
    ghidra_compare_binaries,
    ghidra_analyze_binary,
]

STATIC_ANALYSIS_TOOLS = CODEQL_TOOLS + GHIDRA_TOOLS
