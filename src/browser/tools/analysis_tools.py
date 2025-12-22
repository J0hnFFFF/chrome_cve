"""
Analysis Tools

Tool wrappers for CodeQL and Ghidra analysis services.
These tools provide static and binary analysis capabilities for agents.
"""

import os
import json
from langchain_core import tools

from ..services.codeql_service import CodeQLService, create_codeql_service
from ..services.ghidra_service import GhidraService, create_ghidra_service


# Global service instances (lazy initialization)
_codeql_service = None
_ghidra_service = None


def get_codeql_service(source_path: str = None) -> CodeQLService:
    """Get or create CodeQL service instance."""
    global _codeql_service
    if _codeql_service is None and source_path:
        _codeql_service = CodeQLService(source_path)
    return _codeql_service


def get_ghidra_service() -> GhidraService:
    """Get or create Ghidra service instance."""
    global _ghidra_service
    if _ghidra_service is None:
        _ghidra_service = GhidraService()
    return _ghidra_service


# ============================================================================
# CodeQL Tools
# ============================================================================

@tools.tool
def codeql_find_function_calls(function_name: str, source_path: str = None) -> str:
    """
    Find all calls to a specific function using CodeQL.

    Args:
        function_name: Name of the function to search for
        source_path: Path to source code (uses cached if not provided)

    Returns:
        JSON string with call locations and file paths
    """
    service = get_codeql_service(source_path)
    if not service or not service.is_available():
        return json.dumps({
            "error": "CodeQL not available. Please install CodeQL CLI.",
            "success": False
        })

    result = service.find_function_calls(function_name)
    return json.dumps({
        "success": result.success,
        "query": result.query_name,
        "results": result.results,
        "error": result.error
    }, indent=2)


@tools.tool
def codeql_find_callers(function_name: str, source_path: str = None) -> str:
    """
    Find all functions that call a specific function using CodeQL.

    Args:
        function_name: Name of the target function
        source_path: Path to source code

    Returns:
        JSON string with caller functions and locations
    """
    service = get_codeql_service(source_path)
    if not service or not service.is_available():
        return json.dumps({
            "error": "CodeQL not available",
            "success": False
        })

    result = service.find_callers(function_name)
    return json.dumps({
        "success": result.success,
        "query": result.query_name,
        "results": result.results,
        "error": result.error
    }, indent=2)


@tools.tool
def codeql_find_callees(function_name: str, source_path: str = None) -> str:
    """
    Find all functions called by a specific function using CodeQL.

    Args:
        function_name: Name of the caller function
        source_path: Path to source code

    Returns:
        JSON string with callee functions and locations
    """
    service = get_codeql_service(source_path)
    if not service or not service.is_available():
        return json.dumps({
            "error": "CodeQL not available",
            "success": False
        })

    result = service.find_callees(function_name)
    return json.dumps({
        "success": result.success,
        "query": result.query_name,
        "results": result.results,
        "error": result.error
    }, indent=2)


@tools.tool
def codeql_analyze_taint_flow(
    source_function: str,
    sink_pattern: str,
    source_path: str = None
) -> str:
    """
    Analyze taint flow from function parameters to potential sinks.

    This is useful for tracking how user-controlled data flows through the code
    and identifying potential security issues.

    Args:
        source_function: Function whose parameters are taint sources
        sink_pattern: Pattern to match sink functions (e.g., "memcpy", "strcpy")
        source_path: Path to source code

    Returns:
        JSON string with taint flow paths
    """
    service = get_codeql_service(source_path)
    if not service or not service.is_available():
        return json.dumps({
            "error": "CodeQL not available",
            "success": False
        })

    result = service.analyze_taint_flow(source_function, sink_pattern)
    return json.dumps({
        "success": result.success,
        "query": result.query_name,
        "results": result.results,
        "error": result.error
    }, indent=2)


@tools.tool
def codeql_find_memory_operations(file_pattern: str, source_path: str = None) -> str:
    """
    Find memory allocation/deallocation operations in files matching a pattern.

    Useful for analyzing memory management in vulnerability-related code.

    Args:
        file_pattern: Glob pattern for files (e.g., "v8/src/*.cc")
        source_path: Path to source code

    Returns:
        JSON string with memory operations and locations
    """
    service = get_codeql_service(source_path)
    if not service or not service.is_available():
        return json.dumps({
            "error": "CodeQL not available",
            "success": False
        })

    result = service.find_memory_operations(file_pattern)
    return json.dumps({
        "success": result.success,
        "query": result.query_name,
        "results": result.results,
        "error": result.error
    }, indent=2)


@tools.tool
def codeql_run_custom_query(query: str, source_path: str = None) -> str:
    """
    Run a custom CodeQL query.

    Args:
        query: CodeQL query string (must be valid CodeQL)
        source_path: Path to source code

    Returns:
        JSON string with query results
    """
    service = get_codeql_service(source_path)
    if not service or not service.is_available():
        return json.dumps({
            "error": "CodeQL not available",
            "success": False
        })

    result = service.run_query(query)
    return json.dumps({
        "success": result.success,
        "query": result.query_name,
        "results": result.results,
        "error": result.error
    }, indent=2)


@tools.tool
def codeql_create_database(source_path: str, language: str = "cpp") -> str:
    """
    Create a CodeQL database from source code.

    This must be done before running queries. Can take a long time for large codebases.

    Args:
        source_path: Path to source code root
        language: Programming language (cpp, javascript, python, etc.)

    Returns:
        Status message
    """
    global _codeql_service
    _codeql_service = CodeQLService(source_path)

    if not _codeql_service.is_available():
        return "Error: CodeQL CLI not found. Please install from https://github.com/github/codeql-cli-binaries"

    success = _codeql_service.create_database(language)
    if success:
        return f"Successfully created CodeQL database for {source_path}"
    else:
        return "Failed to create CodeQL database. Check source path and build configuration."


# ============================================================================
# Ghidra Tools
# ============================================================================

@tools.tool
def ghidra_decompile_function(
    binary_path: str,
    function_name: str = ""
) -> str:
    """
    Decompile a function from a binary using Ghidra.

    Args:
        binary_path: Path to the binary file
        function_name: Function to decompile (empty for all functions)

    Returns:
        JSON string with decompiled C code
    """
    service = get_ghidra_service()
    if not service or not service.is_available():
        return json.dumps({
            "error": "Ghidra not available. Please install from https://ghidra-sre.org/",
            "success": False
        })

    result = service.decompile_function(binary_path, function_name)

    functions_data = []
    if result.functions:
        for func in result.functions:
            functions_data.append({
                "name": func.name,
                "address": func.address,
                "size": func.size,
                "decompiled": func.decompiled[:2000] if func.decompiled else ""  # Limit size
            })

    return json.dumps({
        "success": result.success,
        "functions": functions_data,
        "error": result.error
    }, indent=2)


@tools.tool
def ghidra_list_functions(binary_path: str) -> str:
    """
    List all functions in a binary.

    Args:
        binary_path: Path to the binary file

    Returns:
        JSON string with function names, addresses, and sizes
    """
    service = get_ghidra_service()
    if not service or not service.is_available():
        return json.dumps({
            "error": "Ghidra not available",
            "success": False
        })

    result = service.list_functions(binary_path)

    functions_data = []
    if result.functions:
        for func in result.functions:
            functions_data.append({
                "name": func.name,
                "address": func.address,
                "size": func.size
            })

    return json.dumps({
        "success": result.success,
        "function_count": len(functions_data),
        "functions": functions_data[:100],  # Limit to first 100
        "error": result.error
    }, indent=2)


@tools.tool
def ghidra_compare_binaries(
    binary1_path: str,
    binary2_path: str
) -> str:
    """
    Compare two binaries to find differences (e.g., vulnerable vs patched).

    This is useful for understanding what changed between versions and
    identifying the patched functions.

    Args:
        binary1_path: Path to first binary (e.g., vulnerable version)
        binary2_path: Path to second binary (e.g., patched version)

    Returns:
        JSON string with added, removed, and modified functions
    """
    service = get_ghidra_service()
    if not service or not service.is_available():
        return json.dumps({
            "error": "Ghidra not available",
            "success": False
        })

    result = service.compare_binaries(binary1_path, binary2_path)
    return json.dumps(result, indent=2)


@tools.tool
def ghidra_analyze_binary(
    binary_path: str,
    project_name: str = "analysis"
) -> str:
    """
    Import and analyze a binary with Ghidra.

    This performs initial analysis including function detection,
    cross-references, and type propagation.

    Args:
        binary_path: Path to the binary file
        project_name: Name for the Ghidra project

    Returns:
        Status message
    """
    service = get_ghidra_service()
    if not service or not service.is_available():
        return "Error: Ghidra not found. Please install from https://ghidra-sre.org/"

    success = service.analyze_binary(binary_path, project_name)
    if success:
        return f"Successfully analyzed binary: {binary_path}"
    else:
        return "Failed to analyze binary. Check file path and Ghidra installation."


# ============================================================================
# Utility Tools
# ============================================================================

@tools.tool
def check_analysis_tools_status() -> str:
    """
    Check availability of analysis tools (CodeQL, Ghidra).

    Returns:
        JSON string with tool availability status
    """
    codeql_available = False
    ghidra_available = False

    try:
        codeql_service = CodeQLService("/tmp")
        codeql_available = codeql_service.is_available()
    except:
        pass

    try:
        ghidra_service = GhidraService()
        ghidra_available = ghidra_service.is_available()
    except:
        pass

    return json.dumps({
        "codeql": {
            "available": codeql_available,
            "install_url": "https://github.com/github/codeql-cli-binaries"
        },
        "ghidra": {
            "available": ghidra_available,
            "install_url": "https://ghidra-sre.org/"
        }
    }, indent=2)


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

STATIC_ANALYSIS_TOOLS = CODEQL_TOOLS + GHIDRA_TOOLS + [check_analysis_tools_status]
