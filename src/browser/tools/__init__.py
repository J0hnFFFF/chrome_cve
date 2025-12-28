# Browser CVE Tools

from .chromium_tools import (
    fetch_chromium_commit,
    fetch_chromium_file,
    search_chromium_code,
    fetch_chromium_bug,
    get_commit_info,
    list_commit_files,
    analyze_patch_components,
)

from .chrome_tools import (
    list_chrome_versions,
    download_chrome_version,
    find_chrome_executable,
    run_chrome_with_poc,
    create_poc_file,
    test_poc_reproducibility,
    analyze_crash_log,
)

from .common_tools import (
    read_file,
    write_file,
    list_directory,
    run_command,
)
# Tools - Utilities and Helpers (NOT plugins)
# Plugin-specific helpers have been moved to plugins/*/helpers/

from .environment_manager import (  # Phase 0.2
    EnvironmentManager,
    VerificationEnv,
)

from .regression_test_analyzer import (  # Phase 0.3 + 2.3
    RegressionTestAnalyzer,
    TestCase,
    TestAnalysis,
)

from .code_context_fetcher import (  # Phase 2.2
    CodeContextFetcher,
    FunctionContext,
)

# Execution tools
from .execution import (
    ExecutionResult,
    D8Executor,
    ChromeExecutor,
    MultiVersionTester,
)

from .debug import (
    ASANError,
    StackFrame,
    CrashReport,
    ASANParser,
    StackTraceParser,
    CrashAnalyzer,
)

from .analysis_tools import (
    # CodeQL tools
    codeql_find_function_calls,
    codeql_find_callers,
    codeql_find_callees,
    codeql_analyze_taint_flow,
    codeql_find_memory_operations,
    codeql_run_custom_query,
    codeql_create_database,
    # Ghidra tools
    ghidra_decompile_function,
    ghidra_list_functions,
    ghidra_compare_binaries,
    ghidra_analyze_binary,
    # Utility
    check_analysis_tools_status,
    # Tool collections
    CODEQL_TOOLS,
    GHIDRA_TOOLS,
    STATIC_ANALYSIS_TOOLS,
)

# Tool collections for different agents
INFO_TOOLS = [
    fetch_chromium_commit,
    fetch_chromium_file,
    fetch_chromium_bug,
    get_commit_info,
    list_commit_files,
]

ANALYSIS_TOOLS = [
    fetch_chromium_commit,
    fetch_chromium_file,
    search_chromium_code,
    analyze_patch_components,
    read_file,
    # Static analysis
    codeql_find_function_calls,
    codeql_find_callers,
    codeql_find_callees,
    codeql_analyze_taint_flow,
    check_analysis_tools_status,
]

BINARY_ANALYSIS_TOOLS = [
    ghidra_decompile_function,
    ghidra_list_functions,
    ghidra_compare_binaries,
    ghidra_analyze_binary,
]

POC_TOOLS = [
    create_poc_file,
    write_file,
    read_file,
    run_command,
]

EXECUTION_TOOLS = [
    list_chrome_versions,
    download_chrome_version,
    find_chrome_executable,
    run_chrome_with_poc,
    test_poc_reproducibility,
    analyze_crash_log,
]

# Executor classes for programmatic use
EXECUTOR_CLASSES = [
    D8Executor,
    ChromeExecutor,
    MultiVersionTester,
]

# Debug/analysis classes
DEBUG_CLASSES = [
    ASANParser,
    StackTraceParser,
    CrashAnalyzer,
]

ALL_TOOLS = (
    INFO_TOOLS +
    ANALYSIS_TOOLS +
    BINARY_ANALYSIS_TOOLS +
    POC_TOOLS +
    EXECUTION_TOOLS
)

__all__ = [
    # Environment (Phase 0.2)
    "EnvironmentManager",
    "VerificationEnv",
    # Regression Test Analysis (Phase 0.3 + 2.3)
    "RegressionTestAnalyzer",
    "TestCase",
    "TestAnalysis",
    # Code Context (Phase 2.2)
    "CodeContextFetcher",
    "FunctionContext",
    # Execution
    "ExecutionResult",
    "D8Executor",
    "ChromeExecutor",
]
