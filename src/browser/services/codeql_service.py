"""
CodeQL Analysis Service

Provides static code analysis capabilities:
- Dataflow analysis
- Taint tracking
- Call graph analysis
- Vulnerability pattern matching

Requires: CodeQL CLI installed (https://github.com/github/codeql-cli-binaries)
"""

import os
import json
import subprocess
import tempfile
from typing import Optional, List, Dict, Any
from dataclasses import dataclass


@dataclass
class CodeQLResult:
    """Result from a CodeQL query."""
    query_name: str
    results: List[Dict[str, Any]]
    success: bool
    error: Optional[str] = None


class CodeQLService:
    """
    CodeQL analysis service for Chromium source code.

    Usage:
        service = CodeQLService("/path/to/chromium/src")
        service.create_database()
        results = service.query("Find all calls to function X")
    """

    # Pre-built queries for common analysis tasks
    BUILTIN_QUERIES = {
        "find_function_calls": """
            import cpp
            from FunctionCall fc
            where fc.getTarget().getName() = "{function_name}"
            select fc, fc.getLocation().getFile().getRelativePath(), fc.getLocation().getStartLine()
        """,

        "find_function_definition": """
            import cpp
            from Function f
            where f.getName() = "{function_name}"
            select f, f.getLocation().getFile().getRelativePath(), f.getLocation().getStartLine()
        """,

        "find_callers": """
            import cpp
            from FunctionCall fc, Function caller
            where fc.getTarget().getName() = "{function_name}"
              and caller = fc.getEnclosingFunction()
            select caller.getName(), fc.getLocation().getFile().getRelativePath(), fc.getLocation().getStartLine()
        """,

        "find_callees": """
            import cpp
            from FunctionCall fc, Function f
            where f.getName() = "{function_name}"
              and fc.getEnclosingFunction() = f
            select fc.getTarget().getName(), fc.getLocation().getFile().getRelativePath(), fc.getLocation().getStartLine()
        """,

        "taint_from_parameter": """
            import cpp
            import semmle.code.cpp.dataflow.TaintTracking

            class TaintConfig extends TaintTracking::Configuration {{
                TaintConfig() {{ this = "TaintConfig" }}

                override predicate isSource(DataFlow::Node source) {{
                    exists(Parameter p |
                        p.getFunction().getName() = "{function_name}" and
                        source.asParameter() = p
                    )
                }}

                override predicate isSink(DataFlow::Node sink) {{
                    exists(FunctionCall fc |
                        fc.getTarget().getName().matches("%{sink_pattern}%") and
                        sink.asExpr() = fc.getAnArgument()
                    )
                }}
            }}

            from TaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
            where cfg.hasFlowPath(source, sink)
            select source, sink, sink.getNode().getLocation().getFile().getRelativePath()
        """,

        "type_hierarchy": """
            import cpp
            from Class c, Class base
            where c.getName() = "{class_name}"
              and c.getABaseClass+() = base
            select c.getName(), base.getName()
        """,

        "memory_operations": """
            import cpp
            from FunctionCall fc
            where fc.getTarget().getName().regexpMatch(".*alloc.*|.*free.*|.*delete.*|new")
              and fc.getLocation().getFile().getRelativePath().matches("%{file_pattern}%")
            select fc, fc.getTarget().getName(), fc.getLocation().getStartLine()
        """,
    }

    def __init__(self, source_path: str, database_path: str = None):
        """
        Initialize CodeQL service.

        :param source_path: Path to source code
        :param database_path: Path to store/load CodeQL database
        """
        self.source_path = source_path
        self.database_path = database_path or os.path.join(
            tempfile.gettempdir(), "codeql_db"
        )
        self.codeql_path = self._find_codeql()

    def _find_codeql(self) -> Optional[str]:
        """Find CodeQL CLI binary."""
        # Check common locations
        locations = [
            "codeql",  # In PATH
            os.path.expanduser("~/codeql/codeql"),
            "/opt/codeql/codeql",
            os.environ.get("CODEQL_PATH", ""),
        ]

        for loc in locations:
            if loc and os.path.exists(loc):
                return loc

        # Try which command
        try:
            result = subprocess.run(
                ["which", "codeql"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass

        return None

    def is_available(self) -> bool:
        """Check if CodeQL is available."""
        return self.codeql_path is not None

    def create_database(self, language: str = "cpp") -> bool:
        """
        Create CodeQL database from source.

        :param language: Source language (cpp, javascript, python, etc.)
        :return: Success status
        """
        if not self.is_available():
            print("CodeQL not available")
            return False

        cmd = [
            self.codeql_path,
            "database", "create",
            self.database_path,
            f"--language={language}",
            f"--source-root={self.source_path}",
            "--overwrite"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout for large codebases
            )
            return result.returncode == 0
        except Exception as e:
            print(f"Database creation failed: {e}")
            return False

    def run_query(self, query: str, output_format: str = "json") -> CodeQLResult:
        """
        Run a CodeQL query.

        :param query: CodeQL query string
        :param output_format: Output format (json, csv, sarif)
        :return: Query results
        """
        if not self.is_available():
            return CodeQLResult(
                query_name="custom",
                results=[],
                success=False,
                error="CodeQL not available"
            )

        # Write query to temp file
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.ql', delete=False
        ) as f:
            f.write(query)
            query_file = f.name

        output_file = tempfile.mktemp(suffix=f'.{output_format}')

        try:
            cmd = [
                self.codeql_path,
                "query", "run",
                f"--database={self.database_path}",
                f"--output={output_file}",
                query_file
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0:
                return CodeQLResult(
                    query_name="custom",
                    results=[],
                    success=False,
                    error=result.stderr
                )

            # Decode results
            if output_format == "json" and os.path.exists(output_file):
                # Need to decode bqrs to json
                json_output = output_file + ".json"
                decode_cmd = [
                    self.codeql_path,
                    "bqrs", "decode",
                    output_file,
                    f"--output={json_output}",
                    "--format=json"
                ]
                subprocess.run(decode_cmd, capture_output=True)

                if os.path.exists(json_output):
                    with open(json_output, 'r') as f:
                        data = json.load(f)
                    return CodeQLResult(
                        query_name="custom",
                        results=data.get('#select', {}).get('tuples', []),
                        success=True
                    )

            return CodeQLResult(
                query_name="custom",
                results=[],
                success=True
            )

        except subprocess.TimeoutExpired:
            return CodeQLResult(
                query_name="custom",
                results=[],
                success=False,
                error="Query timed out"
            )
        except Exception as e:
            return CodeQLResult(
                query_name="custom",
                results=[],
                success=False,
                error=str(e)
            )
        finally:
            # Cleanup temp files
            for f in [query_file, output_file]:
                if os.path.exists(f):
                    os.remove(f)

    def find_function_calls(self, function_name: str) -> CodeQLResult:
        """Find all calls to a specific function."""
        query = self.BUILTIN_QUERIES["find_function_calls"].format(
            function_name=function_name
        )
        result = self.run_query(query)
        result.query_name = f"find_function_calls({function_name})"
        return result

    def find_callers(self, function_name: str) -> CodeQLResult:
        """Find all functions that call a specific function."""
        query = self.BUILTIN_QUERIES["find_callers"].format(
            function_name=function_name
        )
        result = self.run_query(query)
        result.query_name = f"find_callers({function_name})"
        return result

    def find_callees(self, function_name: str) -> CodeQLResult:
        """Find all functions called by a specific function."""
        query = self.BUILTIN_QUERIES["find_callees"].format(
            function_name=function_name
        )
        result = self.run_query(query)
        result.query_name = f"find_callees({function_name})"
        return result

    def analyze_taint_flow(
        self,
        source_function: str,
        sink_pattern: str
    ) -> CodeQLResult:
        """
        Analyze taint flow from function parameters to sinks.

        :param source_function: Function whose parameters are taint sources
        :param sink_pattern: Pattern to match sink functions
        :return: Taint flow paths
        """
        query = self.BUILTIN_QUERIES["taint_from_parameter"].format(
            function_name=source_function,
            sink_pattern=sink_pattern
        )
        result = self.run_query(query)
        result.query_name = f"taint_flow({source_function} -> {sink_pattern})"
        return result

    def find_memory_operations(self, file_pattern: str) -> CodeQLResult:
        """Find memory allocation/deallocation in files matching pattern."""
        query = self.BUILTIN_QUERIES["memory_operations"].format(
            file_pattern=file_pattern
        )
        result = self.run_query(query)
        result.query_name = f"memory_operations({file_pattern})"
        return result


# Convenience function for tool integration
def create_codeql_service(source_path: str) -> Optional[CodeQLService]:
    """Create CodeQL service if available."""
    service = CodeQLService(source_path)
    if service.is_available():
        return service
    return None
