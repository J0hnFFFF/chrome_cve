"""
Ghidra Analysis Service

Provides binary analysis capabilities:
- Decompilation
- Function analysis
- Cross-references
- Binary diffing

Requires: Ghidra installed (https://ghidra-sre.org/)
"""

import os
import json
import subprocess
import tempfile
from typing import Optional, List, Dict, Any
from dataclasses import dataclass


@dataclass
class GhidraFunction:
    """Represents a function in the binary."""
    name: str
    address: str
    size: int
    decompiled: str = ""
    calls: List[str] = None
    called_by: List[str] = None


@dataclass
class GhidraAnalysisResult:
    """Result from Ghidra analysis."""
    success: bool
    functions: List[GhidraFunction] = None
    error: Optional[str] = None
    raw_output: str = ""


class GhidraService:
    """
    Ghidra headless analysis service.

    Usage:
        service = GhidraService()
        result = service.decompile_function("/path/to/binary", "vulnerable_func")
    """

    # Ghidra script for decompilation
    DECOMPILE_SCRIPT = '''
// Decompile specified functions
// @category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;

public class DecompileScript extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String targetFunc = System.getProperty("TARGET_FUNCTION", "");
        String outputPath = System.getProperty("OUTPUT_PATH", "/tmp/decompiled.txt");

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FileWriter writer = new FileWriter(outputPath);

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            if (targetFunc.isEmpty() || func.getName().contains(targetFunc)) {
                DecompileResults results = decomp.decompileFunction(func, 60, monitor);
                if (results.decompileCompleted()) {
                    writer.write("=== " + func.getName() + " @ " + func.getEntryPoint() + " ===\\n");
                    writer.write(results.getDecompiledFunction().getC());
                    writer.write("\\n\\n");
                }
            }
        }

        writer.close();
        decomp.dispose();
    }
}
'''

    # Script for function listing
    LIST_FUNCTIONS_SCRIPT = '''
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;
import com.google.gson.Gson;
import java.util.*;

public class ListFunctions extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String outputPath = System.getProperty("OUTPUT_PATH", "/tmp/functions.json");

        List<Map<String, Object>> functions = new ArrayList<>();

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            Map<String, Object> funcInfo = new HashMap<>();
            funcInfo.put("name", func.getName());
            funcInfo.put("address", func.getEntryPoint().toString());
            funcInfo.put("size", func.getBody().getNumAddresses());
            functions.add(funcInfo);
        }

        FileWriter writer = new FileWriter(outputPath);
        writer.write(new Gson().toJson(functions));
        writer.close();
    }
}
'''

    def __init__(self, ghidra_path: str = None):
        """
        Initialize Ghidra service.

        :param ghidra_path: Path to Ghidra installation
        """
        self.ghidra_path = ghidra_path or self._find_ghidra()
        self.project_path = os.path.join(tempfile.gettempdir(), "ghidra_projects")
        os.makedirs(self.project_path, exist_ok=True)

    def _find_ghidra(self) -> Optional[str]:
        """Find Ghidra installation."""
        locations = [
            os.environ.get("GHIDRA_HOME", ""),
            os.path.expanduser("~/ghidra"),
            "/opt/ghidra",
            "/usr/local/ghidra",
        ]

        for loc in locations:
            if loc and os.path.exists(loc):
                headless = os.path.join(loc, "support", "analyzeHeadless")
                if os.path.exists(headless):
                    return loc

        return None

    def is_available(self) -> bool:
        """Check if Ghidra is available."""
        return self.ghidra_path is not None

    def _get_headless_path(self) -> str:
        """Get path to analyzeHeadless script."""
        return os.path.join(self.ghidra_path, "support", "analyzeHeadless")

    def analyze_binary(
        self,
        binary_path: str,
        project_name: str = "analysis"
    ) -> bool:
        """
        Import and analyze a binary.

        :param binary_path: Path to binary file
        :param project_name: Name for Ghidra project
        :return: Success status
        """
        if not self.is_available():
            return False

        cmd = [
            self._get_headless_path(),
            self.project_path,
            project_name,
            "-import", binary_path,
            "-overwrite",
            "-analysisTimeoutPerFile", "600"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900
            )
            return result.returncode == 0
        except Exception as e:
            print(f"Analysis failed: {e}")
            return False

    def decompile_function(
        self,
        binary_path: str,
        function_name: str = "",
        project_name: str = "analysis"
    ) -> GhidraAnalysisResult:
        """
        Decompile a function (or all functions if name is empty).

        :param binary_path: Path to binary
        :param function_name: Function to decompile (empty for all)
        :param project_name: Project name
        :return: Decompilation result
        """
        if not self.is_available():
            return GhidraAnalysisResult(
                success=False,
                error="Ghidra not available"
            )

        # Create script file
        script_path = os.path.join(tempfile.gettempdir(), "decompile.java")
        with open(script_path, 'w') as f:
            f.write(self.DECOMPILE_SCRIPT)

        output_path = os.path.join(tempfile.gettempdir(), "decompiled.txt")

        cmd = [
            self._get_headless_path(),
            self.project_path,
            project_name,
            "-import", binary_path,
            "-overwrite",
            "-postScript", script_path,
            "-scriptPath", tempfile.gettempdir(),
            f"-DTARGET_FUNCTION={function_name}",
            f"-DOUTPUT_PATH={output_path}"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    decompiled = f.read()

                # Parse decompiled output into functions
                functions = self._parse_decompiled_output(decompiled)

                return GhidraAnalysisResult(
                    success=True,
                    functions=functions,
                    raw_output=decompiled
                )
            else:
                return GhidraAnalysisResult(
                    success=False,
                    error="No output generated",
                    raw_output=result.stderr
                )

        except subprocess.TimeoutExpired:
            return GhidraAnalysisResult(
                success=False,
                error="Decompilation timed out"
            )
        except Exception as e:
            return GhidraAnalysisResult(
                success=False,
                error=str(e)
            )
        finally:
            for f in [script_path, output_path]:
                if os.path.exists(f):
                    os.remove(f)

    def _parse_decompiled_output(self, output: str) -> List[GhidraFunction]:
        """Parse decompiled output into function objects."""
        functions = []
        current_func = None
        current_code = []

        for line in output.split('\n'):
            if line.startswith('=== ') and ' @ ' in line:
                # Save previous function
                if current_func:
                    current_func.decompiled = '\n'.join(current_code)
                    functions.append(current_func)

                # Parse new function header
                # Format: === func_name @ address ===
                parts = line.strip('= ').split(' @ ')
                if len(parts) >= 2:
                    name = parts[0]
                    addr = parts[1].rstrip(' =')
                    current_func = GhidraFunction(
                        name=name,
                        address=addr,
                        size=0
                    )
                    current_code = []
            elif current_func:
                current_code.append(line)

        # Save last function
        if current_func:
            current_func.decompiled = '\n'.join(current_code)
            functions.append(current_func)

        return functions

    def list_functions(
        self,
        binary_path: str,
        project_name: str = "analysis"
    ) -> GhidraAnalysisResult:
        """
        List all functions in a binary.

        :param binary_path: Path to binary
        :param project_name: Project name
        :return: List of functions
        """
        if not self.is_available():
            return GhidraAnalysisResult(
                success=False,
                error="Ghidra not available"
            )

        # For now, use a simpler approach with objdump if available
        try:
            result = subprocess.run(
                ["objdump", "-t", binary_path],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                functions = []
                for line in result.stdout.split('\n'):
                    if ' F ' in line or ' f ' in line:  # Function symbol
                        parts = line.split()
                        if len(parts) >= 6:
                            functions.append(GhidraFunction(
                                name=parts[-1],
                                address=parts[0],
                                size=int(parts[4], 16) if len(parts) > 4 else 0
                            ))

                return GhidraAnalysisResult(
                    success=True,
                    functions=functions
                )

        except Exception as e:
            pass

        return GhidraAnalysisResult(
            success=False,
            error="Could not list functions"
        )

    def compare_binaries(
        self,
        binary1_path: str,
        binary2_path: str
    ) -> Dict[str, Any]:
        """
        Compare two binaries to find differences.

        :param binary1_path: Path to first binary (vulnerable)
        :param binary2_path: Path to second binary (patched)
        :return: Comparison results
        """
        result = {
            "added_functions": [],
            "removed_functions": [],
            "modified_functions": [],
            "success": False
        }

        # Get functions from both binaries
        funcs1 = self.list_functions(binary1_path)
        funcs2 = self.list_functions(binary2_path)

        if not funcs1.success or not funcs2.success:
            result["error"] = "Could not analyze binaries"
            return result

        names1 = {f.name for f in funcs1.functions}
        names2 = {f.name for f in funcs2.functions}

        result["added_functions"] = list(names2 - names1)
        result["removed_functions"] = list(names1 - names2)

        # For common functions, compare sizes (rough modification detection)
        sizes1 = {f.name: f.size for f in funcs1.functions}
        sizes2 = {f.name: f.size for f in funcs2.functions}

        for name in names1 & names2:
            if sizes1.get(name, 0) != sizes2.get(name, 0):
                result["modified_functions"].append(name)

        result["success"] = True
        return result


# Convenience function
def create_ghidra_service() -> Optional[GhidraService]:
    """Create Ghidra service if available."""
    service = GhidraService()
    if service.is_available():
        return service
    return None
