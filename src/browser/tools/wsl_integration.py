"""
WSL Integration Module

Provides utilities for running Linux tools (especially ASAN binaries) 
through WSL on Windows, with automatic path conversion.
"""

import os
import subprocess
import logging
from typing import Optional, Dict, Any, List
from pathlib import Path, PureWindowsPath, PurePosixPath

logger = logging.getLogger(__name__)


class WSLIntegration:
    """
    Integration layer for Windows Subsystem for Linux.
    
    Features:
    - Detect WSL availability
    - Convert Windows paths to WSL paths
    - Run Linux binaries through wsl.exe
    - Execute ASAN tools in WSL environment
    """
    
    def __init__(self):
        """Initialize WSL integration."""
        self.wsl_available = self._check_wsl_available()
        self.default_distro = self._get_default_distro()
    
    def _check_wsl_available(self) -> bool:
        """Check if WSL is available on the system."""
        try:
            result = subprocess.run(
                ["wsl.exe", "--status"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _get_default_distro(self) -> Optional[str]:
        """Get the default WSL distribution name."""
        if not self.wsl_available:
            return None
        
        try:
            result = subprocess.run(
                ["wsl.exe", "--list", "--quiet"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout:
                # First line is usually the default
                lines = result.stdout.strip().split('\n')
                if lines:
                    # Remove BOM and whitespace
                    distro = lines[0].strip().replace('\x00', '')
                    return distro
        except Exception as e:
            logger.debug(f"Failed to get default distro: {e}")
        
        return None
    
    def windows_to_wsl_path(self, windows_path: str) -> str:
        """
        Convert Windows path to WSL path.
        
        Examples:
            C:\\Users\\Admin\\file.txt -> /mnt/c/Users/Admin/file.txt
            D:\\code\\test.js -> /mnt/d/code/test.js
        
        Args:
            windows_path: Windows-style path
            
        Returns:
            WSL-style path
        """
        # Normalize the path
        win_path = Path(windows_path).resolve()
        
        # Get drive letter and path
        parts = win_path.parts
        if len(parts) == 0:
            return ""
        
        # Extract drive letter (e.g., 'C:')
        drive = parts[0].rstrip(':').lower()
        
        # Build WSL path
        if len(parts) > 1:
            # Join remaining parts with forward slashes
            rest = '/'.join(parts[1:])
            wsl_path = f"/mnt/{drive}/{rest}"
        else:
            wsl_path = f"/mnt/{drive}"
        
        return wsl_path
    
    def wsl_to_windows_path(self, wsl_path: str) -> str:
        """
        Convert WSL path to Windows path.
        
        Examples:
            /mnt/c/Users/Admin/file.txt -> C:\\Users\\Admin\\file.txt
            /mnt/d/code/test.js -> D:\\code\\test.js
        
        Args:
            wsl_path: WSL-style path
            
        Returns:
            Windows-style path
        """
        if not wsl_path.startswith('/mnt/'):
            # Not a mounted Windows path
            return wsl_path
        
        # Remove /mnt/ prefix
        path_parts = wsl_path[5:].split('/')
        
        if len(path_parts) == 0:
            return ""
        
        # First part is drive letter
        drive = path_parts[0].upper()
        
        # Build Windows path
        if len(path_parts) > 1:
            rest = '\\'.join(path_parts[1:])
            windows_path = f"{drive}:\\{rest}"
        else:
            windows_path = f"{drive}:\\"
        
        return windows_path
    
    def run_command(
        self,
        command: List[str],
        cwd: Optional[str] = None,
        timeout: int = 30,
        distro: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run a command in WSL.
        
        Args:
            command: Command and arguments to run
            cwd: Working directory (Windows or WSL path)
            timeout: Timeout in seconds
            distro: WSL distribution name (uses default if not specified)
            
        Returns:
            Dictionary with returncode, stdout, stderr
        """
        if not self.wsl_available:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": "WSL not available",
                "success": False
            }
        
        # Build wsl.exe command
        wsl_cmd = ["wsl.exe"]
        
        # Add distribution if specified
        if distro:
            wsl_cmd.extend(["-d", distro])
        
        # Convert cwd to WSL path if needed
        if cwd:
            wsl_cwd = self.windows_to_wsl_path(cwd) if ':\\' in cwd else cwd
            wsl_cmd.extend(["--cd", wsl_cwd])
        
        # Add the actual command
        wsl_cmd.extend(command)
        
        logger.debug(f"Running WSL command: {' '.join(wsl_cmd)}")
        
        try:
            result = subprocess.run(
                wsl_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout}s",
                "success": False
            }
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }
    
    def run_linux_binary(
        self,
        binary_path: str,
        args: List[str] = None,
        timeout: int = 30,
        env: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Run a Linux binary through WSL.
        
        Args:
            binary_path: Path to Linux binary (Windows or WSL path)
            args: Arguments to pass to the binary
            timeout: Timeout in seconds
            env: Environment variables to set
            
        Returns:
            Dictionary with execution results
        """
        # Convert binary path to WSL if needed
        if ':\\' in binary_path:
            wsl_binary = self.windows_to_wsl_path(binary_path)
        else:
            wsl_binary = binary_path
        
        # Build command
        command = [wsl_binary]
        if args:
            command.extend(args)
        
        # Add environment variables if specified
        if env:
            env_cmd = []
            for key, value in env.items():
                env_cmd.append(f"{key}={value}")
            command = env_cmd + command
        
        return self.run_command(command, timeout=timeout)
    
    def run_asan_binary(
        self,
        binary_path: str,
        poc_code: str,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Run an ASAN-enabled Linux binary with PoC code.
        
        Args:
            binary_path: Path to ASAN binary
            poc_code: PoC code to execute
            timeout: Timeout in seconds
            
        Returns:
            Dictionary with crash info
        """
        import tempfile
        
        # Create temp file for PoC
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.js',
            delete=False
        ) as f:
            f.write(poc_code)
            temp_file = f.name
        
        try:
            # Convert to WSL path
            wsl_poc = self.windows_to_wsl_path(temp_file)
            
            # Run with ASAN options
            env = {
                "ASAN_OPTIONS": "detect_leaks=0:allocator_may_return_null=1"
            }
            
            result = self.run_linux_binary(
                binary_path,
                args=[wsl_poc],
                timeout=timeout,
                env=env
            )
            
            # Parse ASAN output
            crashed = "ASAN" in result["stderr"] or result["returncode"] != 0
            
            return {
                **result,
                "crashed": crashed,
                "asan_output": result["stderr"]
            }
        finally:
            # Cleanup temp file
            if os.path.exists(temp_file):
                os.remove(temp_file)
    
    def check_tool_available(self, tool_name: str) -> bool:
        """
        Check if a Linux tool is available in WSL.
        
        Args:
            tool_name: Name of the tool (e.g., "llvm-symbolizer")
            
        Returns:
            True if tool is available
        """
        result = self.run_command(["which", tool_name], timeout=5)
        return result["success"] and result["stdout"].strip() != ""
    
    def install_tool(self, package_name: str) -> bool:
        """
        Install a package in WSL using apt.
        
        Args:
            package_name: Package name to install
            
        Returns:
            True if installation succeeded
        """
        logger.info(f"Installing {package_name} in WSL...")
        
        # Update package list
        update_result = self.run_command(
            ["sudo", "apt-get", "update"],
            timeout=60
        )
        
        if not update_result["success"]:
            logger.error("Failed to update package list")
            return False
        
        # Install package
        install_result = self.run_command(
            ["sudo", "apt-get", "install", "-y", package_name],
            timeout=120
        )
        
        return install_result["success"]
    
    def get_wsl_info(self) -> Dict[str, Any]:
        """
        Get information about WSL installation.
        
        Returns:
            Dictionary with WSL info
        """
        info = {
            "available": self.wsl_available,
            "default_distro": self.default_distro,
            "distros": []
        }
        
        if not self.wsl_available:
            return info
        
        # Get list of distributions
        try:
            result = subprocess.run(
                ["wsl.exe", "--list", "--verbose"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    # Parse distro info
                    parts = line.strip().split()
                    if parts:
                        distro_name = parts[0].replace('*', '').strip()
                        info["distros"].append(distro_name)
        except Exception as e:
            logger.debug(f"Failed to get distro list: {e}")
        
        return info


def demo_wsl_integration():
    """Demo of WSL integration functionality."""
    print("WSL Integration Demo")
    print("=" * 80)
    
    wsl = WSLIntegration()
    
    # Check availability
    print(f"\nWSL Available: {wsl.wsl_available}")
    if wsl.default_distro:
        print(f"Default Distro: {wsl.default_distro}")
    
    if not wsl.wsl_available:
        print("\nWSL is not available on this system")
        return
    
    # Get WSL info
    info = wsl.get_wsl_info()
    print(f"\nInstalled Distributions:")
    for distro in info["distros"]:
        print(f"  - {distro}")
    
    # Path conversion demo
    print(f"\nPath Conversion:")
    win_path = r"C:\Users\Admin\test.js"
    wsl_path = wsl.windows_to_wsl_path(win_path)
    print(f"  Windows: {win_path}")
    print(f"  WSL: {wsl_path}")
    
    back_to_win = wsl.wsl_to_windows_path(wsl_path)
    print(f"  Back to Windows: {back_to_win}")
    
    # Run simple command
    print(f"\nRunning 'uname -a' in WSL:")
    result = wsl.run_command(["uname", "-a"])
    if result["success"]:
        print(f"  {result['stdout'].strip()}")
    
    # Check for tools
    print(f"\nChecking for tools:")
    for tool in ["llvm-symbolizer", "gdb", "python3"]:
        available = wsl.check_tool_available(tool)
        status = "✓" if available else "✗"
        print(f"  {status} {tool}")


if __name__ == "__main__":
    demo_wsl_integration()
