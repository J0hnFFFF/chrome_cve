"""
Visual Studio Environment Setup

Automatically configures Visual Studio environment variables for building
and debugging on Windows.
"""

import os
import subprocess
import logging
from typing import Dict, Optional, List
from pathlib import Path
import winreg

logger = logging.getLogger(__name__)


class VSEnvironment:
    """
    Visual Studio environment configuration.
    
    Features:
    - Auto-detect VS installation
    - Run vcvarsall.bat or VsDevCmd.bat
    - Extract and apply environment variables
    - Support multiple VS versions
    """
    
    def __init__(self):
        """Initialize VS environment manager."""
        self.vs_path = None
        self.vs_version = None
        self.env_vars = {}
    
    def detect_vs_installation(self) -> Optional[str]:
        """
        Detect Visual Studio installation path.
        
        Returns:
            Path to VS installation, or None
        """
        # Try registry keys for different VS versions
        vs_versions = [
            ("17.0", "2022"),
            ("16.0", "2019"),
            ("15.0", "2017"),
            ("14.0", "2015"),
        ]
        
        for version, year in vs_versions:
            try:
                # Try HKLM first
                key_path = f"SOFTWARE\\Microsoft\\VisualStudio\\{version}\\Setup\\VS"
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        key_path,
                        0,
                        winreg.KEY_READ | winreg.KEY_WOW64_32KEY
                    )
                    
                    vs_path, _ = winreg.QueryValueEx(key, "ProductDir")
                    winreg.CloseKey(key)
                    
                    if vs_path and os.path.exists(vs_path):
                        self.vs_path = vs_path
                        self.vs_version = year
                        logger.info(f"Found VS {year} at {vs_path}")
                        return vs_path
                except WindowsError:
                    pass
                
                # Try vswhere.exe (VS 2017+)
                vswhere_path = Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / \
                              "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
                
                if vswhere_path.exists():
                    result = subprocess.run(
                        [
                            str(vswhere_path),
                            "-latest",
                            "-property", "installationPath"
                        ],
                        capture_output=True,
                        text=True
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        vs_path = result.stdout.strip()
                        self.vs_path = vs_path
                        self.vs_version = year
                        logger.info(f"Found VS {year} at {vs_path} (via vswhere)")
                        return vs_path
                        
            except Exception as e:
                logger.debug(f"Failed to detect VS {year}: {e}")
                continue
        
        logger.warning("Could not detect Visual Studio installation")
        return None
    
    def find_vcvarsall(self) -> Optional[str]:
        """
        Find vcvarsall.bat script.
        
        Returns:
            Path to vcvarsall.bat, or None
        """
        if not self.vs_path:
            self.detect_vs_installation()
        
        if not self.vs_path:
            return None
        
        # Common locations
        possible_paths = [
            Path(self.vs_path) / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat",
            Path(self.vs_path) / "VC" / "vcvarsall.bat",
        ]
        
        for path in possible_paths:
            if path.exists():
                logger.info(f"Found vcvarsall.bat: {path}")
                return str(path)
        
        logger.warning("Could not find vcvarsall.bat")
        return None
    
    def setup_environment(
        self,
        arch: str = "x64",
        sdk_version: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Setup VS environment variables.
        
        Args:
            arch: Target architecture (x86, x64, arm, arm64)
            sdk_version: Optional Windows SDK version
            
        Returns:
            Dictionary of environment variables
        """
        vcvarsall = self.find_vcvarsall()
        
        if not vcvarsall:
            logger.error("Cannot setup environment: vcvarsall.bat not found")
            return {}
        
        # Build command
        cmd = f'"{vcvarsall}" {arch}'
        if sdk_version:
            cmd += f" {sdk_version}"
        
        # Run vcvarsall and capture environment
        logger.info(f"Running: {cmd}")
        
        try:
            # Use a batch script to capture environment
            batch_script = f'''
@echo off
call {cmd}
set
'''
            
            result = subprocess.run(
                ["cmd", "/c", batch_script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"vcvarsall failed: {result.stderr}")
                return {}
            
            # Parse environment variables
            env_vars = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key] = value
            
            # Store important variables
            important_vars = [
                'PATH', 'INCLUDE', 'LIB', 'LIBPATH',
                'WindowsSdkDir', 'WindowsSDKVersion',
                'VCToolsInstallDir', 'VCINSTALLDIR'
            ]
            
            self.env_vars = {
                k: v for k, v in env_vars.items()
                if k in important_vars
            }
            
            logger.info(f"Configured {len(self.env_vars)} environment variables")
            return self.env_vars
            
        except subprocess.TimeoutExpired:
            logger.error("vcvarsall timed out")
            return {}
        except Exception as e:
            logger.error(f"Failed to setup environment: {e}")
            return {}
    
    def apply_to_current_process(self) -> None:
        """Apply environment variables to current process."""
        if not self.env_vars:
            logger.warning("No environment variables to apply")
            return
        
        for key, value in self.env_vars.items():
            os.environ[key] = value
        
        logger.info("Applied VS environment to current process")
    
    def get_compiler_path(self) -> Optional[str]:
        """
        Get path to cl.exe compiler.
        
        Returns:
            Path to cl.exe, or None
        """
        if not self.env_vars:
            self.setup_environment()
        
        # Search in PATH
        path_dirs = self.env_vars.get('PATH', '').split(';')
        
        for dir_path in path_dirs:
            cl_path = Path(dir_path) / "cl.exe"
            if cl_path.exists():
                return str(cl_path)
        
        return None
    
    def get_sdk_version(self) -> Optional[str]:
        """
        Get Windows SDK version.
        
        Returns:
            SDK version string, or None
        """
        if not self.env_vars:
            self.setup_environment()
        
        return self.env_vars.get('WindowsSDKVersion')
    
    def print_environment(self) -> None:
        """Print VS environment information."""
        print(f"\nVisual Studio Environment")
        print("=" * 80)
        
        if self.vs_path:
            print(f"VS Path: {self.vs_path}")
            print(f"VS Version: {self.vs_version}")
        else:
            print("VS not detected")
        
        if self.env_vars:
            print(f"\nEnvironment Variables ({len(self.env_vars)}):")
            for key in ['PATH', 'INCLUDE', 'LIB', 'WindowsSDKVersion']:
                if key in self.env_vars:
                    value = self.env_vars[key]
                    if len(value) > 100:
                        value = value[:100] + "..."
                    print(f"  {key}: {value}")
        
        compiler = self.get_compiler_path()
        if compiler:
            print(f"\nCompiler: {compiler}")
        
        sdk = self.get_sdk_version()
        if sdk:
            print(f"SDK Version: {sdk}")


def setup_vs_environment(arch: str = "x64") -> Dict[str, str]:
    """
    Convenience function to setup VS environment.
    
    Args:
        arch: Target architecture
        
    Returns:
        Environment variables dictionary
    """
    vs_env = VSEnvironment()
    return vs_env.setup_environment(arch)


def demo_vs_environment():
    """Demo of VS environment setup."""
    print("Visual Studio Environment Setup Demo")
    print("=" * 80)
    
    vs_env = VSEnvironment()
    
    # Detect VS
    vs_path = vs_env.detect_vs_installation()
    
    if vs_path:
        print(f"\nDetected VS {vs_env.vs_version}")
        print(f"Path: {vs_path}")
        
        # Find vcvarsall
        vcvarsall = vs_env.find_vcvarsall()
        if vcvarsall:
            print(f"vcvarsall.bat: {vcvarsall}")
            
            # Setup environment
            print("\nSetting up x64 environment...")
            env_vars = vs_env.setup_environment("x64")
            
            if env_vars:
                print(f"✓ Configured {len(env_vars)} variables")
                
                # Show compiler
                compiler = vs_env.get_compiler_path()
                if compiler:
                    print(f"✓ Compiler: {compiler}")
                
                # Show SDK
                sdk = vs_env.get_sdk_version()
                if sdk:
                    print(f"✓ SDK: {sdk}")
            else:
                print("✗ Failed to setup environment")
        else:
            print("✗ vcvarsall.bat not found")
    else:
        print("\n✗ Visual Studio not detected")
        print("\nTo use this feature:")
        print("  1. Install Visual Studio (2015 or later)")
        print("  2. Include C++ build tools")


if __name__ == "__main__":
    demo_vs_environment()
