"""
Environment Manager

Automatically configures verification environment for PoC testing.
Handles d8 and Chrome binary detection, download, and compilation.
"""

import os
import platform
import subprocess
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
import winreg
import re

logger = logging.getLogger(__name__)


@dataclass
class VerificationEnv:
    """Verification environment configuration."""
    d8_path: Optional[str] = None
    chrome_path: Optional[str] = None
    asan_enabled: bool = False
    version: str = ""
    toolchain: Dict[str, Any] = field(default_factory=dict)
    d8_version: str = ""
    chrome_version: str = ""
    
    def is_valid(self) -> bool:
        """Check if environment has at least one valid binary."""
        return bool(self.d8_path or self.chrome_path)


class EnvironmentManager:
    """
    Manages verification environment setup.
    
    Features:
    - Auto-detect existing d8/Chrome installations
    - Download prebuilt binaries
    - Fallback to local compilation
    - Configure ASAN environment
    """
    
    # Common installation paths for Windows
    WINDOWS_D8_PATHS = [
        r"D:\src\v8\out\Debug\d8.exe",
        r"D:\src\v8\out\Release\d8.exe",
        r"C:\src\v8\out\Debug\d8.exe",
        r"C:\src\v8\out\Release\d8.exe",
        r".\volumes\v8\d8.exe",
        r".\d8.exe",
    ]
    
    WINDOWS_CHROME_PATHS = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r".\volumes\chrome\chrome.exe",
    ]
    
    # Registry keys for Chrome and VS
    REG_CHROME_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
    REG_VS_PATH = r"SOFTWARE\Microsoft\VisualStudio\SxS\VS7"
    REG_SDK_PATH = r"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v10.0"
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize environment manager.
        
        Args:
            config: Configuration dictionary with build settings
        """
        self.config = config or {}
        self.build_config = self.config.get("build", {})
        self.source_root = Path(self.build_config.get("source_root", "D:/src"))
        
    def setup_verification_env(
        self,
        component: str = "v8",
        version: str = "",
        prefer_asan: bool = True
    ) -> VerificationEnv:
        """
        Setup verification environment for a specific component.
        
        Args:
            component: Component to test (v8, chrome, etc.)
            version: Specific version to use (optional)
            prefer_asan: Prefer ASAN-enabled builds
            
        Returns:
            VerificationEnv with configured paths
        """
        logger.info(f"Setting up verification environment for {component}")
        
        env = VerificationEnv(version=version)
        
        if component.lower() in ["v8", "javascript", "jit"]:
            # Try to find d8
            env.d8_path = self._find_d8(prefer_asan)
            if env.d8_path:
                logger.info(f"✓ Found d8: {env.d8_path}")
                env.asan_enabled = self._check_asan_enabled(env.d8_path)
            else:
                logger.warning("✗ No d8 binary found")
                logger.info("  Suggestion: Build V8 or download prebuilt binary")
        
        if component.lower() in ["blink", "renderer", "chrome"]:
            # Try to find Chrome
            env.chrome_path = self._find_chrome()
            if env.chrome_path:
                logger.info(f"✓ Found Chrome: {env.chrome_path}")
                env.chrome_version = self.get_binary_version(env.chrome_path)
            else:
                logger.warning("✗ No Chrome binary found")
        
        # Detect toolchain
        env.toolchain = self.detect_toolchain()
        
        # Populate specific versions if available
        if env.d8_path and not env.d8_version:
            env.d8_version = self.get_binary_version(env.d8_path)
        
        # If nothing found, provide helpful message
        if not env.is_valid():
            logger.error("❌ No verification binaries found!")
            logger.info("\nTo fix this:")
            logger.info("1. Build V8 locally:")
            logger.info("   ./src/scripts/win_fetch_source.ps1 -Target v8")
            logger.info("   ./src/scripts/win_build.ps1 -SourcePath D:/src/v8")
            logger.info("\n2. Or specify paths in config.yaml:")
            logger.info("   execution:")
            logger.info("     d8_path: 'D:/path/to/d8.exe'")
            logger.info("     chrome_path: 'C:/path/to/chrome.exe'")
        
        return env
    
    def _find_d8(self, prefer_asan: bool = True) -> Optional[str]:
        """
        Find d8 binary in common locations.
        
        Args:
            prefer_asan: Prefer ASAN-enabled builds
            
        Returns:
            Path to d8.exe or None
        """
        # 1. Check config
        config_path = self.config.get("execution", {}).get("d8_path")
        if config_path and os.path.exists(config_path):
            return config_path
        
        # 2. Check common paths
        for path in self.WINDOWS_D8_PATHS:
            if os.path.exists(path):
                # If prefer ASAN, check if this is ASAN build
                if prefer_asan:
                    if self._check_asan_enabled(path):
                        return path
                else:
                    return path
        
        # 3. Check source_root
        v8_out = self.source_root / "v8" / "out"
        if v8_out.exists():
            # Try Debug first (more likely to have ASAN)
            for build_type in ["Debug", "Release"]:
                d8_path = v8_out / build_type / "d8.exe"
                if d8_path.exists():
                    if prefer_asan:
                        if self._check_asan_enabled(str(d8_path)):
                            return str(d8_path)
                    else:
                        return str(d8_path)
        
        return None
    
    def _find_chrome(self) -> Optional[str]:
        """
        Find Chrome binary in common locations and registry.
        
        Returns:
            Path to chrome.exe or None
        """
        # 1. Check config
        config_path = self.config.get("execution", {}).get("chrome_path")
        if config_path and os.path.exists(config_path):
            return config_path
        
        # 2. Check registry
        registry_path = self._query_registry(winreg.HKEY_LOCAL_MACHINE, self.REG_CHROME_PATH, "")
        if registry_path and os.path.exists(registry_path):
            return registry_path
            
        # 3. Check common paths
        for path in self.WINDOWS_CHROME_PATHS:
            if os.path.exists(path):
                return path
        
        return None

    def _query_registry(self, hkey, path: str, name: str) -> Optional[str]:
        """Query a registry value."""
        try:
            with winreg.OpenKey(hkey, path) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return str(value)
        except (OSError, ValueError):
            return None

    def detect_toolchain(self) -> Dict[str, Any]:
        """
        Detect Windows development toolchain (VS, SDK, depot_tools).
        
        Returns:
            Dictionary with toolchain info
        """
        info = {
            "vs_path": self._query_registry(winreg.HKEY_LOCAL_MACHINE, self.REG_VS_PATH, "15.0") or 
                       self._query_registry(winreg.HKEY_LOCAL_MACHINE, self.REG_VS_PATH, "16.0") or
                       self._query_registry(winreg.HKEY_LOCAL_MACHINE, self.REG_VS_PATH, "17.0"),
            "sdk_path": self._query_registry(winreg.HKEY_LOCAL_MACHINE, self.REG_SDK_PATH, "InstallationFolder"),
            "sdk_version": self._query_registry(winreg.HKEY_LOCAL_MACHINE, self.REG_SDK_PATH, "ProductVersion"),
            "depot_tools": self._find_depot_tools(),
            "wsl_available": self._detect_wsl()
        }
        
        logger.info("[Toolchain] VS Path: " + str(info["vs_path"]))
        logger.info("[Toolchain] SDK: " + str(info["sdk_version"]) + " at " + str(info["sdk_path"]))
        
        return info

    def _find_depot_tools(self) -> Optional[str]:
        """Find depot_tools in PATH or common locations."""
        import shutil
        gclient = shutil.which("gclient")
        if gclient:
            return str(Path(gclient).parent)
        
        # Common locations
        paths = [r"D:\src\depot_tools", r"C:\src\depot_tools", r"C:\depot_tools"]
        for p in paths:
            if os.path.exists(os.path.join(p, "gclient")):
                return p
        return None

    def _detect_wsl(self) -> bool:
        """Detect if WSL is available."""
        try:
            result = subprocess.run(["wsl", "-l", "-q"], capture_output=True, text=True, timeout=2)
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_binary_version(self, path: str) -> str:
        """
        Get version of a binary file.
        
        Args:
            path: Path to binary
            
        Returns:
            Version string or "unknown"
        """
        if not os.path.exists(path):
            return "unknown"
            
        try:
            # Use PowerShell to get version info
            cmd = ['powershell', '-Command', f"(Get-Item '{path}').VersionInfo.ProductVersion"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
            
        # Fallback to binary help output
        try:
            result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', result.stdout)
                if match:
                    return match.group(1)
        except:
            pass
            
        return "unknown"
    
    def _check_asan_enabled(self, binary_path: str) -> bool:
        """
        Check if a binary is built with ASAN.
        
        Args:
            binary_path: Path to binary
            
        Returns:
            True if ASAN is enabled
        """
        try:
            # Run with --help and check for ASAN-related output
            result = subprocess.run(
                [binary_path, "--help"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # ASAN builds often have specific flags or output
            output = result.stdout + result.stderr
            
            # Check for ASAN indicators
            asan_indicators = [
                "asan",
                "AddressSanitizer",
                "ASAN",
            ]
            
            return any(indicator.lower() in output.lower() for indicator in asan_indicators)
            
        except Exception as e:
            logger.debug(f"Failed to check ASAN: {e}")
            return False
    
    def get_default_env(self) -> VerificationEnv:
        """
        Get default verification environment.
        
        Returns:
            VerificationEnv with auto-detected paths and toolchain
        """
        env = VerificationEnv()
        
        # Detect toolchain first
        env.toolchain = self.detect_toolchain()
        
        # Try to find d8 first (most common for V8 CVEs)
        env.d8_path = self._find_d8(prefer_asan=True)
        if env.d8_path:
            env.d8_version = self.get_binary_version(env.d8_path)
            env.asan_enabled = self._check_asan_enabled(env.d8_path)
        
        # Also try to find Chrome
        env.chrome_path = self._find_chrome()
        if env.chrome_path:
            env.chrome_version = self.get_binary_version(env.chrome_path)
        
        return env
    
        return True, ""

    def find_all_versions(self, base_dir: str = None) -> List[Dict[str, str]]:
        """
        Discover all available d8/chrome versions in a directory.
        
        Args:
            base_dir: Base directory to search (defaults to ./volumes)
            
        Returns:
            List of dictionaries with version info
        """
        if not base_dir:
            base_dir = self.config.get("versions_dir", "./volumes")
            
        results = []
        base_path = Path(base_dir)
        if not base_path.exists():
            return results
            
        # Search for chrome- folders
        for folder in base_path.glob("chrome-*"):
            if folder.is_dir():
                version_str = folder.name.replace("chrome-", "")
                
                # Check for binaries
                d8_path = None
                for p in folder.rglob("d8.exe"):
                    d8_path = str(p)
                    break
                    
                chrome_path = None
                for p in folder.rglob("chrome.exe"):
                    chrome_path = str(p)
                    break
                    
                if d8_path or chrome_path:
                    results.append({
                        "version": version_str,
                        "d8_path": d8_path,
                        "chrome_path": chrome_path,
                        "asan": self._check_asan_enabled(d8_path) if d8_path else False
                    })
        
        return sorted(results, key=lambda x: x["version"], reverse=True)
