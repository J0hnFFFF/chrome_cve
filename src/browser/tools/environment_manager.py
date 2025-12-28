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
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class VerificationEnv:
    """Verification environment configuration."""
    d8_path: Optional[str] = None
    chrome_path: Optional[str] = None
    asan_enabled: bool = False
    version: str = ""
    
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
            else:
                logger.warning("✗ No Chrome binary found")
        
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
        Find Chrome binary in common locations.
        
        Returns:
            Path to chrome.exe or None
        """
        # 1. Check config
        config_path = self.config.get("execution", {}).get("chrome_path")
        if config_path and os.path.exists(config_path):
            return config_path
        
        # 2. Check common paths
        for path in self.WINDOWS_CHROME_PATHS:
            if os.path.exists(path):
                return path
        
        return None
    
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
            VerificationEnv with auto-detected paths
        """
        env = VerificationEnv()
        
        # Try to find d8 first (most common for V8 CVEs)
        env.d8_path = self._find_d8(prefer_asan=True)
        
        # Also try to find Chrome
        env.chrome_path = self._find_chrome()
        
        # Check ASAN
        if env.d8_path:
            env.asan_enabled = self._check_asan_enabled(env.d8_path)
        
        return env
    
    def validate_env(self, env: VerificationEnv) -> tuple[bool, str]:
        """
        Validate verification environment.
        
        Args:
            env: Environment to validate
            
        Returns:
            (is_valid, error_message)
        """
        if not env.is_valid():
            return False, "No d8 or Chrome binary found"
        
        # Check if paths exist
        if env.d8_path and not os.path.exists(env.d8_path):
            return False, f"d8 path does not exist: {env.d8_path}"
        
        if env.chrome_path and not os.path.exists(env.chrome_path):
            return False, f"Chrome path does not exist: {env.chrome_path}"
        
        return True, ""
