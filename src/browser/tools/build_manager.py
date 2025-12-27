import os
import subprocess
import logging
import platform
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

class WindowsBuildManager:
    """
    Manages local Windows build process via PowerShell scripts.
    """

    def __init__(self, settings):
        self.settings = settings
        self.source_root = Path(settings.build.source_root)
        self.scripts_dir = Path(__file__).parent.parent.parent / "scripts"
        
        # Ensure scripts exist
        if not self.scripts_dir.exists():
            raise FileNotFoundError(f"Scripts directory not found: {self.scripts_dir}")

    def fetch_source(self, target: str = "v8", version: str = "main") -> bool:
        """Fetch source code using win_fetch_source.ps1."""
        script = self.scripts_dir / "win_fetch_source.ps1"
        
        cmd = [
            "powershell",
            "-ExecutionPolicy", "Bypass",
            "-File", str(script),
            "-RootPath", str(self.source_root),
            "-Target", target,
            "-Version", version
        ]
        
        logger.info(f"Fetching {target} (version: {version})...")
        try:
            subprocess.run(cmd, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Fetch failed: {e}")
            return False

    def build_target(self, target: str = "d8", asan: bool = False) -> Optional[str]:
        """Build target using win_build.ps1."""
        # For V8, source is in source_root/v8, for Chromium it's source_root/chromium/src
        # Simplified logic for V8 focus
        source_path = self.source_root / "v8"
        out_dir = "out\\Debug"
        
        script = self.scripts_dir / "win_build.ps1"
        
        cmd = [
            "powershell",
            "-ExecutionPolicy", "Bypass",
            "-File", str(script),
            "-SourcePath", str(source_path),
            "-OutDir", out_dir
        ]
        
        if asan:
            cmd.append("-ASAN")
            
        logger.info(f"Building {target} (ASAN={asan})...")
        try:
            subprocess.run(cmd, check=True)
            
            # Verify output
            binary_name = f"{target}.exe"
            binary_path = source_path / out_dir / binary_name
            
            if binary_path.exists():
                return str(binary_path)
            else:
                logger.error(f"Build succeeded but binary not found: {binary_path}")
                return None
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Build failed: {e}")
            return None

    def get_binary_path(self, target: str = "d8") -> Optional[str]:
        """Get path to existing binary if built."""
        # Assuming V8 repo structure for now
        binary_path = self.source_root / "v8" / "out" / "Debug" / f"{target}.exe"
        if binary_path.exists():
            return str(binary_path)
        return None
