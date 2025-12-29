"""
Multi-Version Chrome/d8 Manager

Provides convenient APIs for managing multiple Chrome/d8 versions.
"""

import os
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class BinaryVersion:
    """Information about a specific binary version."""
    version: str
    d8_path: Optional[str]
    chrome_path: Optional[str]
    asan_enabled: bool
    base_dir: str
    
    def __str__(self) -> str:
        parts = [f"Version {self.version}"]
        if self.d8_path:
            parts.append(f"d8: {self.d8_path}")
        if self.chrome_path:
            parts.append(f"chrome: {self.chrome_path}")
        if self.asan_enabled:
            parts.append("(ASAN)")
        return " | ".join(parts)


class VersionManager:
    """
    Manager for multiple Chrome/d8 versions.
    
    Features:
    - Auto-discover all versions in a directory
    - Select version by number or criteria
    - Get vulnerable/fixed pairs
    - Manage ASAN vs non-ASAN versions
    """
    
    def __init__(self, base_dir: str = "./volumes"):
        """
        Initialize version manager.
        
        Args:
            base_dir: Base directory containing version folders
        """
        self.base_dir = Path(base_dir)
        self.versions: List[BinaryVersion] = []
        self._refresh()
    
    def _refresh(self) -> None:
        """Refresh the list of available versions."""
        from .environment_manager import EnvironmentManager
        
        env_mgr = EnvironmentManager()
        discovered = env_mgr.find_all_versions(str(self.base_dir))
        
        self.versions = [
            BinaryVersion(
                version=v["version"],
                d8_path=v.get("d8_path"),
                chrome_path=v.get("chrome_path"),
                asan_enabled=v.get("asan", False),
                base_dir=str(self.base_dir / f"chrome-{v['version']}")
            )
            for v in discovered
        ]
        
        logger.info(f"Found {len(self.versions)} versions in {self.base_dir}")
    
    def list_versions(self, asan_only: bool = False) -> List[BinaryVersion]:
        """
        List all available versions.
        
        Args:
            asan_only: Only return ASAN-enabled versions
            
        Returns:
            List of BinaryVersion objects
        """
        if asan_only:
            return [v for v in self.versions if v.asan_enabled]
        return self.versions
    
    def get_version(self, version_str: str) -> Optional[BinaryVersion]:
        """
        Get a specific version by version string.
        
        Args:
            version_str: Version string (e.g., "95.0.4638.69")
            
        Returns:
            BinaryVersion or None if not found
        """
        for v in self.versions:
            if v.version == version_str or version_str in v.version:
                return v
        return None
    
    def get_latest(self, asan_only: bool = False) -> Optional[BinaryVersion]:
        """
        Get the latest version.
        
        Args:
            asan_only: Only consider ASAN versions
            
        Returns:
            Latest BinaryVersion or None
        """
        candidates = self.list_versions(asan_only=asan_only)
        if not candidates:
            return None
        
        # Versions are already sorted in reverse order
        return candidates[0]
    
    def get_version_pair(
        self,
        vulnerable_version: str,
        fixed_version: str = None
    ) -> tuple[Optional[BinaryVersion], Optional[BinaryVersion]]:
        """
        Get a pair of vulnerable and fixed versions.
        
        Args:
            vulnerable_version: Version string for vulnerable binary
            fixed_version: Version string for fixed binary (optional)
                          If not provided, uses the next version
            
        Returns:
            Tuple of (vulnerable, fixed) BinaryVersion objects
        """
        vuln = self.get_version(vulnerable_version)
        
        if fixed_version:
            fixed = self.get_version(fixed_version)
        else:
            # Find next version after vulnerable
            fixed = self._get_next_version(vulnerable_version)
        
        return (vuln, fixed)
    
    def _get_next_version(self, version_str: str) -> Optional[BinaryVersion]:
        """Get the next version after the specified one."""
        current_idx = None
        for i, v in enumerate(self.versions):
            if v.version == version_str or version_str in v.version:
                current_idx = i
                break
        
        if current_idx is not None and current_idx > 0:
            # Versions are sorted in reverse, so previous index is newer
            return self.versions[current_idx - 1]
        
        return None
    
    def get_by_cve(self, cve_id: str, cve_info: Dict[str, Any] = None) -> tuple[Optional[BinaryVersion], Optional[BinaryVersion]]:
        """
        Get vulnerable/fixed version pair based on CVE information.
        
        Args:
            cve_id: CVE ID
            cve_info: Optional CVE metadata with version info
            
        Returns:
            Tuple of (vulnerable, fixed) BinaryVersion objects
        """
        if not cve_info:
            logger.warning(f"No CVE info provided for {cve_id}")
            return (None, None)
        
        # Try to extract version from CVE info
        vulnerable_version = cve_info.get("vulnerable_version")
        fixed_version = cve_info.get("fixed_version")
        
        if vulnerable_version:
            return self.get_version_pair(vulnerable_version, fixed_version)
        
        logger.warning(f"Could not determine versions for {cve_id}")
        return (None, None)
    
    def print_summary(self) -> None:
        """Print a summary of all available versions."""
        print(f"\nAvailable Chrome/d8 Versions ({len(self.versions)} total):")
        print("=" * 80)
        
        for i, v in enumerate(self.versions, 1):
            print(f"{i:2d}. {v}")
        
        print("=" * 80)
        
        asan_count = sum(1 for v in self.versions if v.asan_enabled)
        print(f"\nASAN-enabled: {asan_count}/{len(self.versions)}")
        
        if self.versions:
            latest = self.versions[0]
            print(f"Latest: {latest.version}")
    
    def select_interactive(self) -> Optional[BinaryVersion]:
        """
        Interactively select a version.
        
        Returns:
            Selected BinaryVersion or None
        """
        if not self.versions:
            print("No versions available")
            return None
        
        self.print_summary()
        
        while True:
            try:
                choice = input("\nSelect version number (or 'q' to quit): ").strip()
                
                if choice.lower() == 'q':
                    return None
                
                idx = int(choice) - 1
                if 0 <= idx < len(self.versions):
                    return self.versions[idx]
                else:
                    print(f"Invalid choice. Enter 1-{len(self.versions)}")
            except ValueError:
                print("Invalid input. Enter a number or 'q'")
    
    def get_d8_path(self, version_str: str) -> Optional[str]:
        """
        Get d8 path for a specific version.
        
        Args:
            version_str: Version string
            
        Returns:
            Path to d8 binary or None
        """
        version = self.get_version(version_str)
        return version.d8_path if version else None
    
    def get_chrome_path(self, version_str: str) -> Optional[str]:
        """
        Get Chrome path for a specific version.
        
        Args:
            version_str: Version string
            
        Returns:
            Path to Chrome binary or None
        """
        version = self.get_version(version_str)
        return version.chrome_path if version else None


def demo_version_manager():
    """Demo of version manager functionality."""
    print("Chrome/d8 Version Manager Demo")
    print("=" * 80)
    
    # Initialize manager
    mgr = VersionManager("./volumes")
    
    # Show all versions
    mgr.print_summary()
    
    # Get latest
    latest = mgr.get_latest()
    if latest:
        print(f"\nLatest version: {latest.version}")
        print(f"  d8: {latest.d8_path}")
    
    # Get latest ASAN
    latest_asan = mgr.get_latest(asan_only=True)
    if latest_asan:
        print(f"\nLatest ASAN version: {latest_asan.version}")
    
    # Get version pair
    if len(mgr.versions) >= 2:
        vuln, fixed = mgr.get_version_pair(mgr.versions[1].version)
        if vuln and fixed:
            print(f"\nVersion pair:")
            print(f"  Vulnerable: {vuln.version}")
            print(f"  Fixed: {fixed.version}")


if __name__ == "__main__":
    demo_version_manager()
