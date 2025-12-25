"""
Chrome Version Mapping

Maps Chrome versions to Chromium commits and positions.
"""

import re
import requests
from typing import Optional, Dict, Any, List
from dataclasses import dataclass


@dataclass
class ChromeVersion:
    """Chrome version information."""
    version: str
    chromium_position: Optional[int] = None
    chromium_commit: Optional[str] = None
    release_date: Optional[str] = None
    channel: str = "stable"  # stable, beta, dev, canary


class ChromeVersionMapper:
    """
    Maps Chrome versions to Chromium commits.

    Provides:
    - Version to position mapping
    - Version to commit mapping
    - Affected version range detection
    """

    OMAHAPROXY_URL = "https://omahaproxy.appspot.com"
    VERSIONHISTORY_URL = "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions"

    def __init__(self):
        self._version_cache: Dict[str, ChromeVersion] = {}

    def version_to_position(self, version: str) -> Optional[int]:
        """
        Get Chromium position for a Chrome version.

        Args:
            version: Chrome version string (e.g., "120.0.6099.130")

        Returns:
            Chromium position or None
        """
        cached = self._version_cache.get(version)
        if cached and cached.chromium_position:
            return cached.chromium_position

        try:
            # Try omahaproxy
            url = f"{self.OMAHAPROXY_URL}/deps.json?version={version}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                position = data.get("chromium_base_position")
                if position:
                    self._cache_version(version, chromium_position=int(position))
                    return int(position)
        except Exception as e:
            print(f"Error getting position for {version}: {e}")

        return None

    def version_to_commit(self, version: str) -> Optional[str]:
        """
        Get Chromium commit hash for a Chrome version.

        Args:
            version: Chrome version string

        Returns:
            Commit hash or None
        """
        cached = self._version_cache.get(version)
        if cached and cached.chromium_commit:
            return cached.chromium_commit

        try:
            url = f"{self.OMAHAPROXY_URL}/deps.json?version={version}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                commit = data.get("chromium_commit")
                if commit:
                    self._cache_version(version, chromium_commit=commit)
                    return commit
        except Exception as e:
            print(f"Error getting commit for {version}: {e}")

        return None

    def get_version_info(self, version: str) -> Optional[ChromeVersion]:
        """Get complete version information."""
        if version in self._version_cache:
            return self._version_cache[version]

        position = self.version_to_position(version)
        commit = self.version_to_commit(version)

        if position or commit:
            ver = ChromeVersion(
                version=version,
                chromium_position=position,
                chromium_commit=commit,
            )
            self._version_cache[version] = ver
            return ver

        return None

    def get_previous_version(self, version: str) -> Optional[str]:
        """
        Get the previous stable version.

        Useful for finding the vulnerable version before a fix.
        """
        parts = version.split(".")
        if len(parts) != 4:
            return None

        try:
            # Decrement last part
            parts[3] = str(int(parts[3]) - 1)
            return ".".join(parts)
        except:
            return None

    def get_affected_versions(
        self,
        fixed_version: str,
        count: int = 5,
    ) -> List[str]:
        """
        Get list of potentially affected versions before the fix.

        Args:
            fixed_version: Version where fix was applied
            count: Number of previous versions to return

        Returns:
            List of version strings
        """
        versions = []
        current = fixed_version

        for _ in range(count):
            prev = self.get_previous_version(current)
            if prev:
                versions.append(prev)
                current = prev
            else:
                break

        return versions

    def _cache_version(
        self,
        version: str,
        chromium_position: int = None,
        chromium_commit: str = None,
    ) -> None:
        """Cache version information."""
        if version not in self._version_cache:
            self._version_cache[version] = ChromeVersion(version=version)

        if chromium_position:
            self._version_cache[version].chromium_position = chromium_position
        if chromium_commit:
            self._version_cache[version].chromium_commit = chromium_commit

    def parse_version_from_url(self, url: str) -> Optional[str]:
        """Extract Chrome version from a release notes URL."""
        # Match patterns like "120.0.6099.130"
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', url)
        if match:
            return match.group(1)
        return None


class ChromeDownloader:
    """
    Downloads specific Chrome versions for testing.
    """

    CHROMIUM_SNAPSHOTS = "https://www.googleapis.com/download/storage/v1/b/chromium-browser-snapshots/o"

    def __init__(self, cache_dir: str = "./volumes/chrome"):
        self.cache_dir = cache_dir

    def get_download_url(
        self,
        position: int,
        platform: str = "Win_x64",
    ) -> Optional[str]:
        """
        Get download URL for a specific Chromium position.

        Args:
            position: Chromium position number
            platform: Platform (Win_x64, Linux_x64, Mac)

        Returns:
            Download URL or None
        """
        # Format: chromium-browser-snapshots/<platform>/<position>/chrome-win.zip
        obj_name = f"{platform}%2F{position}%2Fchrome-win.zip"
        url = f"{self.CHROMIUM_SNAPSHOTS}/{obj_name}?alt=media"
        return url

    def download_version(
        self,
        version: str,
        platform: str = "Win_x64",
    ) -> Optional[str]:
        """
        Download a specific Chrome version.

        Args:
            version: Chrome version string
            platform: Target platform

        Returns:
            Path to downloaded Chrome or None
        """
        import os
        from pathlib import Path

        # Get position for version
        mapper = ChromeVersionMapper()
        position = mapper.version_to_position(version)

        if not position:
            print(f"Could not find position for version {version}")
            return None

        # Check cache
        cache_path = Path(self.cache_dir) / f"chrome-{version}"
        if cache_path.exists():
            chrome_exe = self._find_chrome_exe(cache_path)
            if chrome_exe:
                return str(chrome_exe)

        # Download
        url = self.get_download_url(position, platform)
        if not url:
            return None

        try:
            import zipfile
            import tempfile

            print(f"Downloading Chrome {version} from position {position}...")

            response = requests.get(url, stream=True, timeout=300)
            if response.status_code != 200:
                print(f"Download failed: {response.status_code}")
                return None

            # Save and extract
            cache_path.mkdir(parents=True, exist_ok=True)
            zip_path = cache_path / "chrome.zip"

            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # Extract
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(cache_path)

            # Cleanup zip
            zip_path.unlink()

            # Find chrome executable
            chrome_exe = self._find_chrome_exe(cache_path)
            if chrome_exe:
                print(f"Chrome downloaded to: {chrome_exe}")
                return str(chrome_exe)

            return None

        except Exception as e:
            print(f"Download error: {e}")
            return None

    def _find_chrome_exe(self, path) -> Optional[str]:
        """Find Chrome executable in directory."""
        from pathlib import Path
        import platform

        path = Path(path)

        if platform.system() == "Windows":
            for exe in path.rglob("chrome.exe"):
                return exe
        else:
            for exe in path.rglob("chrome"):
                if exe.is_file():
                    return exe

        return None
