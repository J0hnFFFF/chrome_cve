"""
PDB Symbol Downloader

Automatically downloads PDB symbol files from Microsoft Symbol Server
for Windows debugging and symbolization.
"""

import os
import urllib.request
import urllib.parse
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import hashlib

logger = logging.getLogger(__name__)


class PDBDownloader:
    """
    Download PDB symbol files from Microsoft Symbol Server.
    
    Features:
    - Download from Microsoft public symbol server
    - Local cache management
    - GUID-based symbol lookup
    - Automatic retry on failure
    """
    
    # Microsoft public symbol server
    SYMBOL_SERVERS = [
        "https://msdl.microsoft.com/download/symbols",
        "https://chromium-browser-symsrv.commondatastorage.googleapis.com",
    ]
    
    def __init__(self, cache_dir: str = None):
        """
        Initialize PDB downloader.
        
        Args:
            cache_dir: Local cache directory for symbols
        """
        if cache_dir is None:
            cache_dir = os.path.join(
                os.path.expanduser("~"),
                ".chrome_cve",
                "symbols"
            )
        
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"PDB cache directory: {self.cache_dir}")
    
    def download_pdb(
        self,
        pdb_name: str,
        guid: str,
        age: int = 1
    ) -> Optional[str]:
        """
        Download a PDB file from symbol server.
        
        Args:
            pdb_name: Name of PDB file (e.g., "chrome.pdb")
            guid: GUID from PE header (32 hex chars)
            age: Age value from PE header
            
        Returns:
            Path to downloaded PDB file, or None if failed
        """
        # Check cache first
        cached_path = self._get_cache_path(pdb_name, guid, age)
        if cached_path.exists():
            logger.info(f"Found cached PDB: {cached_path}")
            return str(cached_path)
        
        # Try each symbol server
        for server_url in self.SYMBOL_SERVERS:
            try:
                pdb_path = self._download_from_server(
                    server_url,
                    pdb_name,
                    guid,
                    age
                )
                
                if pdb_path:
                    logger.info(f"Downloaded PDB from {server_url}")
                    return pdb_path
            except Exception as e:
                logger.debug(f"Failed to download from {server_url}: {e}")
                continue
        
        logger.warning(f"Could not download PDB: {pdb_name}")
        return None
    
    def _download_from_server(
        self,
        server_url: str,
        pdb_name: str,
        guid: str,
        age: int
    ) -> Optional[str]:
        """Download from a specific symbol server."""
        # Build symbol path: pdbname/GUID+AGE/pdbname
        guid_age = f"{guid.upper()}{age}"
        symbol_path = f"{pdb_name}/{guid_age}/{pdb_name}"
        
        # Full URL
        url = f"{server_url}/{symbol_path}"
        
        logger.debug(f"Trying: {url}")
        
        # Download
        try:
            # Create cache directory
            cache_path = self._get_cache_path(pdb_name, guid, age)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Download file
            urllib.request.urlretrieve(url, str(cache_path))
            
            # Verify download
            if cache_path.exists() and cache_path.stat().st_size > 0:
                return str(cache_path)
            else:
                cache_path.unlink(missing_ok=True)
                return None
                
        except Exception as e:
            logger.debug(f"Download failed: {e}")
            return None
    
    def _get_cache_path(self, pdb_name: str, guid: str, age: int) -> Path:
        """Get local cache path for a PDB file."""
        guid_age = f"{guid.upper()}{age}"
        return self.cache_dir / pdb_name / guid_age / pdb_name
    
    def download_for_binary(self, binary_path: str) -> Optional[str]:
        """
        Download PDB for a specific binary.
        
        Args:
            binary_path: Path to PE binary
            
        Returns:
            Path to PDB file, or None
        """
        # Extract PDB info from PE
        pdb_info = self._extract_pdb_info(binary_path)
        
        if not pdb_info:
            logger.warning(f"Could not extract PDB info from {binary_path}")
            return None
        
        return self.download_pdb(
            pdb_info["pdb_name"],
            pdb_info["guid"],
            pdb_info["age"]
        )
    
    def _extract_pdb_info(self, binary_path: str) -> Optional[Dict[str, Any]]:
        """
        Extract PDB information from PE binary.
        
        This is a simplified implementation. A full implementation would
        parse the PE headers and debug directory.
        """
        try:
            import pefile
            
            pe = pefile.PE(binary_path)
            
            # Get debug directory
            if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                return None
            
            for entry in pe.DIRECTORY_ENTRY_DEBUG:
                if entry.struct.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                    # Parse CodeView data
                    data = entry.entry
                    
                    # Extract GUID and age
                    # This is simplified - real implementation needs proper parsing
                    pdb_name = Path(binary_path).stem + ".pdb"
                    
                    return {
                        "pdb_name": pdb_name,
                        "guid": "00000000000000000000000000000000",  # Placeholder
                        "age": 1
                    }
            
            return None
            
        except ImportError:
            logger.warning("pefile not available. Install with: pip install pefile")
            return None
        except Exception as e:
            logger.debug(f"Failed to extract PDB info: {e}")
            return None
    
    def clear_cache(self) -> None:
        """Clear the symbol cache."""
        import shutil
        
        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Symbol cache cleared")
    
    def get_cache_size(self) -> int:
        """Get total size of cached symbols in bytes."""
        total_size = 0
        
        for file_path in self.cache_dir.rglob("*.pdb"):
            total_size += file_path.stat().st_size
        
        return total_size
    
    def list_cached_symbols(self) -> list:
        """List all cached PDB files."""
        cached = []
        
        for pdb_file in self.cache_dir.rglob("*.pdb"):
            cached.append({
                "name": pdb_file.name,
                "path": str(pdb_file),
                "size": pdb_file.stat().st_size
            })
        
        return cached


def download_chrome_symbols(version: str, cache_dir: str = None) -> Optional[str]:
    """
    Download Chrome symbols for a specific version.
    
    Args:
        version: Chrome version (e.g., "95.0.4638.69")
        cache_dir: Optional cache directory
        
    Returns:
        Path to symbol directory
    """
    downloader = PDBDownloader(cache_dir)
    
    # Chrome PDB name pattern
    pdb_name = "chrome.dll.pdb"
    
    # Note: Real implementation would need actual GUID from the binary
    # This is a placeholder
    logger.warning("Chrome symbol download requires actual GUID from binary")
    
    return None


def demo_pdb_downloader():
    """Demo of PDB downloader functionality."""
    print("PDB Symbol Downloader Demo")
    print("=" * 80)
    
    downloader = PDBDownloader()
    
    print(f"\nCache directory: {downloader.cache_dir}")
    
    # List cached symbols
    cached = downloader.list_cached_symbols()
    print(f"\nCached symbols: {len(cached)}")
    for symbol in cached[:5]:
        print(f"  - {symbol['name']} ({symbol['size']} bytes)")
    
    # Cache size
    cache_size = downloader.get_cache_size()
    print(f"\nTotal cache size: {cache_size / 1024 / 1024:.2f} MB")
    
    print("\nNote: To download symbols, you need:")
    print("  1. Binary file path")
    print("  2. PDB name, GUID, and age from PE header")
    print("  3. pip install pefile (for automatic extraction)")


if __name__ == "__main__":
    demo_pdb_downloader()
