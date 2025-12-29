"""
Intel Collector

Orchestrates intelligence collection from multiple sources.
"""

import logging
from typing import List, Dict, Any, Optional
from .base import IntelSource, IntelResult
from .sources import (
    NVDSource,
    GitilesSource,
    ChromeReleaseSource,
    ChromiumBugTrackerSource,
    GitHubPoCSource,
    CISAKEVSource,
)
from .fusion import IntelFusion

logger = logging.getLogger(__name__)

# Import Rich console for better output
try:
    from ..utils.rich_console import console
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    console = None


def _print(message: str, style: str = None):
    """Print with Rich if available, otherwise use plain print."""
    if RICH_AVAILABLE and console:
        if style:
            console.print(f"[{style}]{message}[/{style}]")
        else:
            console.print(message)
    else:
        print(message)


class IntelCollector:
    """
    Orchestrates multi-source intelligence collection.

    Collects from sources in tier order:
    - Tier 1 (Required): NVD, Gitiles, Chrome Releases
    - Tier 2 (Important): Bug Tracker, GitHub PoC, CISA KEV
    - Tier 3 (Supplementary): Security blogs, ExploitDB

    Then fuses the results into a unified CVEInfo.
    """

    def __init__(
        self,
        nvd_api_key: str = "",
        github_token: str = "",
    ):
        self.sources: List[IntelSource] = []
        self.fusion = IntelFusion()

        # Register sources
        self._register_sources(nvd_api_key, github_token)

    def _register_sources(
        self,
        nvd_api_key: str = "",
        github_token: str = "",
    ) -> None:
        """Register all intel sources."""
        # Tier 1: Required
        self.sources.append(NVDSource(api_key=nvd_api_key))
        self.sources.append(GitilesSource())
        self.sources.append(ChromeReleaseSource())

        # Tier 2: Important
        self.sources.append(ChromiumBugTrackerSource())
        self.sources.append(GitHubPoCSource(token=github_token))
        self.sources.append(CISAKEVSource())

    def collect(
        self,
        cve_id: str,
        tier_limit: int = 2,
    ) -> Dict[str, IntelResult]:
        """
        Collect intelligence from all sources up to the specified tier.

        Args:
            cve_id: The CVE ID to collect for
            tier_limit: Maximum tier to collect from (1, 2, or 3)

        Returns:
            Dictionary mapping source name to IntelResult
        """
        results = {}

        for source in self.sources:
            if source.tier > tier_limit:
                continue

            _print(f"  Collecting from {source.name}...", "cyan")
            result = source.collect(cve_id)
            results[source.name] = result

            if result.success:
                _print(f"    ✓ {source.name}: Got data", "green")
            else:
                _print(f"    ✗ {source.name}: {result.error}", "red")

        return results

    def collect_patches(
        self,
        commit_hashes: List[tuple],  # [(repository, hash), ...]
    ) -> List[IntelResult]:
        """
        Collect patch information for specific commits.

        Args:
            commit_hashes: List of (repository, commit_hash) tuples

        Returns:
            List of IntelResult with patch data
        """
        gitiles = GitilesSource()
        results = []

        for repo, commit in commit_hashes:
            result = gitiles.collect_commit(repo, commit)
            
            # --- New Feature: Regression Test Crawler ---
            try:
                # Import the actual function, not the SerializedTool wrapper
                from ..tools import chromium_tools
                _print(f"  Crawler: Scanning commit {commit} for regression tests...", "yellow")
                
                # Call the function directly from the module
                if hasattr(chromium_tools, 'fetch_associated_tests'):
                    func = chromium_tools.fetch_associated_tests
                    
                    # Check if it's a SerializedTool (has invoke method)
                    if hasattr(func, 'invoke'):
                        # Use invoke instead of __call__ (LangChain 0.1.47+)
                        tests_data = func.invoke({"commit_hash": commit, "repo": repo})
                    elif hasattr(func, 'func'):
                        # It's wrapped but doesn't have invoke, use .func
                        tests_data = func.func(commit, repo)
                    else:
                        # It's the raw function
                        tests_data = func(commit, repo)
                    
                    if tests_data and not tests_data.startswith("No regression tests"):
                        _print(f"    ✓ Found relevant test files", "green")
                        # Attach to the result using a custom field
                        if result.success and isinstance(result.data, dict):
                            result.data['regression_tests'] = tests_data
            except Exception as e:
                logger.debug(f"Failed to fetch regression tests: {e}")
            # --------------------------------------------
            
            results.append(result)

        return results

    def collect_and_fuse(
        self,
        cve_id: str,
        tier_limit: int = 2,
    ):
        """
        Collect intelligence and fuse into unified CVEInfo.

        Args:
            cve_id: The CVE ID to collect for
            tier_limit: Maximum tier to collect from

        Returns:
            Fused CVEInfo object
        """
        # Collect from all sources
        results = self.collect(cve_id, tier_limit)

        # Extract commit hashes from NVD references using new structured data
        nvd_result = results.get("nvd")
        patches = []
        
        if nvd_result and nvd_result.success:
            chromium_refs = nvd_result.data.get("chromium_refs", {})
            
            # Show what we found
            _print(f"\n  📊 Chromium References Found:", "bold cyan")
            _print(f"    Bug IDs: {len(chromium_refs.get('bug_ids', []))}", "cyan")
            _print(f"    Commits: {len(chromium_refs.get('commits', []))}", "cyan")
            _print(f"    Repositories: {chromium_refs.get('repositories', [])}", "cyan")
            _print(f"    Release Notes: {len(chromium_refs.get('release_notes', []))}", "cyan")
            
            # 1. Add commits directly from NVD references
            for commit_info in chromium_refs.get("commits", []):
                repo = commit_info["repository"]
                commit_hash = commit_info["hash"]
                patches.append((repo, commit_hash))
                _print(f"    ✓ Direct commit: {repo}/{commit_hash[:12]}", "green")
            
            # 2. Fetch commits from Bug Tracker
            bug_tracker = ChromiumBugTrackerSource()
            for bug_id in chromium_refs.get("bug_ids", []):
                _print(f"  🔍 Fetching bug tracker issue {bug_id}...", "yellow")
                bug_result = bug_tracker.collect_bug(bug_id)
                
                if bug_result.success and bug_result.data.get("commits"):
                    commits_found = bug_result.data["commits"]
                    for commit in commits_found:
                        # Determine repository (default to chromium/src)
                        repo = "chromium/src"
                        # If we have repository info from NVD, use it
                        if chromium_refs.get("repositories"):
                            repo = chromium_refs["repositories"][0]
                        patches.append((repo, commit))
                    _print(f"    ✓ Found {len(commits_found)} commit(s) in bug {bug_id}", "green")
                    results["bug_tracker"] = bug_result
                else:
                    _print(f"    ✗ No commits found in bug {bug_id}", "yellow")

            # Deduplicate patches
            patches = list(set(patches))
            
            if patches:
                _print(f"\n  📦 Total unique commits to fetch: {len(patches)}", "bold green")
            else:
                _print(f"\n  ⚠️  No commits found in NVD references or bug tracker", "yellow")

        # Collect patches
        if patches:
            patch_results = self.collect_patches(patches)
            for i, pr in enumerate(patch_results):
                results[f"patch_{i}"] = pr
                if pr.success:
                    files_changed = len(pr.data.get("files_changed", []))
                    _print(f"    ✓ Patch {i}: {files_changed} files changed", "green")

        # Fuse all results
        _print(f"\n  🔗 Fusing intelligence from {len(results)} sources...", "bold cyan")
        return self.fusion.fuse(cve_id, results)
