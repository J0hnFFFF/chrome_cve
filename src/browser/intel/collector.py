"""
Intel Collector

Orchestrates intelligence collection from multiple sources.
"""

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

            print(f"  Collecting from {source.name}...")
            result = source.collect(cve_id)
            results[source.name] = result

            if result.success:
                print(f"    ✓ {source.name}: Got data")
            else:
                print(f"    ✗ {source.name}: {result.error}")

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
            from ..tools.chromium_tools import fetch_associated_tests
            print(f"  Crawler: Scanning commit {commit} for regression tests...")
            tests_data = fetch_associated_tests.func(commit, repo)
            if tests_data and not tests_data.startswith("No regression tests"):
                print(f"    ✓ Found relevant test files")
                # Attach to the result using a custom field
                # IntelResult data is a bit rigid, so we add it to the internal dictionary
                if result.success and isinstance(result.data, dict):
                    result.data['regression_tests'] = tests_data
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
            print(f"\n  📊 Chromium References Found:")
            print(f"    Bug IDs: {len(chromium_refs.get('bug_ids', []))}")
            print(f"    Commits: {len(chromium_refs.get('commits', []))}")
            print(f"    Repositories: {chromium_refs.get('repositories', [])}")
            print(f"    Release Notes: {len(chromium_refs.get('release_notes', []))}")
            
            # 1. Add commits directly from NVD references
            for commit_info in chromium_refs.get("commits", []):
                repo = commit_info["repository"]
                commit_hash = commit_info["hash"]
                patches.append((repo, commit_hash))
                print(f"    ✓ Direct commit: {repo}/{commit_hash[:12]}")
            
            # 2. Fetch commits from Bug Tracker
            bug_tracker = ChromiumBugTrackerSource()
            for bug_id in chromium_refs.get("bug_ids", []):
                print(f"  🔍 Fetching bug tracker issue {bug_id}...")
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
                    print(f"    ✓ Found {len(commits_found)} commit(s) in bug {bug_id}")
                    results["bug_tracker"] = bug_result
                else:
                    print(f"    ✗ No commits found in bug {bug_id}")

            # Deduplicate patches
            patches = list(set(patches))
            
            if patches:
                print(f"\n  📦 Total unique commits to fetch: {len(patches)}")
            else:
                print(f"\n  ⚠️  No commits found in NVD references or bug tracker")

        # Collect patches
        if patches:
            patch_results = self.collect_patches(patches)
            for i, pr in enumerate(patch_results):
                results[f"patch_{i}"] = pr
                if pr.success:
                    files_changed = len(pr.data.get("files_changed", []))
                    print(f"    ✓ Patch {i}: {files_changed} files changed")

        # Fuse all results
        print(f"\n  🔗 Fusing intelligence from {len(results)} sources...")
        return self.fusion.fuse(cve_id, results)
