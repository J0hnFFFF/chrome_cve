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

        # Extract commit hashes from NVD references
        nvd_result = results.get("nvd")
        patches = []
        if nvd_result and nvd_result.success:
            import re
            refs = nvd_result.data.get("references", [])
            description = nvd_result.data.get("description", "")

            # Patterns for Chromium commit URLs
            patterns = [
                # Standard gitiles: chromium.googlesource.com/repo/+/hash
                r'chromium\.googlesource\.com/([^/]+(?:/[^/]+)?)/\+/([a-f0-9]{7,40})',
                # Chromium review: chromium-review.googlesource.com/c/repo/+/change
                r'chromium-review\.googlesource\.com/c/([^/]+(?:/[^/]+)?)/\+/(\d+)',
                # Chrome release blog with commit reference
                r'chromereleases\.googleblog\.com.*?([a-f0-9]{40})',
                # Direct git hash in URL
                r'/([a-f0-9]{40})(?:[/?#]|$)',
            ]

            all_text = " ".join(refs) + " " + description

            # Debug: show references
            if refs:
                print(f"  NVD references ({len(refs)}):")
                for ref in refs[:5]:  # Show first 5
                    print(f"    - {ref[:80]}...")

            # Also extract bug IDs and fetch from bug tracker
            bug_tracker = ChromiumBugTrackerSource()
            for ref in refs:
                # Match issues.chromium.org/issues/{id}
                bug_match = re.search(r'issues\.chromium\.org/issues/(\d+)', ref)
                if bug_match:
                    bug_id = bug_match.group(1)
                    print(f"  Fetching bug tracker issue {bug_id}...")
                    bug_result = bug_tracker.collect_bug(bug_id)
                    if bug_result.success and bug_result.data.get("commits"):
                        for commit in bug_result.data["commits"]:
                            patches.append(("chromium/src", commit))
                        print(f"    Found {len(bug_result.data['commits'])} commit(s) in bug {bug_id}")
                    results["bug_tracker"] = bug_result

            for pattern in patterns:
                for match in re.finditer(pattern, all_text):
                    if len(match.groups()) >= 2:
                        repo = match.group(1)
                        commit = match.group(2)
                        # Default repo if not specified
                        if not '/' in repo:
                            repo = f"chromium/src"
                        patches.append((repo, commit))
                    elif len(match.groups()) == 1:
                        # Just hash, assume chromium/src
                        patches.append(("chromium/src", match.group(1)))

            # Deduplicate
            patches = list(set(patches))

            if patches:
                print(f"  Found {len(patches)} commit(s) in NVD references")

        # Collect patches
        if patches:
            patch_results = self.collect_patches(patches)
            for i, pr in enumerate(patch_results):
                results[f"patch_{i}"] = pr
        else:
            print("  No commit hashes found in NVD references")

        # Fuse all results
        return self.fusion.fuse(cve_id, results)
