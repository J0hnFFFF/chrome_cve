"""
Intel Source Implementations

Concrete implementations of intelligence sources.
"""

import re
import json
import requests
import base64
from typing import Optional
from .base import IntelSource, IntelResult


class NVDSource(IntelSource):
    """
    National Vulnerability Database source.

    Provides:
    - CVE description
    - CVSS score and severity
    - CWE classification
    - References
    """

    name = "nvd"
    tier = 1
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    def collect(self, cve_id: str) -> IntelResult:
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            response = requests.get(
                f"{self.NVD_API}?cveId={cve_id}",
                headers=headers,
                timeout=self.timeout
            )

            if response.status_code != 200:
                return IntelResult(
                    source=self.name,
                    error=f"NVD API error: {response.status_code}"
                )

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                return IntelResult(
                    source=self.name,
                    error=f"CVE {cve_id} not found in NVD"
                )

            cve_data = vulnerabilities[0].get("cve", {})
            return IntelResult(
                source=self.name,
                data=self._parse_cve_data(cve_data),
                confidence=1.0
            )

        except Exception as e:
            return IntelResult(source=self.name, error=str(e))

    def _parse_cve_data(self, cve_data: dict) -> dict:
        """Parse CVE data from NVD response."""
        result = {
            "description": "",
            "cvss_score": 0.0,
            "severity": "",
            "cwe_ids": [],
            "references": [],
            "chromium_refs": {},  # NEW: Structured Chromium references
        }

        # Extract description
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                result["description"] = desc.get("value", "")
                break

        # Extract CVSS
        metrics = cve_data.get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                cvss_data = metrics[version][0].get("cvssData", {})
                result["cvss_score"] = cvss_data.get("baseScore", 0.0)
                result["severity"] = cvss_data.get("baseSeverity", "")
                break

        # Extract CWE
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "")
                if cwe_id.startswith("CWE-"):
                    result["cwe_ids"].append(cwe_id)

        # Extract references
        for ref in cve_data.get("references", []):
            result["references"].append(ref.get("url", ""))

        # NEW: Extract Chromium-specific references
        result["chromium_refs"] = self._extract_chromium_references(
            result["references"]
        )

        return result

    def _extract_chromium_references(self, references: list) -> dict:
        """
        Extract Chromium-specific information from NVD references.
        
        Returns:
            Dictionary with bug_ids, commits, and release_notes
        """
        chromium_refs = {
            "bug_ids": [],
            "commits": [],
            "release_notes": [],
            "repositories": set(),  # Track which repos are involved
        }
        
        for ref in references:
            # Extract Bug IDs from issues.chromium.org
            # Example: https://issues.chromium.org/issues/417169470
            bug_match = re.search(r'issues\.chromium\.org/issues/(\d+)', ref)
            if bug_match:
                bug_id = bug_match.group(1)
                chromium_refs["bug_ids"].append(bug_id)
                continue
            
            # Extract Commit hashes from googlesource.com
            # Example: https://chromium.googlesource.com/chromium/src/+/abc123def456
            commit_match = re.search(
                r'chromium\.googlesource\.com/([^/]+(?:/[^/]+)?)/\+/([a-f0-9]{7,40})',
                ref
            )
            if commit_match:
                repo = commit_match.group(1)
                commit_hash = commit_match.group(2)
                chromium_refs["commits"].append({
                    "repository": repo,
                    "hash": commit_hash,
                    "url": ref
                })
                chromium_refs["repositories"].add(repo)
                continue
            
            # Extract from Chrome Release Blog
            # Example: https://chromereleases.googleblog.com/2025/05/stable-channel-update-for-desktop_27.html
            if "chromereleases.googleblog.com" in ref:
                chromium_refs["release_notes"].append(ref)
                # Try to extract version from URL or will need to parse page
                version_match = re.search(r'chrome[/-]?(\d+\.\d+\.\d+\.\d+)', ref, re.I)
                if version_match:
                    chromium_refs.setdefault("versions", []).append(version_match.group(1))
                continue
            
            # Extract from Chromium Code Review
            # Example: https://chromium-review.googlesource.com/c/chromium/src/+/123456
            review_match = re.search(
                r'chromium-review\.googlesource\.com/c/([^/]+(?:/[^/]+)?)/\+/(\d+)',
                ref
            )
            if review_match:
                repo = review_match.group(1)
                review_id = review_match.group(2)
                chromium_refs.setdefault("reviews", []).append({
                    "repository": repo,
                    "review_id": review_id,
                    "url": ref
                })
                chromium_refs["repositories"].add(repo)
                continue
        
        # Convert set to list for JSON serialization
        chromium_refs["repositories"] = list(chromium_refs["repositories"])
        
        # Deduplicate bug IDs
        chromium_refs["bug_ids"] = list(set(chromium_refs["bug_ids"]))
        
        return chromium_refs


class GitilesSource(IntelSource):
    """
    Chromium Gitiles source for patch information.
    
    Enhanced with:
    - Automatic repository detection
    - Batch commit fetching
    - Patch caching
    """
    
    name = "gitiles"
    tier = 1
    
    CHROMIUM_GITILES = "https://chromium.googlesource.com"
    
    # Repository mapping for automatic detection
    REPO_PATTERNS = {
        'v8': ['v8/v8', 'chromium/src'],  # Try v8/v8 first for V8 issues
        'blink': ['chromium/src'],
        'skia': ['skia/skia', 'chromium/src'],
        'chromium': ['chromium/src'],
    }
    
    def __init__(self, timeout: int = 30, cache_dir: str = None):
        super().__init__(timeout)
        self.cache = {}  # In-memory cache
        self.cache_dir = cache_dir  # Optional disk cache
    
    def collect(self, cve_id: str) -> IntelResult:
        # This source requires commit hashes from NVD references
        # It should be called with commit info, not just CVE ID
        return IntelResult(
            source=self.name,
            error="GitilesSource requires commit hashes. Use collect_commit() or collect_commits_batch() instead."
        )
    
    def detect_repository(self, component: str = None, commit_hash: str = None) -> list:
        """
        Detect likely repositories for a component or commit.
        
        Args:
            component: Component name (e.g., 'v8', 'blink')
            commit_hash: Commit hash to search for
            
        Returns:
            List of repository paths to try, in priority order
        """
        if component:
            component_lower = component.lower()
            for key, repos in self.REPO_PATTERNS.items():
                if key in component_lower:
                    return repos
        
        # Default: try chromium/src
        return ['chromium/src']
    
    def collect_commit(self, repository: str, commit_hash: str) -> IntelResult:
        """Collect patch information for a specific commit."""
        # Check cache first
        cache_key = f"{repository}:{commit_hash}"
        if cache_key in self.cache:
            # Assuming logger is defined elsewhere or needs to be imported
            # from your_logging_module import logger
            # logger.debug(f"Cache hit for {cache_key}")
            return self.cache[cache_key]
        
        try:
            # Fetch commit info
            url = f"{self.CHROMIUM_GITILES}/{repository}/+/{commit_hash}?format=JSON"
            response = requests.get(url, timeout=self.timeout)

            if response.status_code != 200:
                result = IntelResult(
                    source=self.name,
                    error=f"Gitiles error: {response.status_code}"
                )
                self.cache[cache_key] = result
                return result

            # Remove Gitiles JSON security prefix
            json_text = response.text
            if json_text.startswith(")]}'"):
                json_text = json_text[4:]

            commit_data = json.loads(json_text)

            # Fetch diff
            diff_url = f"{self.CHROMIUM_GITILES}/{repository}/+/{commit_hash}%5E%21/?format=TEXT"
            diff_response = requests.get(diff_url, timeout=self.timeout)

            diff_content = ""
            files_changed = []
            if diff_response.status_code == 200:
                diff_content = base64.b64decode(diff_response.content).decode('utf-8', errors='ignore')
                # Extract changed files
                for line in diff_content.split('\n'):
                    if line.startswith('diff --git'):
                        match = re.search(r'diff --git a/(.*) b/', line)
                        if match:
                            files_changed.append(match.group(1))

            result = IntelResult(
                source=self.name,
                data={
                    "commit_hash": commit_hash,
                    "repository": repository,
                    "message": commit_data.get("message", ""),
                    "diff_content": diff_content,
                    "files_changed": files_changed,
                    "author": commit_data.get("author", {}).get("name", ""),
                    "committer": commit_data.get("committer", {}).get("name", ""),
                },
                confidence=1.0
            )
            
            # Cache the result
            self.cache[cache_key] = result
            return result

        except Exception as e:
            result = IntelResult(source=self.name, error=str(e))
            self.cache[cache_key] = result
            return result
    
    def collect_commits_batch(
        self,
        commits: list,  # [(repo, hash), ...] or [hash, ...]
        component: str = None
    ) -> list:
        """
        Collect multiple commits in batch.
        
        Args:
            commits: List of (repository, commit_hash) tuples or just commit hashes
            component: Component hint for repository detection
            
        Returns:
            List of IntelResult objects
        """
        results = []
        
        for commit_info in commits:
            if isinstance(commit_info, tuple):
                repo, commit_hash = commit_info
            else:
                # Auto-detect repository
                commit_hash = commit_info
                repos_to_try = self.detect_repository(component, commit_hash)
                repo = repos_to_try[0]  # Use first match
            
            result = self.collect_commit(repo, commit_hash)
            results.append(result)
        
        return results
    
    def try_multiple_repositories(self, commit_hash: str, component: str = None) -> IntelResult:
        """
        Try fetching a commit from multiple repositories.
        
        Useful when repository is unknown.
        """
        repos_to_try = self.detect_repository(component)
        
        for repo in repos_to_try:
            result = self.collect_commit(repo, commit_hash)
            if result.success:
                # Assuming logger is defined elsewhere or needs to be imported
                # from your_logging_module import logger
                # logger.info(f"Found commit {commit_hash[:12]} in {repo}")
                return result
        
        # All failed
        return IntelResult(
            source=self.name,
            error=f"Commit {commit_hash} not found in any repository"
        )


class ChromeReleaseSource(IntelSource):
    """
    Chrome Release Notes source.

    Provides:
    - Version mapping
    - Release dates
    - CVE associations
    """

    name = "chrome_releases"
    tier = 1

    def collect(self, cve_id: str) -> IntelResult:
        # TODO: Implement Chrome release notes parsing
        return IntelResult(
            source=self.name,
            error="ChromeReleaseSource not yet implemented"
        )


class ChromiumBugTrackerSource(IntelSource):
    """
    Chromium Bug Tracker source.
    
    Enhanced with:
    - HTML parsing for commit extraction
    - Retry mechanism with exponential backoff
    - Handling of restricted/private bugs
    """
    
    name = "chromium_bug_tracker"
    tier = 2
    
    BUG_TRACKER_URL = "https://issues.chromium.org/issues"
    
    def __init__(self, timeout: int = 30, max_retries: int = 3):
        super().__init__(timeout)
        self.max_retries = max_retries
    
    def collect(self, cve_id: str) -> IntelResult:
        # This source requires bug IDs from NVD references
        return IntelResult(
            source=self.name,
            error="ChromiumBugTrackerSource requires bug IDs. Use collect_bug() instead."
        )
    
    def collect_bug(self, bug_id: str) -> IntelResult:
        """
        Collect information from a Chromium bug.
        
        Enhanced with retry logic and HTML parsing.
        """
        for attempt in range(self.max_retries):
            try:
                result = self._fetch_bug_with_retry(bug_id, attempt)
                if result.success or result.error != "retry":
                    return result
                
                # Exponential backoff
                if attempt < self.max_retries - 1:
                    import time
                    # Assuming logger is defined elsewhere or needs to be imported
                    # from your_logging_module import logger
                    # For now, just print if logger is not available
                    # print(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s")
                    wait_time = 2 ** attempt  # 1s, 2s, 4s
                    # logger.debug(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s")
                    time.sleep(wait_time)
                    
            except Exception as e:
                # Assuming logger is defined elsewhere or needs to be imported
                # logger.error(f"Bug tracker error on attempt {attempt + 1}: {e}")
                if attempt == self.max_retries - 1:
                    return IntelResult(source=self.name, error=str(e))
        
        return IntelResult(
            source=self.name,
            error=f"Failed after {self.max_retries} retries"
        )
    
    def _fetch_bug_with_retry(self, bug_id: str, attempt: int) -> IntelResult:
        """Fetch bug information with retry support."""
        try:
            url = f"{self.BUG_TRACKER_URL}/{bug_id}"
            
            # Add headers to mimic browser
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 403:
                return IntelResult(
                    source=self.name,
                    data={
                        "bug_id": bug_id,
                        "restricted": True,
                        "commits": [],
                    },
                    confidence=0.3,
                    error="Bug is restricted/private"
                )
            
            if response.status_code == 429:  # Rate limited
                return IntelResult(source=self.name, error="retry")
            
            if response.status_code != 200:
                return IntelResult(
                    source=self.name,
                    error=f"HTTP {response.status_code}"
                )
            
            # Parse HTML to extract commits
            commits = self._parse_commits_from_html(response.text)
            
            # Extract additional metadata
            metadata = self._parse_bug_metadata(response.text)
            
            return IntelResult(
                source=self.name,
                data={
                    "bug_id": bug_id,
                    "url": url,
                    "commits": commits,
                    "restricted": False,
                    **metadata,
                },
                confidence=0.9 if commits else 0.5
            )
            
        except requests.Timeout:
            return IntelResult(source=self.name, error="retry")
        except Exception as e:
            return IntelResult(source=self.name, error=str(e))
    
    def _parse_commits_from_html(self, html_content: str) -> list:
        """
        Parse commit hashes from bug tracker HTML.
        
        Looks for:
        - Gitiles links: chromium.googlesource.com/.../+/{hash}
        - Gerrit links: chromium-review.googlesource.com/c/.../+/{id}
        - Direct commit references in text
        """
        commits = []
        
        # Pattern 1: Gitiles commit links
        gitiles_pattern = r'chromium\.googlesource\.com/([^/]+(?:/[^/]+)?)/\+/([a-f0-9]{7,40})'
        for match in re.finditer(gitiles_pattern, html_content):
            commits.append(match.group(2))
        
        # Pattern 2: Gerrit review links (need to resolve to commits)
        # For now, just note them
        gerrit_pattern = r'chromium-review\.googlesource\.com/c/[^/]+/\+/(\d+)'
        gerrit_reviews = re.findall(gerrit_pattern, html_content)
        
        # Pattern 3: Commit hashes in text (40 hex chars)
        # Be conservative to avoid false positives
        commit_pattern = r'\b([a-f0-9]{40})\b'
        potential_commits = re.findall(commit_pattern, html_content)
        
        # Only add if we have context suggesting it's a commit
        for commit in potential_commits:
            # Check if near keywords like "commit", "fix", "patch"
            context_pattern = rf'(?:commit|fix|patch|cl|change).{{0,50}}{commit}'
            if re.search(context_pattern, html_content, re.I):
                commits.append(commit)
        
        # Deduplicate while preserving order
        seen = set()
        unique_commits = []
        for commit in commits:
            if commit not in seen:
                seen.add(commit)
                unique_commits.append(commit)
        
        return unique_commits
    
    def _parse_bug_metadata(self, html_content: str) -> dict:
        """Extract additional metadata from bug page."""
        metadata = {
            "title": "",
            "status": "",
            "component": "",
        }
        
        # Try to extract title
        title_match = re.search(r'<title>([^<]+)</title>', html_content)
        if title_match:
            metadata["title"] = title_match.group(1).strip()
        
        # Try to extract status (if visible in HTML)
        status_match = re.search(r'Status[:\s]+(\w+)', html_content, re.I)
        if status_match:
            metadata["status"] = status_match.group(1)
        
        # Try to extract component
        component_match = re.search(r'Component[:\s]+([^<\n]+)', html_content, re.I)
        if component_match:
            metadata["component"] = component_match.group(1).strip()
        
        return metadata


class GitHubPoCSource(IntelSource):
    """
    GitHub PoC Search source.

    Provides:
    - Existing PoC code
    - Analysis writeups
    - Related repositories
    """

    name = "github_poc"
    tier = 2

    def __init__(self, token: str = ""):
        self.token = token

    def collect(self, cve_id: str) -> IntelResult:
        try:
            headers = {"Accept": "application/vnd.github.v3+json"}
            if self.token:
                headers["Authorization"] = f"token {self.token}"

            # Search for repositories mentioning the CVE
            url = f"https://api.github.com/search/repositories?q={cve_id}"
            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code != 200:
                return IntelResult(
                    source=self.name,
                    error=f"GitHub API error: {response.status_code}"
                )

            data = response.json()
            repos = []
            for item in data.get("items", [])[:5]:  # Top 5 results
                repos.append({
                    "name": item.get("full_name"),
                    "url": item.get("html_url"),
                    "description": item.get("description"),
                    "stars": item.get("stargazers_count"),
                })

            return IntelResult(
                source=self.name,
                data={"repositories": repos},
                confidence=0.7 if repos else 0.3
            )

        except Exception as e:
            return IntelResult(source=self.name, error=str(e))


class CISAKEVSource(IntelSource):
    """
    CISA Known Exploited Vulnerabilities source.

    Provides:
    - Exploitation confirmation
    - Required action dates
    """

    name = "cisa_kev"
    tier = 2
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def collect(self, cve_id: str) -> IntelResult:
        try:
            response = requests.get(self.KEV_URL, timeout=self.timeout)

            if response.status_code != 200:
                return IntelResult(
                    source=self.name,
                    error=f"CISA KEV error: {response.status_code}"
                )

            data = response.json()
            for vuln in data.get("vulnerabilities", []):
                if vuln.get("cveID") == cve_id:
                    return IntelResult(
                        source=self.name,
                        data={
                            "known_exploited": True,
                            "vendor": vuln.get("vendorProject"),
                            "product": vuln.get("product"),
                            "vulnerability_name": vuln.get("vulnerabilityName"),
                            "date_added": vuln.get("dateAdded"),
                            "short_description": vuln.get("shortDescription"),
                            "required_action": vuln.get("requiredAction"),
                            "due_date": vuln.get("dueDate"),
                        },
                        confidence=1.0
                    )

            return IntelResult(
                source=self.name,
                data={"known_exploited": False},
                confidence=1.0
            )

        except Exception as e:
            return IntelResult(source=self.name, error=str(e))
