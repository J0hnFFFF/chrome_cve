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

        return result


class GitilesSource(IntelSource):
    """
    Chromium Gitiles source.

    Provides:
    - Patch diff content
    - Commit messages
    - Changed files
    """

    name = "gitiles"
    tier = 1
    CHROMIUM_GITILES = "https://chromium.googlesource.com"

    def collect(self, cve_id: str) -> IntelResult:
        # This source requires commit hashes from NVD references
        # It should be called with commit info, not just CVE ID
        return IntelResult(
            source=self.name,
            error="GitilesSource requires commit hashes. Use collect_commit() instead."
        )

    def collect_commit(self, repository: str, commit_hash: str) -> IntelResult:
        """Collect patch information for a specific commit."""
        try:
            # Fetch commit info
            url = f"{self.CHROMIUM_GITILES}/{repository}/+/{commit_hash}?format=JSON"
            response = requests.get(url, timeout=self.timeout)

            if response.status_code != 200:
                return IntelResult(
                    source=self.name,
                    error=f"Gitiles error: {response.status_code}"
                )

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

            return IntelResult(
                source=self.name,
                data={
                    "commit_hash": commit_hash,
                    "repository": repository,
                    "message": commit_data.get("message", ""),
                    "diff_content": diff_content,
                    "files_changed": files_changed,
                },
                confidence=1.0
            )

        except Exception as e:
            return IntelResult(source=self.name, error=str(e))


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

    Provides:
    - Bug details and comments
    - Related issues
    - Commit hashes from fix
    """

    name = "bug_tracker"
    tier = 2
    ISSUES_URL = "https://issues.chromium.org"

    def collect(self, cve_id: str) -> IntelResult:
        """
        Collect bug info. Requires bug_id to be set via collect_bug().
        For CVE lookup, use NVD references to get bug ID first.
        """
        return IntelResult(
            source=self.name,
            error="Use collect_bug() with bug ID from NVD references"
        )

    def collect_bug(self, bug_id: str) -> IntelResult:
        """Collect information from a specific bug."""
        try:
            # Fetch the bug page
            url = f"{self.ISSUES_URL}/issues/{bug_id}"
            response = requests.get(url, timeout=self.timeout)

            if response.status_code != 200:
                return IntelResult(
                    source=self.name,
                    error=f"Bug tracker error: {response.status_code}"
                )

            # Parse the page for commit hashes
            html = response.text
            commits = []

            # Look for gitiles commit links
            import re
            patterns = [
                r'chromium\.googlesource\.com/[^/]+/[^/]+/\+/([a-f0-9]{7,40})',
                r'crrev\.com/([a-f0-9]{7,40})',
                r'Cr-Commit-Position:.*?([a-f0-9]{40})',
            ]

            for pattern in patterns:
                for match in re.finditer(pattern, html):
                    commits.append(match.group(1))

            # Deduplicate
            commits = list(set(commits))

            return IntelResult(
                source=self.name,
                data={
                    "bug_id": bug_id,
                    "url": url,
                    "commits": commits,
                },
                confidence=0.9 if commits else 0.5
            )

        except Exception as e:
            return IntelResult(source=self.name, error=str(e))


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
