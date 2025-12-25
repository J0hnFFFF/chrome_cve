"""
Intelligence Collection System for Chrome CVE Reproducer

This module provides multi-source intelligence gathering:

Tier 1 (Required):
- NVDSource: CVE description, CVSS, CWE from NVD API
- GitilesSource: Patch diff, commit info from Chromium Git
- ChromeReleaseSource: Version mapping, release notes

Tier 2 (Important):
- ChromiumBugTrackerSource: Bug details, comments
- GitHubPoCSource: Existing PoC search
- CISAKEVSource: Known exploitation confirmation

Tier 3 (Supplementary):
- SecurityBlogSource: Technical analysis articles
- ExploitDBSource: Public exploit code

The intel system also provides:
- IntelFusion: Merge and validate multi-source data
- Confidence scoring for intelligence quality
"""

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
from .collector import IntelCollector
from .version import ChromeVersionMapper, ChromeDownloader, ChromeVersion

__all__ = [
    'IntelSource',
    'IntelResult',
    'NVDSource',
    'GitilesSource',
    'ChromeReleaseSource',
    'ChromiumBugTrackerSource',
    'GitHubPoCSource',
    'CISAKEVSource',
    'IntelFusion',
    'IntelCollector',
    'ChromeVersionMapper',
    'ChromeDownloader',
    'ChromeVersion',
]
