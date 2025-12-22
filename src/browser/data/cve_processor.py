"""
Chromium CVE Data Processor

Fetches and processes CVE information from various sources:
- NVD (National Vulnerability Database)
- Chromium Bug Tracker
- Chromium Git repositories
"""

import re
import json
import requests
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class PatchInfo:
    """Information about a patch commit."""
    commit_hash: str
    repository: str  # e.g., "chromium/src", "v8/v8"
    message: str = ""
    files_changed: List[str] = field(default_factory=list)
    diff_content: str = ""


@dataclass
class CVEInfo:
    """Complete CVE information."""
    cve_id: str
    description: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    cwe_ids: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    patches: List[PatchInfo] = field(default_factory=list)
    bug_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    component: str = ""  # V8, Blink, etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cwe_ids": self.cwe_ids,
            "affected_versions": self.affected_versions,
            "fixed_versions": self.fixed_versions,
            "patches": [
                {
                    "commit_hash": p.commit_hash,
                    "repository": p.repository,
                    "message": p.message,
                    "files_changed": p.files_changed,
                }
                for p in self.patches
            ],
            "bug_ids": self.bug_ids,
            "references": self.references,
            "component": self.component,
        }


class ChromiumCVEProcessor:
    """Process CVE information for Chromium/Chrome vulnerabilities."""

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CHROMIUM_GITILES = "https://chromium.googlesource.com"

    def __init__(self, cve_id: str):
        self.cve_id = cve_id
        self.cve_info = CVEInfo(cve_id=cve_id)

    def fetch_from_nvd(self) -> bool:
        """Fetch CVE info from NVD."""
        try:
            response = requests.get(
                f"{self.NVD_API}?cveId={self.cve_id}",
                timeout=30
            )

            if response.status_code != 200:
                print(f"NVD API error: {response.status_code}")
                return False

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                print(f"CVE {self.cve_id} not found in NVD")
                return False

            cve_data = vulnerabilities[0].get("cve", {})

            # Extract description
            descriptions = cve_data.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    self.cve_info.description = desc.get("value", "")
                    break

            # Extract CVSS score
            metrics = cve_data.get("metrics", {})
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    cvss_data = metrics[version][0].get("cvssData", {})
                    self.cve_info.cvss_score = cvss_data.get("baseScore", 0.0)
                    self.cve_info.severity = cvss_data.get("baseSeverity", "")
                    break

            # Extract CWE
            weaknesses = cve_data.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_id = desc.get("value", "")
                    if cwe_id.startswith("CWE-"):
                        self.cve_info.cwe_ids.append(cwe_id)

            # Extract references
            references = cve_data.get("references", [])
            for ref in references:
                url = ref.get("url", "")
                self.cve_info.references.append(url)

                # Extract Chromium bug IDs
                bug_match = re.search(r'bugs\.chromium\.org/p/chromium/issues/detail\?id=(\d+)', url)
                if bug_match:
                    self.cve_info.bug_ids.append(bug_match.group(1))

                # Extract commit hashes from Chromium git
                commit_match = re.search(r'chromium\.googlesource\.com/([^/]+/[^/]+)/\+/([a-f0-9]{40})', url)
                if commit_match:
                    repo = commit_match.group(1)
                    commit = commit_match.group(2)
                    self.cve_info.patches.append(PatchInfo(
                        commit_hash=commit,
                        repository=repo
                    ))

            return True

        except Exception as e:
            print(f"Error fetching from NVD: {e}")
            return False

    def fetch_patch_details(self) -> None:
        """Fetch detailed patch information for each commit."""
        import base64

        for patch in self.cve_info.patches:
            try:
                # Fetch commit info
                url = f"{self.CHROMIUM_GITILES}/{patch.repository}/+/{patch.commit_hash}?format=JSON"
                response = requests.get(url, timeout=30)

                if response.status_code == 200:
                    # Remove Gitiles JSON security prefix
                    json_text = response.text
                    if json_text.startswith(")]}'"):
                        json_text = json_text[4:]

                    data = json.loads(json_text)
                    patch.message = data.get("message", "")

                # Fetch diff
                diff_url = f"{self.CHROMIUM_GITILES}/{patch.repository}/+/{patch.commit_hash}%5E%21/?format=TEXT"
                diff_response = requests.get(diff_url, timeout=30)

                if diff_response.status_code == 200:
                    patch.diff_content = base64.b64decode(diff_response.content).decode('utf-8', errors='ignore')

                    # Extract changed files
                    for line in patch.diff_content.split('\n'):
                        if line.startswith('diff --git'):
                            match = re.search(r'diff --git a/(.*) b/', line)
                            if match:
                                patch.files_changed.append(match.group(1))

            except Exception as e:
                print(f"Error fetching patch {patch.commit_hash}: {e}")

    def detect_component(self) -> str:
        """Detect which Chromium component is affected based on patches."""
        component_patterns = {
            # JavaScript引擎
            "V8": ["v8/", "src/v8/"],
            # WebAssembly (在V8目录下但独立)
            "Wasm": ["v8/src/wasm/", "src/wasm/"],
            # 渲染引擎
            "Blink": ["third_party/blink/", "blink/renderer/"],
            # 图形
            "Skia": ["third_party/skia/"],
            "WebGL": ["gpu/command_buffer/", "gpu/GLES2/", "ui/gl/"],
            "ANGLE": ["third_party/angle/"],
            # 媒体
            "PDFium": ["third_party/pdfium/"],
            "WebRTC": ["third_party/webrtc/"],
            "FFmpeg": ["third_party/ffmpeg/"],
            # 网络
            "Network": ["net/", "services/network/"],
            "QUIC": ["net/quic/", "net/third_party/quiche/"],
            # 安全
            "Sandbox": ["sandbox/"],
            # 其他
            "Mojo": ["mojo/"],
            "IPC": ["ipc/"],
        }

        detected = set()

        for patch in self.cve_info.patches:
            for file_path in patch.files_changed:
                # Wasm检测优先于V8
                if "wasm" in file_path.lower():
                    detected.add("Wasm")
                    continue

                for component, patterns in component_patterns.items():
                    for pattern in patterns:
                        if file_path.startswith(pattern):
                            detected.add(component)

        # 从描述中检测
        desc_lower = self.cve_info.description.lower()
        if "v8" in desc_lower or "javascript" in desc_lower:
            detected.add("V8")
        if "blink" in desc_lower or "renderer" in desc_lower:
            detected.add("Blink")
        if "webassembly" in desc_lower or "wasm" in desc_lower:
            detected.add("Wasm")
        if "webgl" in desc_lower or "gpu process" in desc_lower:
            detected.add("WebGL")
        if "webrtc" in desc_lower or "peerconnection" in desc_lower:
            detected.add("WebRTC")
        if "pdf" in desc_lower:
            detected.add("PDFium")

        if detected:
            self.cve_info.component = ", ".join(sorted(detected))
        else:
            self.cve_info.component = "Unknown"

        return self.cve_info.component

    def process(self) -> CVEInfo:
        """Run the full processing pipeline."""
        print(f"Processing {self.cve_id}...")

        # Step 1: Fetch from NVD
        print("  Fetching from NVD...")
        self.fetch_from_nvd()

        # Step 2: Fetch patch details
        if self.cve_info.patches:
            print(f"  Fetching {len(self.cve_info.patches)} patch(es)...")
            self.fetch_patch_details()

        # Step 3: Detect component
        print("  Detecting component...")
        self.detect_component()

        print(f"  Done. Component: {self.cve_info.component}")
        return self.cve_info

    def to_knowledge_text(self) -> str:
        """Convert CVE info to text format for LLM consumption."""
        text = f"""
# CVE Information: {self.cve_id}

## Summary
- **Severity**: {self.cve_info.severity} (CVSS: {self.cve_info.cvss_score})
- **Component**: {self.cve_info.component}
- **CWE**: {', '.join(self.cve_info.cwe_ids) or 'Not specified'}

## Description
{self.cve_info.description}

## Patches
"""
        for i, patch in enumerate(self.cve_info.patches, 1):
            text += f"""
### Patch {i}: {patch.commit_hash[:12]}
- **Repository**: {patch.repository}
- **Files Changed**: {len(patch.files_changed)}
  {chr(10).join('  - ' + f for f in patch.files_changed[:10])}
  {'  ... and more' if len(patch.files_changed) > 10 else ''}

**Commit Message**:
{patch.message[:500]}{'...' if len(patch.message) > 500 else ''}
"""

        if self.cve_info.bug_ids:
            text += f"""
## Related Bugs
{chr(10).join('- https://bugs.chromium.org/p/chromium/issues/detail?id=' + bid for bid in self.cve_info.bug_ids)}
"""

        return text
