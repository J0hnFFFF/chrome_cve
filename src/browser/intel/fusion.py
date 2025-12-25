"""
Intel Fusion

Merges intelligence from multiple sources into unified CVEInfo.
"""

from typing import Dict, List, Any
from .base import IntelResult
from ..models.cve import CVEInfo, PatchInfo


class IntelFusion:
    """
    Fuses intelligence from multiple sources.

    Handles:
    - Data merging from different sources
    - Conflict resolution
    - Confidence calculation
    - Component detection
    """

    def fuse(
        self,
        cve_id: str,
        results: Dict[str, IntelResult],
    ) -> CVEInfo:
        """
        Fuse all intel results into a unified CVEInfo.

        Args:
            cve_id: The CVE ID
            results: Dictionary of source name to IntelResult

        Returns:
            Fused CVEInfo object
        """
        cve_info = CVEInfo(cve_id=cve_id)

        # Process NVD data (highest priority for basic info)
        nvd_result = results.get("nvd")
        if nvd_result and nvd_result.success:
            self._merge_nvd_data(cve_info, nvd_result.data)
            cve_info.sources.append("nvd")

        # Process patch data
        for key, result in results.items():
            if key.startswith("patch_") and result.success:
                patch = self._parse_patch_data(result.data)
                if patch:
                    cve_info.patches.append(patch)
                    cve_info.sources.append(f"gitiles:{patch.commit_hash[:8]}")

        # Process GitHub PoC data
        github_result = results.get("github_poc")
        if github_result and github_result.success:
            repos = github_result.data.get("repositories", [])
            for repo in repos:
                cve_info.references.append(repo.get("url", ""))
            if repos:
                cve_info.sources.append("github")

        # Process CISA KEV data
        kev_result = results.get("cisa_kev")
        if kev_result and kev_result.success:
            if kev_result.data.get("known_exploited"):
                cve_info.sources.append("cisa_kev")
                # Add KEV info to references
                cve_info.references.append(
                    f"CISA KEV: {kev_result.data.get('vulnerability_name', 'N/A')}"
                )

        # Detect component from patches
        cve_info.component = self._detect_component(cve_info)

        # Calculate overall confidence
        cve_info.confidence = self._calculate_confidence(results)

        return cve_info

    def _merge_nvd_data(self, cve_info: CVEInfo, data: dict) -> None:
        """Merge NVD data into CVEInfo."""
        cve_info.description = data.get("description", "")
        cve_info.cvss_score = data.get("cvss_score", 0.0)
        cve_info.severity = data.get("severity", "")
        cve_info.cwe_ids = data.get("cwe_ids", [])
        cve_info.references.extend(data.get("references", []))

    def _parse_patch_data(self, data: dict) -> PatchInfo:
        """Parse patch data into PatchInfo."""
        return PatchInfo(
            commit_hash=data.get("commit_hash", ""),
            repository=data.get("repository", ""),
            message=data.get("message", ""),
            files_changed=data.get("files_changed", []),
            diff_content=data.get("diff_content", ""),
        )

    def _detect_component(self, cve_info: CVEInfo) -> str:
        """Detect component from patches and description."""
        component_patterns = {
            "V8": ["v8/", "src/v8/"],
            "Wasm": ["v8/src/wasm/", "wasm/"],
            "Blink": ["third_party/blink/", "blink/renderer/"],
            "Skia": ["third_party/skia/"],
            "WebGL": ["gpu/command_buffer/", "gpu/GLES2/"],
            "PDFium": ["third_party/pdfium/"],
            "WebRTC": ["third_party/webrtc/"],
            "Network": ["net/", "services/network/"],
        }

        detected = set()

        for patch in cve_info.patches:
            for file_path in patch.files_changed:
                # Wasm detection before V8
                if "wasm" in file_path.lower():
                    detected.add("Wasm")
                    continue

                for component, patterns in component_patterns.items():
                    for pattern in patterns:
                        if file_path.startswith(pattern):
                            detected.add(component)

        # Description-based detection
        desc_lower = cve_info.description.lower()
        if "v8" in desc_lower or "javascript" in desc_lower:
            detected.add("V8")
        if "blink" in desc_lower or "renderer" in desc_lower:
            detected.add("Blink")
        if "webassembly" in desc_lower or "wasm" in desc_lower:
            detected.add("Wasm")

        return ", ".join(sorted(detected)) if detected else "Unknown"

    def _calculate_confidence(self, results: Dict[str, IntelResult]) -> float:
        """Calculate overall confidence score."""
        if not results:
            return 0.0

        successful = [r for r in results.values() if r.success]
        if not successful:
            return 0.0

        # Weight by tier
        tier_weights = {1: 1.0, 2: 0.8, 3: 0.5}
        total_weight = 0
        weighted_confidence = 0

        for result in successful:
            # Get source tier (default to 2)
            tier = 2
            weight = tier_weights.get(tier, 0.5)
            total_weight += weight
            weighted_confidence += result.confidence * weight

        return weighted_confidence / total_weight if total_weight > 0 else 0.0
