"""
Intel Fusion

Merges intelligence from multiple sources into unified CVEInfo.
Enhanced with smart patch selection and quality reporting.
"""

from typing import Dict, List, Any, Optional
from .base import IntelResult
from ..models.cve import CVEInfo, PatchInfo
import logging

logger = logging.getLogger(__name__)


class IntelFusion:
    """
    Fuses intelligence from multiple sources.

    Enhanced with:
    - Smart patch selection (when multiple commits)
    - Improved confidence calculation
    - Intelligence collection reporting
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

        # Process patch data with smart selection
        patches_data = []
        for key, result in results.items():
            if key.startswith("patch_") and result.success:
                patches_data.append(result.data)
        
        # Smart patch selection
        selected_patches = self._select_best_patches(patches_data)
        for patch_data in selected_patches:
            patch = self._parse_patch_data(patch_data)
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
        cve_info.confidence = self._calculate_confidence(results, cve_info)

        return cve_info

    def _select_best_patches(self, patches_data: List[dict]) -> List[dict]:
        """
        Select best patches when multiple are available.
        
        Prioritization criteria:
        1. Patches with regression tests
        2. Patches with more files changed (more comprehensive)
        3. Patches with longer commit messages (more context)
        
        Args:
            patches_data: List of patch data dictionaries
            
        Returns:
            Sorted list of patch data (best first)
        """
        if not patches_data:
            return []
        
        if len(patches_data) == 1:
            return patches_data
        
        def patch_score(patch: dict) -> float:
            """Calculate quality score for a patch."""
            score = 0.0
            
            # Has regression tests? (+50 points)
            if patch.get("regression_tests"):
                score += 50.0
            
            # Number of files changed (+1 point per file, max 20)
            files_changed = len(patch.get("files_changed", []))
            score += min(files_changed, 20)
            
            # Commit message length (+0.01 per char, max 10)
            message_len = len(patch.get("message", ""))
            score += min(message_len * 0.01, 10)
            
            # Has diff content? (+10 points)
            if patch.get("diff_content"):
                score += 10.0
            
            return score
        
        # Sort by score (descending)
        sorted_patches = sorted(patches_data, key=patch_score, reverse=True)
        
        # Log selection
        if len(sorted_patches) > 1:
            best = sorted_patches[0]
            logger.info(
                f"Selected best patch: {best.get('commit_hash', 'unknown')[:12]} "
                f"(score: {patch_score(best):.1f}, {len(best.get('files_changed', []))} files)"
            )
        
        return sorted_patches

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
            regression_tests=data.get("regression_tests", ""),
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

    def _calculate_confidence(
        self,
        results: Dict[str, IntelResult],
        cve_info: CVEInfo
    ) -> float:
        """
        Calculate overall confidence score.
        
        Enhanced to consider:
        - Source tier and success rate
        - Patch quality (has regression tests, file count)
        - Component detection confidence
        """
        if not results:
            return 0.0

        successful = [r for r in results.values() if r.success]
        if not successful:
            return 0.0

        # Base confidence from sources
        tier_weights = {1: 1.0, 2: 0.8, 3: 0.5}
        total_weight = 0
        weighted_confidence = 0

        for result in successful:
            # Get source tier (default to 2)
            tier = getattr(result, 'tier', 2)
            weight = tier_weights.get(tier, 0.5)
            total_weight += weight
            weighted_confidence += result.confidence * weight

        base_confidence = weighted_confidence / total_weight if total_weight > 0 else 0.0
        
        # Boost for high-quality patches
        patch_boost = 0.0
        if cve_info.patches:
            # Has patches: +0.1
            patch_boost += 0.1
            
            # Has regression tests: +0.1
            if any(p.regression_tests for p in cve_info.patches):
                patch_boost += 0.1
            
            # Multiple patches: +0.05
            if len(cve_info.patches) > 1:
                patch_boost += 0.05
        
        # Boost for component detection
        component_boost = 0.05 if cve_info.component != "Unknown" else 0.0
        
        # Final confidence (capped at 1.0)
        final_confidence = min(base_confidence + patch_boost + component_boost, 1.0)
        
        return final_confidence

    def generate_collection_report(
        self,
        cve_id: str,
        results: Dict[str, IntelResult],
        cve_info: CVEInfo
    ) -> dict:
        """
        Generate intelligence collection report.
        
        Returns:
            Dictionary with collection statistics and quality metrics
        """
        report = {
            "cve_id": cve_id,
            "sources_attempted": len(results),
            "sources_successful": sum(1 for r in results.values() if r.success),
            "sources_failed": sum(1 for r in results.values() if not r.success),
            "patches_collected": len(cve_info.patches),
            "component_detected": cve_info.component,
            "confidence_score": cve_info.confidence,
            "has_regression_tests": any(p.regression_tests for p in cve_info.patches),
            "source_details": {},
        }
        
        # Detailed source breakdown
        for source_name, result in results.items():
            report["source_details"][source_name] = {
                "success": result.success,
                "confidence": result.confidence if result.success else 0.0,
                "error": result.error if not result.success else None,
            }
        
        # Quality assessment
        if report["patches_collected"] == 0:
            report["quality"] = "LOW"
            report["recommendation"] = "No patches found. Manual investigation required."
        elif report["has_regression_tests"]:
            report["quality"] = "HIGH"
            report["recommendation"] = "Excellent: Has regression tests for PoC generation."
        elif report["patches_collected"] > 0:
            report["quality"] = "MEDIUM"
            report["recommendation"] = "Good: Has patches but no regression tests."
        else:
            report["quality"] = "UNKNOWN"
            report["recommendation"] = "Insufficient data."
        
        return report

