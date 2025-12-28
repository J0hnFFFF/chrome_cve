"""
Dynamic Knowledge Builder

Automatically extracts context from Chromium source code and external sources
to assist PoC generation (Phase 5.1).
"""

import os
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class KnowledgeContext:
    """Context information for a CVE."""
    cve_id: str
    source_comments: List[str]
    similar_cves: List[Dict[str, Any]]
    design_docs: List[str]
    commit_context: Dict[str, Any]
    confidence: float


class DynamicKnowledgeBuilder:
    """
    Builds dynamic knowledge base from multiple sources.
    
    Features (Phase 5.1):
    - Source code comment extraction (5.1.1)
    - Similar CVE retrieval (5.1.4)
    - Design document search (5.1.3 - optional)
    """
    
    def __init__(
        self,
        chromium_path: str = None,
        code_context_fetcher=None,
        cache_dir: str = None
    ):
        """
        Initialize knowledge builder.
        
        Args:
            chromium_path: Path to Chromium source
            code_context_fetcher: CodeContextFetcher instance
            cache_dir: Directory for caching knowledge
        """
        self.chromium_path = chromium_path
        self.code_context_fetcher = code_context_fetcher
        self.cache_dir = cache_dir or os.path.join(
            os.path.expanduser("~"), ".chrome_cve_cache", "knowledge"
        )
        os.makedirs(self.cache_dir, exist_ok=True)
        self._cache = {}
    
    def build_knowledge(
        self,
        cve_info: Dict[str, Any],
        patch_info: Dict[str, Any]
    ) -> KnowledgeContext:
        """
        Build knowledge context for a CVE.
        
        Args:
            cve_info: CVE information
            patch_info: Patch information
            
        Returns:
            KnowledgeContext with extracted information
        """
        cve_id = cve_info.get("cve_id", "unknown")
        logger.info(f"Building knowledge for {cve_id}")
        
        # Check cache
        cached = self._get_cached(cve_id)
        if cached:
            logger.info(f"Using cached knowledge for {cve_id}")
            return cached
        
        # Extract from multiple sources
        knowledge = KnowledgeContext(
            cve_id=cve_id,
            source_comments=self._extract_source_comments(patch_info),
            similar_cves=self._find_similar_cves(cve_info),
            design_docs=self._search_design_docs(cve_info),
            commit_context=self._extract_commit_context(patch_info),
            confidence=self._calculate_confidence(cve_info, patch_info)
        )
        
        # Cache result
        self._cache_knowledge(cve_id, knowledge)
        
        logger.info(f"Built knowledge for {cve_id}: "
                   f"{len(knowledge.source_comments)} comments, "
                   f"{len(knowledge.similar_cves)} similar CVEs")
        
        return knowledge
    
    # ========== Phase 5.1.1: Source Comment Extraction ==========
    
    def _extract_source_comments(
        self,
        patch_info: Dict[str, Any]
    ) -> List[str]:
        """
        Extract source code comments from patch.
        
        Uses existing CodeContextFetcher (Phase 2.2).
        """
        if not self.code_context_fetcher:
            logger.warning("No CodeContextFetcher available")
            return []
        
        comments = []
        patch_diff = patch_info.get("diff", "")
        
        # Extract modified functions from diff
        functions = self._extract_functions_from_diff(patch_diff)
        
        # Get context for each function
        for func_info in functions:
            try:
                context = self.code_context_fetcher.fetch_function_context(
                    file_path=func_info["file"],
                    function_name=func_info["function"],
                    commit_hash=patch_info.get("commit_hash")
                )
                
                if context and context.comments:
                    comments.extend(context.comments)
                    
            except Exception as e:
                logger.debug(f"Failed to fetch context for {func_info}: {e}")
        
        return list(set(comments))  # Deduplicate
    
    def _extract_functions_from_diff(self, diff: str) -> List[Dict[str, str]]:
        """Extract function names and files from diff."""
        import re
        
        functions = []
        current_file = None
        
        for line in diff.split('\n'):
            # File marker
            if line.startswith('diff --git') or line.startswith('+++'):
                match = re.search(r'b/(.+?)(?:\s|$)', line)
                if match:
                    current_file = match.group(1)
            
            # Function marker (C++ or JS)
            elif current_file:
                # C++ function
                cpp_match = re.match(r'[-+]\s*(\w+::\w+)\s*\(', line)
                if cpp_match:
                    functions.append({
                        "file": current_file,
                        "function": cpp_match.group(1)
                    })
                
                # JavaScript function
                js_match = re.match(r'[-+]\s*function\s+(\w+)\s*\(', line)
                if js_match:
                    functions.append({
                        "file": current_file,
                        "function": js_match.group(1)
                    })
        
        return functions[:10]  # Limit to 10 functions
    
    # ========== Phase 5.1.4: Similar CVE Retrieval ==========
    
    def _find_similar_cves(
        self,
        cve_info: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Find similar CVEs using NVD API.
        
        Similarity based on:
        - Component match
        - Vulnerability type match
        - Time window (±6 months)
        """
        try:
            from .cve_similarity import CVESimilarityFinder
            
            finder = CVESimilarityFinder(cache_dir=self.cache_dir)
            similar = finder.find_similar(
                cve_info=cve_info,
                max_results=5
            )
            
            return similar
            
        except ImportError:
            logger.warning("CVESimilarityFinder not available")
            return []
        except Exception as e:
            logger.error(f"Failed to find similar CVEs: {e}")
            return []
    
    # ========== Helper Methods ==========
    
    def _search_design_docs(
        self,
        cve_info: Dict[str, Any]
    ) -> List[str]:
        """
        Search Chromium design documents.
        
        Phase 5.1.3 (Low priority) - Basic implementation.
        """
        # TODO: Implement full design doc search
        # For now, return empty list
        return []
    
    def _extract_commit_context(
        self,
        patch_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract context from commit message."""
        commit_msg = patch_info.get("commit_message", "")
        
        return {
            "message": commit_msg,
            "has_bug_id": "BUG=" in commit_msg or "Bug:" in commit_msg,
            "has_test": "test" in commit_msg.lower(),
            "length": len(commit_msg)
        }
    
    def _calculate_confidence(
        self,
        cve_info: Dict[str, Any],
        patch_info: Dict[str, Any]
    ) -> float:
        """Calculate confidence score for knowledge."""
        score = 0.5  # Base score
        
        # Has patch
        if patch_info.get("diff"):
            score += 0.2
        
        # Has commit message
        if patch_info.get("commit_message"):
            score += 0.1
        
        # Has CVE description
        if cve_info.get("description"):
            score += 0.1
        
        # Has references
        if cve_info.get("references"):
            score += 0.1
        
        return min(score, 1.0)
    
    def _get_cached(self, cve_id: str) -> Optional[KnowledgeContext]:
        """Get cached knowledge."""
        if cve_id in self._cache:
            return self._cache[cve_id]
        
        # TODO: Load from disk cache
        return None
    
    def _cache_knowledge(self, cve_id: str, knowledge: KnowledgeContext):
        """Cache knowledge."""
        self._cache[cve_id] = knowledge
        
        # TODO: Save to disk cache
