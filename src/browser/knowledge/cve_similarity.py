"""
CVE Similarity Finder

Finds similar CVEs using NVD API (Phase 5.1.4).
"""

import os
import json
import logging
import hashlib
from typing import Dict, Any, List
from datetime import datetime, timedelta
import requests

logger = logging.getLogger(__name__)


class CVESimilarityFinder:
    """
    Finds similar CVEs using NVD API.
    
    Similarity criteria:
    - Component match (v8, blink, etc.)
    - Vulnerability type match
    - Time window (±6 months)
    """
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, cache_dir: str = None, api_key: str = None):
        """
        Initialize similarity finder.
        
        Args:
            cache_dir: Directory for caching results
            api_key: NVD API key (optional, for higher rate limits)
        """
        self.cache_dir = cache_dir or os.path.join(
            os.path.expanduser("~"), ".chrome_cve_cache", "nvd"
        )
        os.makedirs(self.cache_dir, exist_ok=True)
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self._session = requests.Session()
        
        if self.api_key:
            self._session.headers["apiKey"] = self.api_key
    
    def find_similar(
        self,
        cve_info: Dict[str, Any],
        max_results: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Find similar CVEs.
        
        Args:
            cve_info: CVE information
            max_results: Maximum number of results
            
        Returns:
            List of similar CVEs with similarity scores
        """
        cve_id = cve_info.get("cve_id", "")
        
        # Check cache
        cached = self._get_cached(cve_id)
        if cached:
            logger.info(f"Using cached similar CVEs for {cve_id}")
            return cached[:max_results]
        
        # Extract search criteria
        component = self._extract_component(cve_info)
        vuln_type = self._extract_vuln_type(cve_info)
        time_window = self._get_time_window(cve_info)
        
        logger.info(f"Searching similar CVEs: component={component}, "
                   f"type={vuln_type}, window={time_window}")
        
        # Search NVD
        candidates = self._search_nvd(component, time_window)
        
        # Score and rank
        scored = []
        for candidate in candidates:
            if candidate.get("id") == cve_id:
                continue  # Skip self
            
            score = self._calculate_similarity(cve_info, candidate)
            if score > 0.3:  # Threshold
                scored.append({
                    "cve_id": candidate.get("id"),
                    "description": candidate.get("description", ""),
                    "similarity_score": score,
                    "published_date": candidate.get("published"),
                    "references": candidate.get("references", [])
                })
        
        # Sort by score
        scored.sort(key=lambda x: x["similarity_score"], reverse=True)
        result = scored[:max_results]
        
        # Cache result
        self._cache_result(cve_id, result)
        
        logger.info(f"Found {len(result)} similar CVEs for {cve_id}")
        return result
    
    def _search_nvd(
        self,
        keyword: str,
        time_window: tuple
    ) -> List[Dict[str, Any]]:
        """Search NVD API."""
        try:
            params = {
                "keywordSearch": keyword,
                "pubStartDate": time_window[0],
                "pubEndDate": time_window[1],
                "resultsPerPage": 20
            }
            
            response = self._session.get(
                self.NVD_API_URL,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                # Extract CVE data
                results = []
                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    results.append({
                        "id": cve.get("id"),
                        "description": self._extract_description(cve),
                        "published": cve.get("published"),
                        "references": cve.get("references", [])
                    })
                
                return results
            else:
                logger.warning(f"NVD API returned {response.status_code}")
                return []
                
        except requests.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to search NVD: {e}")
            return []
    
    def _calculate_similarity(
        self,
        cve1: Dict[str, Any],
        cve2: Dict[str, Any]
    ) -> float:
        """Calculate similarity score between two CVEs."""
        score = 0.0
        
        # Component match
        comp1 = self._extract_component(cve1).lower()
        comp2 = self._extract_component(cve2).lower()
        if comp1 and comp2 and comp1 in comp2:
            score += 0.4
        
        # Vulnerability type match
        type1 = self._extract_vuln_type(cve1).lower()
        type2 = self._extract_vuln_type(cve2).lower()
        if type1 and type2:
            # Exact match
            if type1 == type2:
                score += 0.3
            # Partial match
            elif type1 in type2 or type2 in type1:
                score += 0.15
        
        # Description similarity (simple keyword match)
        desc1 = cve1.get("description", "").lower()
        desc2 = cve2.get("description", "").lower()
        if desc1 and desc2:
            common_words = set(desc1.split()) & set(desc2.split())
            if len(common_words) > 5:
                score += 0.2
            elif len(common_words) > 3:
                score += 0.1
        
        # Time proximity (closer = more similar)
        time_diff = self._calculate_time_diff(cve1, cve2)
        if time_diff < 30:  # Within 30 days
            score += 0.1
        elif time_diff < 90:  # Within 90 days
            score += 0.05
        
        return min(score, 1.0)
    
    def _extract_component(self, cve_info: Dict[str, Any]) -> str:
        """Extract component from CVE info."""
        # Try multiple sources
        component = cve_info.get("component", "")
        if component:
            return component
        
        # Extract from description
        desc = cve_info.get("description", "").lower()
        if "v8" in desc:
            return "v8"
        elif "blink" in desc:
            return "blink"
        elif "webassembly" in desc or "wasm" in desc:
            return "wasm"
        elif "chrome" in desc:
            return "chrome"
        
        return "unknown"
    
    def _extract_vuln_type(self, cve_info: Dict[str, Any]) -> str:
        """Extract vulnerability type."""
        vuln_type = cve_info.get("vulnerability_type", "")
        if vuln_type:
            return vuln_type
        
        # Extract from description
        desc = cve_info.get("description", "").lower()
        keywords = {
            "use-after-free": ["use-after-free", "uaf"],
            "buffer_overflow": ["buffer overflow", "heap overflow"],
            "type_confusion": ["type confusion"],
            "integer_overflow": ["integer overflow"],
        }
        
        for vuln_type, patterns in keywords.items():
            if any(p in desc for p in patterns):
                return vuln_type
        
        return "unknown"
    
    def _get_time_window(self, cve_info: Dict[str, Any]) -> tuple:
        """Get time window for search (±6 months)."""
        published = cve_info.get("published_date")
        
        if published:
            try:
                pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
            except:
                pub_date = datetime.now()
        else:
            pub_date = datetime.now()
        
        start = pub_date - timedelta(days=180)
        end = pub_date + timedelta(days=180)
        
        return (
            start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            end.strftime("%Y-%m-%dT%H:%M:%S.000")
        )
    
    def _calculate_time_diff(
        self,
        cve1: Dict[str, Any],
        cve2: Dict[str, Any]
    ) -> int:
        """Calculate time difference in days."""
        try:
            date1 = datetime.fromisoformat(
                cve1.get("published_date", "").replace('Z', '+00:00')
            )
            date2 = datetime.fromisoformat(
                cve2.get("published", "").replace('Z', '+00:00')
            )
            return abs((date1 - date2).days)
        except:
            return 999  # Large number if parsing fails
    
    def _extract_description(self, cve: Dict[str, Any]) -> str:
        """Extract description from CVE data."""
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        return ""
    
    def _get_cached(self, cve_id: str) -> List[Dict[str, Any]]:
        """Get cached results."""
        cache_file = os.path.join(
            self.cache_dir,
            f"{cve_id}_similar.json"
        )
        
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        return None
    
    def _cache_result(self, cve_id: str, result: List[Dict[str, Any]]):
        """Cache results."""
        cache_file = os.path.join(
            self.cache_dir,
            f"{cve_id}_similar.json"
        )
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to cache results: {e}")
