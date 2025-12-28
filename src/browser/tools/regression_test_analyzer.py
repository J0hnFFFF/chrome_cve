"""
Regression Test Analyzer

Extracts and analyzes regression tests from patches.
Enhanced with LLM for test intent understanding and PoC simplification.
"""

import re
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TestCase:
    """Represents a test case extracted from patch."""
    file_path: str
    test_name: str
    code: str
    language: str
    is_regression_test: bool
    markers: List[str]


@dataclass
class TestAnalysis:
    """Results from deep test analysis."""
    test_intent: str
    minimal_steps: List[str]
    critical_values: Dict[str, Any]
    simplified_poc: str
    confidence: float


class RegressionTestAnalyzer:
    """
    Analyzes regression tests from patches.
    
    Enhanced with LLM for:
    - Understanding test intent
    - Extracting minimal trigger conditions
    - Generating simplified PoCs
    """
    
    # Patterns to identify regression tests
    REGRESSION_MARKERS = [
        r"chromium\.org.*issues/\d+",
        r"CVE-\d{4}-\d+",
        r"security.*test",
    ]
    
    def __init__(self, llm_service=None):
        """
        Initialize analyzer.
        
        Args:
            llm_service: Optional LLM service for deep analysis
        """
        self.llm_service = llm_service
        self._analysis_cache = {}
        
        # NEW: Initialize C++ to JS converter (Phase 3.3)
        self._cpp_converter = None
        try:
            from .cpp_to_js_converter import CppToJsConverter
            self._cpp_converter = CppToJsConverter(llm_service)
            logger.info("C++ to JavaScript converter initialized")
        except ImportError:
            logger.warning("CppToJsConverter not available")
    
    def extract_from_patch(self, patch_diff: str, patch_info: Dict[str, Any]) -> List[TestCase]:
        """
        Extract regression tests from a patch.
        
        Args:
            patch_diff: The patch diff content
            patch_info: Patch metadata (commit hash, files changed, etc.)
            
        Returns:
            List of extracted test cases
        """
        test_cases = []
        
        # 1. Identify test files in the patch
        test_files = self._identify_test_files(patch_diff, patch_info)
        
        logger.info(f"Found {len(test_files)} test files in patch")
        
        # 2. Extract test code from each file
        for file_path in test_files:
            cases = self._extract_tests_from_file(patch_diff, file_path)
            test_cases.extend(cases)
        
        # 3. Filter for regression tests
        regression_tests = [tc for tc in test_cases if self._is_regression_test(tc)]
        
        logger.info(f"Extracted {len(regression_tests)} regression tests")
        
        return regression_tests
    
    def _identify_test_files(self, patch_diff: str, patch_info: Dict[str, Any]) -> List[str]:
        """Identify test files in the patch."""
        test_files = []
        
        # Get files changed from patch info
        files_changed = patch_info.get("files_changed", [])
        
        # Check each file against test patterns
        for file_path in files_changed:
            if self._is_test_file(file_path):
                test_files.append(file_path)
        
        # Also extract from diff headers
        diff_files = re.findall(r'diff --git a/(.*?) b/', patch_diff)
        for file_path in diff_files:
            if self._is_test_file(file_path) and file_path not in test_files:
                test_files.append(file_path)
        
        return test_files
    
    def _is_test_file(self, file_path: str) -> bool:
        """Check if a file is a test file."""
        for pattern in self.TEST_FILE_PATTERNS:
            if re.search(pattern, file_path, re.I):
                return True
        return False
    
    def _extract_tests_from_file(self, patch_diff: str, file_path: str) -> List[TestCase]:
        """Extract test cases from a specific file in the patch."""
        test_cases = []
        
        # Find the section of the diff for this file
        file_pattern = rf"diff --git a/{re.escape(file_path)}.*?(?=diff --git|$)"
        file_match = re.search(file_pattern, patch_diff, re.DOTALL)
        
        if not file_match:
            return test_cases
        
        file_diff = file_match.group(0)
        
        # Determine language
        language = self._detect_language(file_path)
        
        # Extract added code (lines starting with +)
        added_lines = []
        for line in file_diff.split('\n'):
            if line.startswith('+') and not line.startswith('+++'):
                # Remove the + prefix
                added_lines.append(line[1:])
        
        if not added_lines:
            return test_cases
        
        # Join added lines to form test code
        test_code = '\n'.join(added_lines)
        
        # Extract test name if possible
        test_name = self._extract_test_name(test_code, language)
        
        # Create test case
        test_case = TestCase(
            file_path=file_path,
            test_name=test_name or f"test_from_{file_path.split('/')[-1]}",
            code=test_code,
            language=language,
            description=f"Extracted from {file_path}",
        )
        
        test_cases.append(test_case)
        
        return test_cases
    
    def _detect_language(self, file_path: str) -> str:
        """Detect language from file extension."""
        if file_path.endswith('.js'):
            return 'javascript'
        elif file_path.endswith('.html'):
            return 'html'
        elif file_path.endswith(('.cc', '.cpp', '.h')):
            return 'cpp'
        else:
            return 'unknown'
    
    def _extract_test_name(self, code: str, language: str) -> Optional[str]:
        """Extract test name from code."""
        if language == 'javascript':
            # Look for test function names
            match = re.search(r'function\s+(\w+)\s*\(', code)
            if match:
                return match.group(1)
        
        elif language == 'cpp':
            # Look for TEST or TEST_F macros
            match = re.search(r'TEST(?:_F)?\s*\(\s*\w+\s*,\s*(\w+)\s*\)', code)
            if match:
                return match.group(1)
        
        return None
    
    def _is_regression_test(self, test_case: TestCase) -> bool:
        """Check if a test case is a regression test."""
        # Check file path
        if 'regress' in test_case.file_path.lower():
            return True
        
        # Check test name
        if test_case.test_name and 'regress' in test_case.test_name.lower():
            return True
        
        # Check code for regression markers
        for marker in self.REGRESSION_MARKERS:
            if re.search(marker, test_case.code, re.I):
                return True
        
        return False
    
    def convert_to_poc(self, test_case: TestCase) -> Dict[str, Any]:
        """
        Convert a test case to a standalone PoC.
        
        Args:
            test_case: Test case to convert
            
        Returns:
            PoC dictionary
        """
        if test_case.language == 'javascript':
            return self._convert_js_test_to_poc(test_case)
        elif test_case.language == 'html':
            return self._convert_html_test_to_poc(test_case)
        elif test_case.language == 'cpp':
            return self._convert_cpp_test_to_poc(test_case)
        else:
            return {
                "code": test_case.code,
                "language": test_case.language,
                "source": "regression_test",
                "test_name": test_case.test_name,
            }
    
    def _convert_js_test_to_poc(self, test_case: TestCase) -> Dict[str, Any]:
        """Convert JavaScript test to PoC."""
        code = test_case.code
        
        # Remove test framework boilerplate
        code = self._remove_test_boilerplate(code)
        
        # Add V8 debugging helpers if not present
        if '%' not in code:
            preamble = """
// V8 debugging helpers
// Run with: d8 --allow-natives-syntax poc.js

"""
            code = preamble + code
        
        return {
            "code": code,
            "language": "javascript",
            "source": "regression_test",
            "test_name": test_case.test_name,
            "file_path": test_case.file_path,
        }
    
    def _convert_html_test_to_poc(self, test_case: TestCase) -> Dict[str, Any]:
        """Convert HTML test to PoC."""
        code = test_case.code
        
        # If it's a complete HTML file, use as-is
        if '<html' in code.lower():
            return {
                "code": code,
                "language": "html",
                "source": "regression_test",
                "test_name": test_case.test_name,
            }
        
        # Otherwise, wrap in minimal HTML
        wrapped = f"""<!DOCTYPE html>
<html>
<head>
    <title>{test_case.test_name} - Regression Test PoC</title>
</head>
<body>
    <h1>{test_case.test_name}</h1>
    <div id="test-output"></div>
    
    {code}
</body>
</html>"""
        
        return {
            "code": wrapped,
            "language": "html",
            "source": "regression_test",
            "test_name": test_case.test_name,
        }
    
    def _convert_cpp_test_to_poc(self, test_case: TestCase) -> Dict[str, Any]:
        """
        Convert C++ test to PoC.
        
        Enhanced with C++ to JavaScript converter (Phase 3.3).
        """
        code = test_case.code
        
        # Try automatic conversion if converter available
        if self._cpp_converter and self._cpp_converter.can_convert(code):
            logger.info(f"Attempting C++ to JavaScript conversion for {test_case.test_name}")
            js_code = self._cpp_converter.convert(code)
            
            if js_code:
                return {
                    "code": js_code,
                    "language": "javascript",
                    "source": "regression_test_cpp_converted",
                    "test_name": test_case.test_name,
                    "original_language": "cpp",
                    "conversion_method": "automatic",
                }
        
        # Fallback: return C++ code with note
        return {
            "code": code,
            "language": "cpp",
            "source": "regression_test",
            "test_name": test_case.test_name,
            "note": "C++ test - automatic conversion not available, may need manual conversion",
        }
    
    def _remove_test_boilerplate(self, code: str) -> str:
        """Remove common test framework boilerplate."""
        # Remove common test assertions
        code = re.sub(r'assertEquals?\s*\([^)]+\)\s*;?', '', code)
        code = re.sub(r'assertTrue?\s*\([^)]+\)\s*;?', '', code)
        code = re.sub(r'assertFalse?\s*\([^)]+\)\s*;?', '', code)
        
        # Remove test framework imports
        code = re.sub(r'import\s+.*test.*', '', code, flags=re.I)
        
        # Clean up extra whitespace
        code = re.sub(r'\n\s*\n\s*\n', '\n\n', code)
        
        return code.strip()
    
    def analyze_test_coverage(self, test_cases: List[TestCase]) -> Dict[str, Any]:
        """
        Analyze test coverage and quality.
        
        Returns:
            Analysis of test cases
        """
        return {
            "total_tests": len(test_cases),
            "by_language": self._count_by_language(test_cases),
            "regression_tests": sum(1 for tc in test_cases if tc.is_regression_test),
            "test_files": list(set(tc.file_path for tc in test_cases)),
        }
    
    def _count_by_language(self, test_cases: List[TestCase]) -> Dict[str, int]:
        """Count test cases by language."""
        counts = {}
        for tc in test_cases:
            counts[tc.language] = counts.get(tc.language, 0) + 1
        return counts
