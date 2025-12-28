"""
C++ to JavaScript Converter

Converts C++ regression tests to JavaScript PoCs.
Uses LLM assistance and pattern matching.
"""

import re
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class CppToJsConverter:
    """
    Converts C++ tests to JavaScript PoCs.
    
    Strategies:
    1. Pattern-based conversion (simple cases)
    2. LLM-assisted conversion (complex cases)
    """
    
    # Common C++ to JavaScript mappings
    CONVERSION_PATTERNS = {
        # Types
        r'\bHandle<JSArrayBuffer>\b': 'ArrayBuffer',
        r'\bHandle<JSArray>\b': 'Array',
        r'\bHandle<JSObject>\b': 'Object',
        r'\bHandle<String>\b': 'String',
        r'\bint32_t\b': 'number',
        r'\bint64_t\b': 'number',
        r'\buint32_t\b': 'number',
        r'\bdouble\b': 'number',
        r'\bbool\b': 'boolean',
        
        # Functions/Methods
        r'->Slice\(': '.slice(',
        r'->Length\(\)': '.length',
        r'->Get\(': '[',
        r'->Set\(': '[',
        r'CreateBuffer\(': 'new ArrayBuffer(',
        r'CreateArray\(': 'new Array(',
        
        # Test macros
        r'TEST_F?\([^,]+,\s*(\w+)\)': r'function \1()',
        r'EXPECT_TRUE\(': '// Expected: ',
        r'EXPECT_FALSE\(': '// Expected: ',
        r'EXPECT_EQ\(': '// Expected: ',
        r'ASSERT_': '// Assert: ',
        
        # Comments
        r'//\s*': '// ',
    }
    
    def __init__(self, llm_service=None):
        """
        Initialize converter.
        
        Args:
            llm_service: Optional LLM service for complex conversions
        """
        self.llm_service = llm_service
    
    def convert(
        self,
        cpp_code: str,
        analysis: Dict[str, Any] = None
    ) -> Optional[str]:
        """
        Convert C++ test to JavaScript PoC.
        
        Args:
            cpp_code: C++ test code
            analysis: Optional vulnerability analysis for context
            
        Returns:
            JavaScript PoC code or None if conversion failed
        """
        # Try pattern-based conversion first
        js_code = self._pattern_based_convert(cpp_code)
        
        # If LLM available and pattern conversion seems incomplete, use LLM
        if self.llm_service and self._needs_llm_assistance(js_code, cpp_code):
            logger.info("Using LLM for C++ to JavaScript conversion")
            llm_result = self._llm_assisted_convert(cpp_code, analysis)
            if llm_result:
                return llm_result
        
        # Clean up and return pattern-based result
        return self._cleanup_conversion(js_code)
    
    def _pattern_based_convert(self, cpp_code: str) -> str:
        """
        Convert using pattern matching.
        
        Args:
            cpp_code: C++ code
            
        Returns:
            Partially converted JavaScript code
        """
        js_code = cpp_code
        
        # Apply all conversion patterns
        for cpp_pattern, js_replacement in self.CONVERSION_PATTERNS.items():
            js_code = re.sub(cpp_pattern, js_replacement, js_code)
        
        return js_code
    
    def _needs_llm_assistance(self, js_code: str, cpp_code: str) -> bool:
        """
        Determine if LLM assistance is needed.
        
        Indicators:
        - Still contains C++ syntax
        - Complex pointer operations
        - Template usage
        """
        # Check for remaining C++ syntax
        cpp_indicators = [
            r'\bstd::',
            r'\bnamespace\b',
            r'\btemplate\s*<',
            r'\bclass\b',
            r'\bstruct\b',
            r'->\w+\(',  # Pointer method calls
            r'\*\w+',    # Pointer declarations
        ]
        
        for indicator in cpp_indicators:
            if re.search(indicator, js_code):
                return True
        
        # Check if conversion changed enough
        similarity = len(set(js_code.split()) & set(cpp_code.split())) / len(set(cpp_code.split()))
        if similarity > 0.8:  # More than 80% similar
            return True
        
        return False
    
    def _llm_assisted_convert(
        self,
        cpp_code: str,
        analysis: Dict[str, Any] = None
    ) -> Optional[str]:
        """
        Convert using LLM assistance.
        
        Args:
            cpp_code: C++ test code
            analysis: Vulnerability analysis for context
            
        Returns:
            JavaScript PoC or None
        """
        if not self.llm_service:
            return None
        
        # Build context
        context = ""
        if analysis:
            vuln_type = analysis.get("vulnerability_type", "Unknown")
            root_cause = analysis.get("root_cause", "Unknown")
            context = f"""
Vulnerability Context:
- Type: {vuln_type}
- Root Cause: {root_cause}
"""
        
        prompt = f"""Convert this C++ regression test to JavaScript PoC.

C++ Test Code:
```cpp
{cpp_code[:2000]}
```
{context}
Requirements:
1. Find equivalent JavaScript API calls
2. Preserve the vulnerability trigger logic
3. Make it runnable in d8 or Chrome DevTools
4. Remove C++ test framework code (TEST_F, EXPECT_*, etc.)
5. Add comments explaining the conversion

Provide:
<conversion_notes>
Brief explanation of key conversions made
</conversion_notes>

<javascript_poc>
Complete JavaScript PoC code
</javascript_poc>"""

        try:
            response = self.llm_service.generate(prompt, temperature=0.3)
            
            # Extract JavaScript code
            js_code = self._extract_tag(response, "javascript_poc")
            
            if js_code and len(js_code) > 20:
                logger.info("LLM conversion successful")
                return js_code
            else:
                logger.warning("LLM conversion failed to produce valid code")
                return None
                
        except Exception as e:
            logger.error(f"LLM conversion error: {e}")
            return None
    
    def _cleanup_conversion(self, js_code: str) -> str:
        """
        Clean up converted code.
        
        Args:
            js_code: Converted JavaScript code
            
        Returns:
            Cleaned JavaScript code
        """
        # Remove C++ includes
        js_code = re.sub(r'#include\s+[<"].*?[>"]', '', js_code)
        
        # Remove namespace declarations
        js_code = re.sub(r'namespace\s+\w+\s*{', '', js_code)
        js_code = re.sub(r'}\s*//\s*namespace', '', js_code)
        
        # Remove C++ specific keywords
        js_code = re.sub(r'\bvoid\s+', '', js_code)
        js_code = re.sub(r'\bconst\s+', 'const ', js_code)
        
        # Clean up extra whitespace
        js_code = re.sub(r'\n\s*\n\s*\n', '\n\n', js_code)
        
        # Add JavaScript header if not present
        if '// PoC' not in js_code and '// Converted' not in js_code:
            header = "// Converted from C++ regression test\n// Run with: d8 poc.js\n\n"
            js_code = header + js_code
        
        return js_code.strip()
    
    def _extract_tag(self, text: str, tag: str) -> str:
        """Extract content from XML-style tags."""
        pattern = rf"<{tag}>(.*?)</{tag}>"
        match = re.search(pattern, text, re.DOTALL)
        return match.group(1).strip() if match else ""
    
    def can_convert(self, cpp_code: str) -> bool:
        """
        Check if C++ code is likely convertible.
        
        Args:
            cpp_code: C++ code
            
        Returns:
            True if conversion is likely to succeed
        """
        # Check for V8 API usage (good indicator)
        v8_indicators = [
            'JSArrayBuffer',
            'JSArray',
            'JSObject',
            'Handle<',
            'V8_',
        ]
        
        has_v8_api = any(indicator in cpp_code for indicator in v8_indicators)
        
        # Check for test structure
        has_test_structure = bool(re.search(r'TEST_?F?\(', cpp_code))
        
        # Avoid very complex C++ (templates, inheritance, etc.)
        too_complex = bool(re.search(r'template\s*<.*?class.*?>', cpp_code))
        
        return has_v8_api and has_test_structure and not too_complex
