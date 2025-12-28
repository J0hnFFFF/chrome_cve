"""
Code Context Fetcher

Retrieves code context (function definitions, class context) from Gitiles
to provide better context for LLM patch analysis.
"""

import re
import base64
import logging
import requests
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FunctionContext:
    """Context for a function."""
    function_name: str
    file_path: str
    start_line: int
    end_line: int
    code: str
    language: str


class CodeContextFetcher:
    """
    Fetches code context from Gitiles.
    
    Capabilities:
    - Fetch complete file content
    - Extract function definitions
    - Get surrounding context
    """
    
    GITILES_BASE = "https://chromium.googlesource.com"
    
    def __init__(self, timeout: int = 30):
        """
        Initialize context fetcher.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self._file_cache = {}
    
    def fetch_function_context(
        self,
        repository: str,
        commit: str,
        file_path: str,
        function_name: str,
        context_lines: int = 10
    ) -> Optional[FunctionContext]:
        """
        Fetch function context from Gitiles.
        
        Args:
            repository: Repository path (e.g., 'chromium/src')
            commit: Commit hash
            file_path: File path in repository
            function_name: Function name to find
            context_lines: Extra lines before/after function
            
        Returns:
            FunctionContext or None if not found
        """
        # Get file content
        file_content = self._fetch_file_content(repository, commit, file_path)
        if not file_content:
            return None
        
        # Detect language
        language = self._detect_language(file_path)
        
        # Extract function
        if language == "cpp":
            return self._extract_cpp_function(
                file_content, file_path, function_name, context_lines
            )
        elif language == "javascript":
            return self._extract_js_function(
                file_content, file_path, function_name, context_lines
            )
        else:
            logger.warning(f"Unsupported language for {file_path}")
            return None
    
    def fetch_functions_from_diff(
        self,
        repository: str,
        commit: str,
        patch_diff: str,
        max_functions: int = 5
    ) -> List[FunctionContext]:
        """
        Extract function contexts from patch diff.
        
        Args:
            repository: Repository path
            commit: Commit hash
            patch_diff: Patch diff content
            max_functions: Maximum functions to extract
            
        Returns:
            List of FunctionContext objects
        """
        contexts = []
        
        # Parse diff to find modified functions
        modified_functions = self._parse_diff_for_functions(patch_diff)
        
        for file_path, function_name in modified_functions[:max_functions]:
            context = self.fetch_function_context(
                repository, commit, file_path, function_name
            )
            if context:
                contexts.append(context)
        
        return contexts
    
    def _fetch_file_content(
        self,
        repository: str,
        commit: str,
        file_path: str
    ) -> Optional[str]:
        """Fetch file content from Gitiles."""
        cache_key = f"{repository}:{commit}:{file_path}"
        
        # Check cache
        if cache_key in self._file_cache:
            return self._file_cache[cache_key]
        
        try:
            url = f"{self.GITILES_BASE}/{repository}/+/{commit}/{file_path}?format=TEXT"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code != 200:
                logger.warning(f"Failed to fetch {file_path}: {response.status_code}")
                return None
            
            # Decode base64 content
            content = base64.b64decode(response.content).decode('utf-8', errors='ignore')
            
            # Cache result
            self._file_cache[cache_key] = content
            
            return content
            
        except Exception as e:
            logger.error(f"Error fetching file content: {e}")
            return None
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        if file_path.endswith(('.cc', '.cpp', '.h', '.hpp')):
            return "cpp"
        elif file_path.endswith(('.js', '.mjs')):
            return "javascript"
        elif file_path.endswith('.py'):
            return "python"
        else:
            return "unknown"
    
    def _extract_cpp_function(
        self,
        file_content: str,
        file_path: str,
        function_name: str,
        context_lines: int = 10
    ) -> Optional[FunctionContext]:
        """
        Extract C++ function using heuristics.
        
        Simple approach:
        1. Find function signature
        2. Track braces to find function end
        3. Extract code block
        """
        lines = file_content.split('\n')
        
        # Find function signature
        # Pattern: return_type function_name(params) {
        # or: return_type ClassName::function_name(params) {
        pattern = rf'\b{re.escape(function_name)}\s*\('
        
        start_line = None
        for i, line in enumerate(lines):
            if re.search(pattern, line):
                start_line = i
                break
        
        if start_line is None:
            logger.debug(f"Function {function_name} not found in {file_path}")
            return None
        
        # Find function body start (opening brace)
        body_start = start_line
        for i in range(start_line, min(start_line + 10, len(lines))):
            if '{' in lines[i]:
                body_start = i
                break
        
        # Track braces to find function end
        brace_count = 0
        end_line = body_start
        
        for i in range(body_start, len(lines)):
            line = lines[i]
            brace_count += line.count('{')
            brace_count -= line.count('}')
            
            if brace_count == 0 and '{' in lines[body_start]:
                end_line = i
                break
        
        # Add context lines
        context_start = max(0, start_line - context_lines)
        context_end = min(len(lines), end_line + context_lines + 1)
        
        # Extract code
        code = '\n'.join(lines[context_start:context_end])
        
        return FunctionContext(
            function_name=function_name,
            file_path=file_path,
            start_line=context_start + 1,  # 1-indexed
            end_line=context_end,
            code=code,
            language="cpp"
        )
    
    def _extract_js_function(
        self,
        file_content: str,
        file_path: str,
        function_name: str,
        context_lines: int = 10
    ) -> Optional[FunctionContext]:
        """Extract JavaScript function."""
        lines = file_content.split('\n')
        
        # Pattern: function name(...) { or const name = (...) => {
        patterns = [
            rf'function\s+{re.escape(function_name)}\s*\(',
            rf'const\s+{re.escape(function_name)}\s*=',
            rf'let\s+{re.escape(function_name)}\s*=',
            rf'{re.escape(function_name)}\s*:\s*function',
        ]
        
        start_line = None
        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    start_line = i
                    break
            if start_line is not None:
                break
        
        if start_line is None:
            return None
        
        # Find function end (simplified - track braces)
        brace_count = 0
        end_line = start_line
        
        for i in range(start_line, len(lines)):
            line = lines[i]
            brace_count += line.count('{')
            brace_count -= line.count('}')
            
            if brace_count == 0 and '{' in lines[start_line:i+1]:
                end_line = i
                break
        
        # Add context
        context_start = max(0, start_line - context_lines)
        context_end = min(len(lines), end_line + context_lines + 1)
        
        code = '\n'.join(lines[context_start:context_end])
        
        return FunctionContext(
            function_name=function_name,
            file_path=file_path,
            start_line=context_start + 1,
            end_line=context_end,
            code=code,
            language="javascript"
        )
    
    def _parse_diff_for_functions(self, patch_diff: str) -> List[Tuple[str, str]]:
        """
        Parse diff to find modified functions.
        
        Returns:
            List of (file_path, function_name) tuples
        """
        functions = []
        current_file = None
        
        for line in patch_diff.split('\n'):
            # Track current file
            if line.startswith('diff --git'):
                match = re.search(r'b/(.*?)$', line)
                if match:
                    current_file = match.group(1)
            
            # Extract function from @@ line
            elif line.startswith('@@') and current_file:
                # Format: @@ -start,count +start,count @@ function_name
                match = re.search(r'@@.*@@\s+(.*)', line)
                if match:
                    func_info = match.group(1).strip()
                    # Extract function name (before '(')
                    func_match = re.search(r'(\w+)\s*\(', func_info)
                    if func_match:
                        function_name = func_match.group(1)
                        functions.append((current_file, function_name))
        
        # Deduplicate
        return list(set(functions))
    
    def format_context_for_llm(self, contexts: List[FunctionContext]) -> str:
        """
        Format function contexts for LLM consumption.
        
        Args:
            contexts: List of FunctionContext objects
            
        Returns:
            Formatted string for LLM prompt
        """
        if not contexts:
            return "No function context available."
        
        parts = []
        for ctx in contexts:
            parts.append(f"""
Function: {ctx.function_name}
File: {ctx.file_path} (lines {ctx.start_line}-{ctx.end_line})
Language: {ctx.language}

```{ctx.language}
{ctx.code}
```
""")
        
        return "\n---\n".join(parts)
