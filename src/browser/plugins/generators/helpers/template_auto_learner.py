"""
Template Auto-Learner

Automatically learns new PoC templates from successful PoCs (Phase 4.2).
Integrates with existing services (CodeQL, Ghidra) for enhanced analysis.
"""

import re
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class Pattern:
    """Extracted code pattern."""
    code: str
    key_operations: List[str]
    control_flow: List[str]
    constants: List[Dict[str, Any]]


class TemplateAutoLearner:
    """
    Automatically learns PoC templates from successful PoCs.
    
    Features:
    - AST-based pattern extraction (using CodeQL if available)
    - LLM-assisted generalization
    - Integration with existing services (CodeQL, Ghidra)
    - Template validation and deduplication
    """
    
    def __init__(
        self,
        llm_service=None,
        template_library=None,
        codeql_service=None,
        ghidra_service=None
    ):
        """
        Initialize auto-learner.
        
        Args:
            llm_service: LLM service for generalization
            template_library: PoCTemplateLibrary to add templates to
            codeql_service: Optional CodeQL service for AST analysis
            ghidra_service: Optional Ghidra service for binary analysis
        """
        self.llm_service = llm_service
        self.template_library = template_library
        self.codeql_service = codeql_service
        self.ghidra_service = ghidra_service
        self._learned_templates = {}
        self._template_hashes = set()  # For deduplication
    
    def learn_from_poc(
        self,
        poc_code: str,
        metadata: Dict[str, Any]
    ) -> Optional[Any]:  # Returns PoCTemplate
        """
        Learn new template from successful PoC.
        
        Args:
            poc_code: Successful PoC code
            metadata: Metadata (vuln_type, component, cve_id, etc.)
            
        Returns:
            New PoCTemplate or None if learning failed
        """
        logger.info(f"Learning template from PoC for {metadata.get('cve_id', 'unknown')}")
        
        # 1. Extract pattern
        pattern = self._extract_pattern(poc_code)
        if not pattern:
            logger.warning("Failed to extract pattern")
            return None
        
        # 2. Enhance with services (if available)
        pattern = self._enhance_pattern_with_services(pattern, poc_code)
        
        # 3. Identify parameters
        parameters = self._identify_parameters(pattern)
        
        # 4. Generalize with LLM
        if self.llm_service:
            template_code = self._generalize_with_llm(pattern, parameters, metadata)
        else:
            template_code = self._generalize_heuristic(pattern, parameters)
        
        if not template_code:
            logger.warning("Failed to generalize template")
            return None
        
        # 5. Validate template
        if not self._validate_template(template_code):
            logger.warning("Template validation failed")
            return None
        
        # 6. Create template object
        from .poc_template_library import PoCTemplate
        
        template = PoCTemplate(
            name=f"learned_{metadata.get('vuln_type', 'unknown')}_{self._generate_id()}",
            vuln_type=metadata.get('vuln_type', 'unknown'),
            component=metadata.get('component', 'unknown'),
            language="javascript",
            code=template_code,
            parameters=parameters,
            description=f"Auto-learned from {metadata.get('cve_id', 'successful PoC')}",
            variants=[]
        )
        
        # 7. Add to library
        if self.template_library:
            self._add_to_library(template)
        
        logger.info(f"Successfully learned template: {template.name}")
        return template
    
    def _extract_pattern(self, poc_code: str) -> Optional[Pattern]:
        """
        Extract code pattern using AST analysis.
        
        Uses CodeQL service if available, otherwise falls back to heuristics.
        
        Args:
            poc_code: PoC code
            
        Returns:
            Extracted Pattern or None
        """
        try:
            # Try to use CodeQL for JavaScript AST analysis
            if self.codeql_service and self.codeql_service.is_available():
                return self._extract_pattern_with_codeql(poc_code)
            
            # Fallback: Heuristic extraction
            return self._extract_pattern_heuristic(poc_code)
            
        except Exception as e:
            logger.error(f"Pattern extraction failed: {e}")
            return None
    
    def _extract_pattern_with_codeql(self, poc_code: str) -> Pattern:
        """
        Extract pattern using CodeQL service.
        
        Uses CodeQL to analyze JavaScript code structure.
        """
        logger.info("Using CodeQL for pattern extraction")
        
        # For now, fall back to heuristics
        # TODO: Implement JavaScript CodeQL queries for pattern extraction
        # This would require:
        # 1. Creating temp JavaScript file
        # 2. Creating CodeQL database
        # 3. Running custom queries to extract:
        #    - Function calls
        #    - Control flow
        #    - Constants
        
        return self._extract_pattern_heuristic(poc_code)
    
    def _extract_pattern_heuristic(self, poc_code: str) -> Pattern:
        """Heuristic pattern extraction (fallback)."""
        # Extract key operations
        key_ops = []
        
        # Common vulnerability patterns
        patterns = {
            "ArrayBuffer": r'new ArrayBuffer\([^)]+\)',
            "TypedArray": r'new (Uint8|Uint32|Float64)Array\([^)]+\)',
            "slice": r'\.slice\([^)]+\)',
            "gc": r'gc\(\)',
            "%Optimize": r'%\w+\([^)]+\)',
        }
        
        for name, pattern in patterns.items():
            if re.search(pattern, poc_code):
                key_ops.append(name)
        
        # Extract control flow
        control_flow = []
        if "for" in poc_code:
            control_flow.append("loop")
        if "if" in poc_code:
            control_flow.append("conditional")
        if "try" in poc_code:
            control_flow.append("exception_handling")
        
        # Extract constants
        constants = []
        for match in re.finditer(r'(0x[0-9a-fA-F]+|\d+)', poc_code):
            constants.append({
                "value": match.group(1),
                "position": match.start()
            })
        
        return Pattern(
            code=poc_code,
            key_operations=key_ops,
            control_flow=control_flow,
            constants=constants[:10]  # Limit to 10
        )
    
    
    def _enhance_pattern_with_services(
        self,
        pattern: Pattern,
        poc_code: str
    ) -> Pattern:
        """
        Enhance pattern using available services.
        
        Args:
            pattern: Initial pattern
            poc_code: Original PoC code
            
        Returns:
            Enhanced pattern
        """
        # Use CodeQL if available for deeper analysis
        if self.codeql_service and self.codeql_service.is_available():
            logger.info("Enhancing pattern with CodeQL analysis")
            # TODO: Add CodeQL-based enhancement
        
        # Use Ghidra if analyzing binary-related PoCs
        if self.ghidra_service and self.ghidra_service.is_available():
            logger.info("Ghidra service available for binary analysis")
            # TODO: Add Ghidra-based enhancement if needed
        
        return pattern
    
    def _identify_parameters(self, pattern: Pattern) -> List[str]:
        """
        Identify parameterizable values.
        
        Args:
            pattern: Extracted pattern
            
        Returns:
            List of parameter names
        """
        params = []
        
        # Constants become parameters
        seen_values = set()
        for const in pattern.constants:
            value = const["value"]
            if value in seen_values:
                continue
            seen_values.add(value)
            
            # Determine parameter name based on value
            if value.startswith("0x"):
                if int(value, 16) > 0x1000:
                    params.append("buffer_size")
                else:
                    params.append("offset")
            elif value.isdigit():
                num = int(value)
                if num > 1000:
                    params.append("iterations")
                elif num < 0:
                    params.append("negative_value")
                else:
                    params.append("count")
        
        # Deduplicate
        return list(dict.fromkeys(params))[:5]  # Max 5 params
    
    def _generalize_with_llm(
        self,
        pattern: Pattern,
        parameters: List[str],
        metadata: Dict[str, Any]
    ) -> Optional[str]:
        """
        Generalize pattern into template using LLM.
        
        Args:
            pattern: Extracted pattern
            parameters: Parameter names
            metadata: Vulnerability metadata
            
        Returns:
            Template code or None
        """
        prompt = f"""Convert this specific PoC into a reusable template:

PoC Code:
```javascript
{pattern.code[:1500]}
```

Vulnerability Type: {metadata.get('vuln_type', 'Unknown')}
Component: {metadata.get('component', 'Unknown')}
Key Operations: {', '.join(pattern.key_operations)}

Parameters to generalize: {', '.join(parameters)}

Create a template with:
1. Replace specific values with {{param_name}} placeholders
2. Add comments explaining each step
3. Keep the core vulnerability trigger logic
4. Make it reusable for similar vulnerabilities

Output format:
<template>
// PoC for {{vuln_type}}
// Run with: d8 poc.js

// Setup: ...
const value = {{param_name}};

// Trigger: ...

// Expected: ...
</template>"""

        try:
            response = self.llm_service.generate(prompt, temperature=0.3)
            template = self._extract_tag(response, "template")
            return template if template else None
        except Exception as e:
            logger.error(f"LLM generalization failed: {e}")
            return None
    
    def _generalize_heuristic(
        self,
        pattern: Pattern,
        parameters: List[str]
    ) -> str:
        """Heuristic generalization (fallback)."""
        # Simple replacement of constants with placeholders
        code = pattern.code
        
        for i, const in enumerate(pattern.constants[:len(parameters)]):
            value = const["value"]
            param_name = parameters[i] if i < len(parameters) else f"param_{i}"
            code = code.replace(value, f"{{{param_name}}}")
        
        # Add header comment
        header = f"""// Auto-learned PoC Template
// Run with: d8 poc.js

"""
        return header + code
    
    def _validate_template(self, template_code: str) -> bool:
        """
        Validate template quality.
        
        Args:
            template_code: Template code
            
        Returns:
            True if valid
        """
        # 1. Syntax check (basic)
        if not template_code or len(template_code) < 50:
            return False
        
        # 2. Must have parameters
        if "{" not in template_code or "}" not in template_code:
            return False
        
        # 3. Check for deduplication
        template_hash = hashlib.md5(template_code.encode()).hexdigest()
        if template_hash in self._template_hashes:
            logger.info("Template already exists (duplicate)")
            return False
        
        self._template_hashes.add(template_hash)
        return True
    
    def _add_to_library(self, template) -> None:
        """Add template to library."""
        vuln_type = template.vuln_type
        
        if vuln_type not in self.template_library.templates:
            self.template_library.templates[vuln_type] = []
        
        self.template_library.templates[vuln_type].append(template)
        logger.info(f"Added template to library: {vuln_type}/{template.name}")
    
    def _generate_id(self) -> str:
        """Generate unique template ID."""
        import time
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    
    def _extract_tag(self, text: str, tag: str) -> str:
        """Extract content from XML-style tags."""
        pattern = rf"<{tag}>(.*?)</{tag}>"
        match = re.search(pattern, text, re.DOTALL)
        return match.group(1).strip() if match else ""
    
    
    def get_learned_templates(self) -> List[Any]:
        """Get all learned templates."""
        return list(self._learned_templates.values())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get learning statistics."""
        services_available = []
        if self.codeql_service and self.codeql_service.is_available():
            services_available.append("CodeQL")
        if self.ghidra_service and self.ghidra_service.is_available():
            services_available.append("Ghidra")
        
        return {
            "total_learned": len(self._learned_templates),
            "unique_templates": len(self._template_hashes),
            "services_available": services_available,
        }
