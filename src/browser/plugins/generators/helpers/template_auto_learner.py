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
        
        import tempfile
        import os
        from pathlib import Path
        
        try:
            # 1. Creating temp JavaScript file
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.js',
                delete=False,
                encoding='utf-8'
            ) as f:
                f.write(poc_code)
                temp_js_path = f.name
            
            # 2. Creating CodeQL database
            temp_db_dir = tempfile.mkdtemp(prefix='codeql_poc_')
            
            try:
                logger.debug(f"Creating CodeQL database at {temp_db_dir}")
                success = self.codeql_service.create_database(
                    source_path=os.path.dirname(temp_js_path),
                    language='javascript',
                    db_path=temp_db_dir
                )
                
                if not success:
                    logger.warning("Failed to create CodeQL database, falling back to heuristics")
                    return self._extract_pattern_heuristic(poc_code)
                
                # 3. Running custom queries to extract patterns
                query_dir = Path(__file__).parent.parent.parent.parent / 'codeql_queries' / 'js'
                
                key_ops = []
                control_flow = []
                constants = []
                
                # Run JIT patterns query
                jit_query = query_dir / 'extract_jit_patterns.ql'
                if jit_query.exists():
                    jit_result = self.codeql_service.run_query(
                        str(jit_query),
                        db_path=temp_db_dir
                    )
                    if jit_result.success and jit_result.results:
                        key_ops.extend(['jit_optimization', 'trigger_loop'])
                        logger.debug(f"Found {len(jit_result.results)} JIT patterns")
                
                # Run GC triggers query
                gc_query = query_dir / 'extract_gc_triggers.ql'
                if gc_query.exists():
                    gc_result = self.codeql_service.run_query(
                        str(gc_query),
                        db_path=temp_db_dir
                    )
                    if gc_result.success and gc_result.results:
                        for result in gc_result.results:
                            if 'ArrayBuffer' in str(result):
                                key_ops.append('ArrayBuffer')
                            if 'TypedArray' in str(result):
                                key_ops.append('TypedArray')
                            if 'gc' in str(result).lower():
                                key_ops.append('gc')
                        logger.debug(f"Found {len(gc_result.results)} GC patterns")
                
                # Run control flow query
                cf_query = query_dir / 'extract_control_flow.ql'
                if cf_query.exists():
                    cf_result = self.codeql_service.run_query(
                        str(cf_query),
                        db_path=temp_db_dir
                    )
                    if cf_result.success and cf_result.results:
                        control_flow.extend(['nested_loop', 'conditional'])
                        logger.debug(f"Found {len(cf_result.results)} control flow patterns")
                
                # Fallback to heuristic for constants extraction
                heuristic_pattern = self._extract_pattern_heuristic(poc_code)
                constants = heuristic_pattern.constants
                
                # Merge with heuristic results if CodeQL found nothing
                if not key_ops:
                    key_ops = heuristic_pattern.key_operations
                if not control_flow:
                    control_flow = heuristic_pattern.control_flow
                
                return Pattern(
                    code=poc_code,
                    key_operations=list(set(key_ops)),  # Deduplicate
                    control_flow=list(set(control_flow)),
                    constants=constants
                )
                
            finally:
                # Cleanup
                import shutil
                if os.path.exists(temp_db_dir):
                    shutil.rmtree(temp_db_dir, ignore_errors=True)
                if os.path.exists(temp_js_path):
                    os.remove(temp_js_path)
                    
        except Exception as e:
            logger.error(f"CodeQL extraction failed: {e}")
            logger.debug("Falling back to heuristic extraction")
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
        Identify parameterizable values using semantic analysis.
        
        Args:
            pattern: Extracted pattern
            
        Returns:
            List of parameter names with semantic meaning
        """
        params = []
        seen_params = set()
        
        # Analyze code context to understand parameter semantics
        code_lower = pattern.code.lower()
        
        # 1. Analyze constants in context
        for const in pattern.constants:
            value = const["value"]
            position = const["position"]
            
            # Get surrounding context (50 chars before and after)
            start = max(0, position - 50)
            end = min(len(pattern.code), position + len(value) + 50)
            context = pattern.code[start:end].lower()
            
            param_name = self._classify_constant_by_context(value, context, pattern)
            
            if param_name and param_name not in seen_params:
                params.append(param_name)
                seen_params.add(param_name)
        
        # 2. Infer parameters from key operations
        operation_params = self._infer_params_from_operations(pattern)
        for param in operation_params:
            if param not in seen_params:
                params.append(param)
                seen_params.add(param)
        
        # 3. Infer parameters from control flow
        control_params = self._infer_params_from_control_flow(pattern)
        for param in control_params:
            if param not in seen_params:
                params.append(param)
                seen_params.add(param)
        
        # Limit to reasonable number of parameters
        return params[:8]  # Max 8 params for template clarity
    
    def _classify_constant_by_context(
        self,
        value: str,
        context: str,
        pattern: Pattern
    ) -> str:
        """
        Classify a constant based on its usage context.
        
        Args:
            value: The constant value
            context: Surrounding code context
            pattern: Full pattern for additional analysis
            
        Returns:
            Semantic parameter name
        """
        # Hexadecimal values
        if value.startswith("0x"):
            try:
                num_value = int(value, 16)
                
                # Memory addresses or large buffers
                if num_value >= 0x10000:
                    if 'arraybuffer' in context or 'buffer' in context:
                        return 'buffer_size'
                    elif 'address' in context or 'ptr' in context:
                        return 'target_address'
                    else:
                        return 'heap_size'
                
                # Offsets or small values
                elif num_value < 0x1000:
                    if 'offset' in context or '[' in context:
                        return 'array_offset'
                    elif 'index' in context:
                        return 'array_index'
                    else:
                        return 'magic_value'
                
                # Medium range - likely sizes or counts
                else:
                    if 'length' in context or 'size' in context:
                        return 'allocation_size'
                    else:
                        return 'spray_count'
                        
            except ValueError:
                return 'hex_constant'
        
        # Decimal values
        elif value.isdigit():
            num_value = int(value)
            
            # Large iteration counts (JIT triggers)
            if num_value >= 10000:
                if 'for' in context or 'while' in context:
                    return 'jit_iterations'
                else:
                    return 'trigger_count'
            
            # Medium counts (spray/allocation)
            elif num_value >= 100:
                if 'new' in context or 'array' in context:
                    return 'spray_count'
                elif 'for' in context:
                    return 'loop_count'
                else:
                    return 'allocation_count'
            
            # Small values (indices, offsets)
            elif num_value >= 0:
                if '[' in context or 'index' in context:
                    return 'array_index'
                elif 'length' in context:
                    return 'array_length'
                else:
                    return 'small_constant'
            
            # Negative values (underflow triggers)
            else:
                return 'negative_offset'
        
        # String or other constants
        else:
            return 'string_constant'
    
    def _infer_params_from_operations(self, pattern: Pattern) -> List[str]:
        """
        Infer parameters based on key operations in the pattern.
        
        Args:
            pattern: Extracted pattern
            
        Returns:
            List of inferred parameter names
        """
        params = []
        
        # JIT optimization patterns need iteration count
        if 'jit_optimization' in pattern.key_operations or '%Optimize' in pattern.key_operations:
            if 'jit_iterations' not in params:
                params.append('jit_iterations')
        
        # GC patterns need allocation size
        if 'gc' in pattern.key_operations:
            if 'allocation_size' not in params:
                params.append('allocation_size')
        
        # ArrayBuffer patterns need buffer size
        if 'ArrayBuffer' in pattern.key_operations:
            if 'buffer_size' not in params:
                params.append('buffer_size')
        
        # TypedArray patterns need array length
        if 'TypedArray' in pattern.key_operations:
            if 'array_length' not in params:
                params.append('array_length')
        
        return params
    
    def _infer_params_from_control_flow(self, pattern: Pattern) -> List[str]:
        """
        Infer parameters based on control flow patterns.
        
        Args:
            pattern: Extracted pattern
            
        Returns:
            List of inferred parameter names
        """
        params = []
        
        # Nested loops suggest spray or trigger patterns
        if 'nested_loop' in pattern.control_flow:
            params.append('outer_loop_count')
            params.append('inner_loop_count')
        
        # Simple loops suggest iteration-based triggers
        elif 'loop' in pattern.control_flow:
            params.append('loop_iterations')
        
        # Conditionals suggest threshold or check values
        if 'conditional' in pattern.control_flow:
            params.append('threshold_value')
        
        return params
    
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
