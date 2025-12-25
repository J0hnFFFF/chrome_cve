"""
Knowledge Loader

Bridges existing knowledge files to the new SemanticMemory system.
Provides automatic loading and synchronization.
"""

from typing import Dict, List, Optional
from .semantic import SemanticMemory, ComponentKnowledge, VulnTypeKnowledge


class KnowledgeLoader:
    """
    Loads knowledge from browser/knowledge/ into SemanticMemory.

    This bridges the existing static knowledge files with the new
    dynamic memory system.
    """

    def __init__(self, semantic_memory: SemanticMemory):
        self.memory = semantic_memory

    def load_all(self) -> int:
        """
        Load all knowledge into semantic memory.

        Returns:
            Number of knowledge items loaded
        """
        count = 0
        count += self._load_component_knowledge()
        count += self._load_vulnerability_types()
        return count

    def _load_component_knowledge(self) -> int:
        """Load component knowledge from browser/knowledge/."""
        try:
            from ..knowledge import (
                V8_OVERVIEW, V8_VULNERABILITY_PATTERNS, V8_DEBUGGING,
                V8_EXPLOITATION_PRIMITIVES, V8_OBJECT_MODEL, V8_JIT_KNOWLEDGE,
                BLINK_OVERVIEW, BLINK_VULNERABILITY_PATTERNS, BLINK_DEBUGGING,
                BLINK_EXPLOITATION_PRIMITIVES, BLINK_DOM_KNOWLEDGE,
                SKIA_OVERVIEW, SKIA_VULNERABILITY_PATTERNS, SKIA_DEBUGGING,
                SKIA_EXPLOITATION,
                PDFIUM_OVERVIEW, PDFIUM_VULNERABILITY_PATTERNS, PDFIUM_DEBUGGING,
                PDFIUM_EXPLOITATION,
                WEBRTC_OVERVIEW, WEBRTC_VULNERABILITY_PATTERNS, WEBRTC_DEBUGGING,
                WEBRTC_EXPLOITATION,
                NETWORK_OVERVIEW, NETWORK_VULNERABILITY_PATTERNS, NETWORK_DEBUGGING,
                NETWORK_EXPLOITATION,
                WEBGL_OVERVIEW, WEBGL_VULNERABILITY_PATTERNS, WEBGL_DEBUGGING,
                WEBGL_EXPLOITATION, WEBGL_ARCHITECTURE,
                WASM_OVERVIEW, WASM_VULNERABILITY_PATTERNS, WASM_DEBUGGING,
                WASM_EXPLOITATION, WASM_BINARY_FORMAT,
            )

            components = [
                ComponentKnowledge(
                    name="v8",
                    overview=V8_OVERVIEW,
                    architecture=V8_OBJECT_MODEL + "\n\n" + V8_JIT_KNOWLEDGE,
                    vulnerability_patterns=V8_VULNERABILITY_PATTERNS,
                    debugging_guide=V8_DEBUGGING,
                    exploitation_primitives=V8_EXPLOITATION_PRIMITIVES,
                ),
                ComponentKnowledge(
                    name="blink",
                    overview=BLINK_OVERVIEW,
                    architecture=BLINK_DOM_KNOWLEDGE,
                    vulnerability_patterns=BLINK_VULNERABILITY_PATTERNS,
                    debugging_guide=BLINK_DEBUGGING,
                    exploitation_primitives=BLINK_EXPLOITATION_PRIMITIVES,
                ),
                ComponentKnowledge(
                    name="skia",
                    overview=SKIA_OVERVIEW,
                    vulnerability_patterns=SKIA_VULNERABILITY_PATTERNS,
                    debugging_guide=SKIA_DEBUGGING,
                    exploitation_primitives=SKIA_EXPLOITATION,
                ),
                ComponentKnowledge(
                    name="pdfium",
                    overview=PDFIUM_OVERVIEW,
                    vulnerability_patterns=PDFIUM_VULNERABILITY_PATTERNS,
                    debugging_guide=PDFIUM_DEBUGGING,
                    exploitation_primitives=PDFIUM_EXPLOITATION,
                ),
                ComponentKnowledge(
                    name="webrtc",
                    overview=WEBRTC_OVERVIEW,
                    vulnerability_patterns=WEBRTC_VULNERABILITY_PATTERNS,
                    debugging_guide=WEBRTC_DEBUGGING,
                    exploitation_primitives=WEBRTC_EXPLOITATION,
                ),
                ComponentKnowledge(
                    name="network",
                    overview=NETWORK_OVERVIEW,
                    vulnerability_patterns=NETWORK_VULNERABILITY_PATTERNS,
                    debugging_guide=NETWORK_DEBUGGING,
                    exploitation_primitives=NETWORK_EXPLOITATION,
                ),
                ComponentKnowledge(
                    name="webgl",
                    overview=WEBGL_OVERVIEW,
                    architecture=WEBGL_ARCHITECTURE,
                    vulnerability_patterns=WEBGL_VULNERABILITY_PATTERNS,
                    debugging_guide=WEBGL_DEBUGGING,
                    exploitation_primitives=WEBGL_EXPLOITATION,
                ),
                ComponentKnowledge(
                    name="wasm",
                    overview=WASM_OVERVIEW,
                    architecture=WASM_BINARY_FORMAT,
                    vulnerability_patterns=WASM_VULNERABILITY_PATTERNS,
                    debugging_guide=WASM_DEBUGGING,
                    exploitation_primitives=WASM_EXPLOITATION,
                ),
            ]

            for ck in components:
                self.memory.save_component_knowledge(ck)

            return len(components)

        except ImportError as e:
            print(f"Warning: Could not import knowledge modules: {e}")
            return 0

    def _load_vulnerability_types(self) -> int:
        """Load common vulnerability type knowledge."""
        vuln_types = [
            VulnTypeKnowledge(
                name="type-confusion",
                description="""
Type Confusion vulnerabilities occur when code doesn't properly verify object types
before performing operations that assume a specific type.

In V8/JavaScript:
- JIT compiler assumes wrong type during optimization
- Turbofan speculative optimizations based on incorrect feedback

In Blink/C++:
- Invalid casts between DOM element types
- Template instantiation with wrong types
""",
                trigger_patterns=[
                    "Create objects that change type after JIT compilation",
                    "Use Object.defineProperty to change object layout",
                    "Trigger deoptimization after type assumption",
                    "Polymorphic call sites with unexpected types",
                ],
                poc_templates=[
                    "function trigger() { let obj = {}; obj.a = 1; return obj; }",
                    "// Force JIT compilation with consistent types",
                    "for (let i = 0; i < 10000; i++) trigger();",
                    "// Now trigger type confusion",
                ],
                exploitation_steps=[
                    "Identify the confused types and their memory layouts",
                    "Create fake object with controlled data at expected offsets",
                    "Use type confusion to read/write arbitrary memory",
                    "Build addrof/fakeobj primitives",
                    "Achieve code execution via WASM or JIT spray",
                ],
            ),
            VulnTypeKnowledge(
                name="use-after-free",
                description="""
Use-After-Free (UAF) vulnerabilities occur when memory is accessed after being freed.

Common patterns:
- Event handlers accessing freed objects
- Callbacks executing after object destruction
- Race conditions in garbage collection
- Incorrect reference counting
""",
                trigger_patterns=[
                    "Register callbacks, trigger free, then trigger callback",
                    "Use nested event handlers to cause re-entrancy",
                    "Exploit GC timing with WeakRef or FinalizationRegistry",
                    "Create complex object graphs with cycles",
                ],
                poc_templates=[
                    "let obj = new VulnerableObject();",
                    "obj.addEventListener('event', () => { /* access freed memory */ });",
                    "obj.free(); // or trigger GC",
                    "obj.dispatchEvent(new Event('event'));",
                ],
                exploitation_steps=[
                    "Trigger the UAF to understand timing",
                    "Spray heap with controlled objects same size as freed object",
                    "Read freed memory to leak pointers",
                    "Write to freed memory to corrupt objects",
                    "Chain into type confusion or other primitives",
                ],
            ),
            VulnTypeKnowledge(
                name="heap-buffer-overflow",
                description="""
Heap buffer overflow occurs when data is written beyond allocated heap memory bounds.

Common causes:
- Integer overflow in size calculations
- Off-by-one errors in loops
- Missing bounds checks in array operations
- Incorrect length handling in string operations
""",
                trigger_patterns=[
                    "Provide oversized input to trigger overflow",
                    "Use integer overflow to create small buffer",
                    "Exploit length confusion between encodings (UTF-8 vs UTF-16)",
                    "Create arrays near integer max then add elements",
                ],
                poc_templates=[
                    "let arr = new Array(0x7fffffff); // Large array",
                    "arr.push(1); // Trigger overflow",
                ],
                exploitation_steps=[
                    "Identify overflow direction and controllable bytes",
                    "Heap groom to place target object after buffer",
                    "Overflow into adjacent object's header/data",
                    "Corrupt vtable or inline data pointers",
                    "Gain arbitrary read/write primitive",
                ],
            ),
            VulnTypeKnowledge(
                name="integer-overflow",
                description="""
Integer overflow occurs when arithmetic operations exceed integer bounds,
causing wraparound or truncation that leads to incorrect behavior.

Impact:
- Small buffer allocation leading to heap overflow
- Incorrect bounds checks
- Wrong array indices
""",
                trigger_patterns=[
                    "Multiply large numbers to wrap around",
                    "Add to numbers near MAX_INT",
                    "Truncation between 64-bit and 32-bit values",
                    "Signed/unsigned confusion in comparisons",
                ],
                poc_templates=[
                    "let size = 0x100000001; // Exceeds 32-bit",
                    "let buffer = allocateBuffer(size); // Truncated to 1",
                ],
                exploitation_steps=[
                    "Calculate values that cause desired wraparound",
                    "Use small allocation with large copy/write",
                    "Chain into heap overflow exploitation",
                ],
            ),
            VulnTypeKnowledge(
                name="oob-read-write",
                description="""
Out-of-bounds read/write vulnerabilities allow accessing memory outside
intended array or buffer boundaries.

V8 specific:
- TypedArray with wrong length
- ArrayBuffer detachment issues
- Bounds check elimination bugs in JIT
""",
                trigger_patterns=[
                    "Detach ArrayBuffer while TypedArray is in use",
                    "JIT bounds check elimination with incorrect ranges",
                    "SharedArrayBuffer race conditions",
                    "Negative index handling bugs",
                ],
                poc_templates=[
                    "let ab = new ArrayBuffer(0x100);",
                    "let ta = new Float64Array(ab);",
                    "// Trigger bug that makes ta think it's larger",
                    "ta[0x100] = leaked_value; // OOB write",
                ],
                exploitation_steps=[
                    "Achieve stable OOB access",
                    "Read adjacent object pointers (addrof)",
                    "Write adjacent object fields (fakeobj)",
                    "Build arbitrary R/W from OOB primitive",
                    "RCE via code injection or JIT gadgets",
                ],
            ),
            VulnTypeKnowledge(
                name="race-condition",
                description="""
Race condition vulnerabilities occur when multiple threads or processes
access shared resources without proper synchronization.

Browser contexts:
- Worker threads sharing data
- IPC message handling
- SharedArrayBuffer + Atomics
- DOM mutation during rendering
""",
                trigger_patterns=[
                    "Use SharedArrayBuffer with multiple workers",
                    "Race between main thread and worker",
                    "Exploit timing between IPC messages",
                    "DOM manipulation during style recalculation",
                ],
                poc_templates=[
                    "let sab = new SharedArrayBuffer(0x100);",
                    "let worker = new Worker('worker.js');",
                    "worker.postMessage(sab);",
                    "// Race between threads",
                ],
                exploitation_steps=[
                    "Identify race window and success indicators",
                    "Create tight racing loop for reliability",
                    "Win race to achieve inconsistent state",
                    "Exploit inconsistent state for memory corruption",
                ],
            ),
        ]

        for vk in vuln_types:
            self._save_vuln_knowledge(vk)

        return len(vuln_types)

    def _save_vuln_knowledge(self, vk: VulnTypeKnowledge) -> None:
        """Save vulnerability knowledge to memory."""
        self.memory._vuln_knowledge[vk.name] = vk

        vuln_dir = self.memory.storage_path / "vulnerabilities"
        vuln_dir.mkdir(parents=True, exist_ok=True)

        import json
        file_path = vuln_dir / f"{vk.name}.json"
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump({
                "name": vk.name,
                "description": vk.description,
                "trigger_patterns": vk.trigger_patterns,
                "poc_templates": vk.poc_templates,
                "exploitation_steps": vk.exploitation_steps,
            }, f, indent=2)


def initialize_knowledge(storage_path: str = "./volumes/memory/semantic") -> SemanticMemory:
    """
    Initialize semantic memory with all built-in knowledge.

    Args:
        storage_path: Path to store knowledge files

    Returns:
        Initialized SemanticMemory instance
    """
    memory = SemanticMemory(storage_path)
    loader = KnowledgeLoader(memory)
    count = loader.load_all()
    print(f"Loaded {count} knowledge items into semantic memory")
    return memory
