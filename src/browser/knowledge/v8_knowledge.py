"""
V8 JavaScript Engine Knowledge Base

This module contains structured knowledge about V8 internals
for vulnerability analysis and PoC development.
"""

V8_OVERVIEW = """
# V8 JavaScript Engine Overview

V8 is Chrome's JavaScript and WebAssembly engine. Key components:

## Execution Pipeline
1. **Parser**: JavaScript source → AST
2. **Ignition**: AST → Bytecode (interpreter)
3. **Sparkplug**: Fast non-optimizing compiler
4. **Maglev**: Mid-tier optimizing compiler
5. **TurboFan**: Full optimizing compiler

## Memory Model
- **Heap**: Managed memory for JS objects
- **Stack**: Execution stack for function calls
- **Handles**: Safe pointers to heap objects
- **Tagged Pointers**: SMI (small integer) vs HeapObject discrimination
"""

V8_OBJECT_MODEL = """
# V8 Object Model

## Object Representation
- Every object has a Map (hidden class) defining its shape
- Properties stored in-object or in external PropertyArray
- Elements stored in Elements backing store

## Key Object Types
- **JSObject**: Base for all JS objects
- **JSArray**: Arrays with elements backing store
- **JSFunction**: Function objects with code
- **JSTypedArray**: TypedArray views (Uint8Array, etc.)
- **JSArrayBuffer**: Raw binary data buffer

## Maps (Hidden Classes)
- Define property layout and types
- Map transitions create new maps
- Stable maps enable JIT optimization
- Map deprecation can cause security issues

## Elements Kinds
```
PACKED_SMI_ELEMENTS        → Only small integers
PACKED_DOUBLE_ELEMENTS     → Only doubles
PACKED_ELEMENTS            → Any elements
HOLEY_*                    → Has holes (undefined gaps)
DICTIONARY_ELEMENTS        → Sparse array (slow)
```

Transitions only go "down" (more general), never up.
"""

V8_JIT_KNOWLEDGE = """
# V8 JIT Compilation

## TurboFan Optimization Pipeline
1. **Graph Building**: Bytecode → Sea of Nodes IR
2. **Inlining**: Inline hot function calls
3. **Typing**: Infer types from feedback
4. **Lowering**: High-level → Low-level operations
5. **Register Allocation**: Assign registers
6. **Code Generation**: IR → Machine code

## Type Feedback
- Inline Caches (ICs) collect runtime type info
- FeedbackVector stores collected feedback
- JIT uses feedback for speculative optimization

## Common Optimization Bugs

### Bounds Check Elimination (BCE)
```javascript
// If JIT proves index < array.length, bounds check removed
// Bug: Incorrect range analysis can eliminate valid checks
function f(arr, i) {
    return arr[i];  // If JIT thinks i always < arr.length
}
```

### Type Confusion
```javascript
// JIT assumes type based on profiling
function access(obj) {
    return obj.x;  // Assumes obj always has property 'x' as double
}
// If called with different type → type confusion
```

### Side Effect Modeling
```javascript
// JIT must track all side effects
function f(arr) {
    let x = arr.length;
    g();  // If g() modifies arr, x may be stale
    return arr[x - 1];  // Potential OOB if length changed
}
```

## Triggering JIT Compilation
```javascript
// TurboFan optimization
function hot() { /* code */ }
for (let i = 0; i < 10000; i++) hot();

// With natives syntax (--allow-natives-syntax)
%PrepareFunctionForOptimization(f);
f(arg);
%OptimizeFunctionOnNextCall(f);
f(arg);  // Now runs optimized code
```
"""

V8_GC_KNOWLEDGE = """
# V8 Garbage Collection (Orinoco)

## GC Types
- **Scavenge**: Young generation, copying collector
- **Mark-Sweep**: Old generation, mark and sweep
- **Mark-Compact**: Old generation with compaction

## Memory Spaces
- **New Space**: Young generation (nursery)
- **Old Space**: Long-lived objects
- **Code Space**: Compiled code
- **Map Space**: Object maps
- **Large Object Space**: Objects > 512KB

## GC-Related Vulnerabilities

### UAF During GC
```javascript
// Object moved during GC, stale pointer remains
let obj = {x: 1};
let ptr = getInternalPointer(obj);  // Raw pointer
gc();  // obj moves to old space
usePointer(ptr);  // Dangling pointer!
```

### Write Barrier Bugs
- Write barriers track cross-generation pointers
- Missing write barrier → GC misses references → Premature free

### Incremental Marking Bugs
- Incremental marking can be interrupted by JS
- Object state may change during marking
- Race conditions between JS and GC

## Triggering GC
```javascript
// With --expose-gc
gc();
gc();  // Run twice for full GC

// Without flag - allocate heavily
for (let i = 0; i < 100000; i++) {
    new ArrayBuffer(1024 * 1024);
}
```
"""

V8_VULNERABILITY_PATTERNS = """
# Common V8 Vulnerability Patterns

## 1. Type Confusion in JIT

### Pattern
- JIT compiles function assuming specific types
- Attacker provides different type at runtime
- Type confusion leads to memory corruption

### Example Trigger
```javascript
function confused(arr) {
    return arr[0];  // JIT assumes always array
}
// Profile with arrays
for (let i = 0; i < 10000; i++) confused([1.1]);
// Trigger with non-array
confused({0: obj});  // Type confusion
```

## 2. Bounds Check Elimination Bug

### Pattern
- JIT eliminates bounds check due to incorrect range analysis
- Attacker crafts input that violates assumed range
- Out-of-bounds access

### Example Trigger
```javascript
function oob(arr, i) {
    // JIT thinks: i comes from loop, always < arr.length
    if (i < arr.length) {
        // But attacker modifies arr.length after check
        callback();  // Shrinks array
        return arr[i];  // OOB!
    }
}
```

## 3. Prototype Pollution Impact

### Pattern
- Modifying Array.prototype affects JIT assumptions
- Prototype chain lookups can bypass optimizations
- Elements kind transitions through prototype

### Example Trigger
```javascript
Array.prototype[0] = 1.1;  // Pollute prototype
let arr = new Array(10);
// arr becomes HOLEY, but JIT might not expect this
function f(a) { return a[0]; }
```

## 4. ArrayBuffer Length Confusion

### Pattern
- ArrayBuffer.byteLength vs TypedArray.length desync
- Detached buffer access
- Shared memory race conditions

### Example Trigger
```javascript
let ab = new ArrayBuffer(0x100);
let view = new Uint8Array(ab);
// Detach or modify buffer
ab.transfer();  // ES2024
// view.length still appears valid
view[0];  // UAF or OOB
```

## 5. RegExp Exploitation

### Pattern
- RegExp execution can trigger callbacks
- Callbacks can modify objects during regexp processing
- Race between regexp engine and JS

### Example Trigger
```javascript
let re = /x/g;
re[Symbol.match] = function(s) {
    // Modify s or global state
    return [];
};
"x".match(re);  // Trigger callback
```
"""

V8_DEBUGGING = """
# V8 Debugging Techniques

## Debug Flags
```
--allow-natives-syntax    # Enable %DebugPrint, etc.
--trace-opt               # Log optimizations
--trace-deopt             # Log deoptimizations
--trace-gc                # Log GC activity
--print-bytecode          # Print bytecode
--print-opt-code          # Print optimized code
```

## Native Syntax Functions
```javascript
%DebugPrint(obj);          // Print object details
%HeapObjectVerify(obj);    // Verify heap object
%HasFastProperties(obj);   // Check property mode
%GetOptimizationStatus(f); // Get function opt status

// Optimization control
%PrepareFunctionForOptimization(f);
%OptimizeFunctionOnNextCall(f);
%NeverOptimizeFunction(f);
%DeoptimizeFunction(f);
%DeoptimizeNow();
```

## d8 Shell Usage
```bash
# Run with debug flags
./d8 --allow-natives-syntax poc.js

# GDB with V8
gdb -ex 'r' --args ./d8 --allow-natives-syntax poc.js

# ASAN build
export ASAN_OPTIONS=detect_leaks=0
./d8_asan poc.js
```

## Crash Analysis
- SIGSEGV at address 0xXXXX: Null or low address → likely null deref
- SIGSEGV at address 0x41414141: Controlled crash
- SIGABRT: Assertion failure or CHECK
- Look for "DCHECK" or "CHECK" in stack trace
"""

V8_EXPLOITATION_PRIMITIVES = """
# V8 Exploitation Primitives

## Goal: addrof/fakeobj Primitives

### addrof(obj)
Get the address of a JavaScript object as a number.

Typical approach:
1. Create type confusion between Object and Float64
2. Store object, read as float
3. Float bits = object address

### fakeobj(addr)
Create a JavaScript object reference from an address.

Typical approach:
1. Create type confusion between Float64 and Object
2. Store address as float
3. Read as object reference

## OOB Read/Write

### Achieving OOB
1. Corrupt array length field
2. Bounds check elimination bug
3. TypedArray offset confusion

### Using OOB
```javascript
// With corrupted array
let oob_arr = corrupt_length(original_arr);
// Read at offset
let leak = oob_arr[OOB_INDEX];
// Write at offset
oob_arr[OOB_INDEX] = value;
```

## Arbitrary Read/Write

### Via ArrayBuffer
1. Corrupt ArrayBuffer backing store pointer
2. Create TypedArray view
3. Read/write via view

### Via Object Properties
1. Fake object with controlled properties
2. Property access = arbitrary read
3. Property write = arbitrary write

## Code Execution
1. Find RWX region or JIT code
2. Overwrite with shellcode
3. Or corrupt function pointer
4. Trigger execution
"""


def get_v8_knowledge() -> str:
    """Get complete V8 knowledge base as a single string."""
    return "\n\n".join([
        V8_OVERVIEW,
        V8_OBJECT_MODEL,
        V8_JIT_KNOWLEDGE,
        V8_GC_KNOWLEDGE,
        V8_VULNERABILITY_PATTERNS,
        V8_DEBUGGING,
    ])


def get_v8_exploitation_knowledge() -> str:
    """Get V8 exploitation techniques."""
    return V8_EXPLOITATION_PRIMITIVES


# Knowledge sections for targeted inclusion
V8_KNOWLEDGE_SECTIONS = {
    "overview": V8_OVERVIEW,
    "object_model": V8_OBJECT_MODEL,
    "jit": V8_JIT_KNOWLEDGE,
    "gc": V8_GC_KNOWLEDGE,
    "patterns": V8_VULNERABILITY_PATTERNS,
    "debugging": V8_DEBUGGING,
    "exploitation": V8_EXPLOITATION_PRIMITIVES,
}
