"""
Blink Rendering Engine Knowledge Base

This module contains structured knowledge about Blink internals
for vulnerability analysis and PoC development.
"""

BLINK_OVERVIEW = """
# Blink Rendering Engine Overview

Blink is Chrome's rendering engine, forked from WebKit. Key subsystems:

## Core Components
1. **DOM**: Document Object Model implementation
2. **CSS**: Style parsing and resolution
3. **Layout**: Box tree and positioning
4. **Paint**: Drawing operations
5. **Compositor**: GPU-accelerated compositing

## Rendering Pipeline
1. Parse HTML → DOM Tree
2. Parse CSS → CSSOM
3. Style Resolution → Computed Styles
4. Layout → Layout Tree
5. Paint → Display Lists
6. Composite → Layers → GPU

## Key Directories
- `third_party/blink/renderer/core/`: Core rendering
- `third_party/blink/renderer/bindings/`: V8 bindings
- `third_party/blink/renderer/platform/`: Platform abstractions
- `third_party/blink/renderer/modules/`: Web APIs
"""

BLINK_DOM_KNOWLEDGE = """
# Blink DOM Implementation

## Node Hierarchy
```
EventTarget
  └── Node
        ├── Document
        ├── DocumentFragment
        ├── Element
        │     ├── HTMLElement
        │     │     ├── HTMLDivElement
        │     │     ├── HTMLIFrameElement
        │     │     └── ...
        │     └── SVGElement
        ├── Attr
        ├── CharacterData
        │     ├── Text
        │     └── Comment
        └── DocumentType
```

## DOM Memory Management (Oilpan)
- Garbage-collected heap (Oilpan)
- Traced pointers: Member<T>, WeakMember<T>
- Raw pointers allowed in certain scopes
- Cross-thread pointers require special handling

## Node Lifecycle
1. Creation: `Document::CreateElement()`
2. Insertion: `Node::insertBefore()`, `appendChild()`
3. Removal: `Node::removeChild()`, `innerHTML = ""`
4. Destruction: When no references remain

## Common DOM Vulnerability Patterns

### UAF in Node Removal
```javascript
let child = parent.firstChild;
parent.innerHTML = "";  // child freed
child.textContent;  // UAF!
```

### Event Handler UAF
```javascript
el.addEventListener('click', function() {
    this.remove();  // Remove during event
    // Handler continues with freed element
});
el.click();
```

### MutationObserver Races
```javascript
let observer = new MutationObserver((mutations) => {
    // DOM modified during observation
    // Can cause inconsistent state
});
observer.observe(node, {childList: true, subtree: true});
```
"""

BLINK_LAYOUT_KNOWLEDGE = """
# Blink Layout System

## Layout Object Hierarchy
```
LayoutObject
  ├── LayoutBox (has dimensions)
  │     ├── LayoutBlock
  │     │     ├── LayoutBlockFlow
  │     │     └── LayoutTable
  │     ├── LayoutReplaced
  │     │     ├── LayoutImage
  │     │     └── LayoutVideo
  │     └── LayoutFlexibleBox
  └── LayoutInline
```

## Layout Process
1. **Style Recalc**: ComputedStyle for each element
2. **Layout Tree Build**: Create LayoutObjects
3. **Layout**: Calculate positions and sizes
4. **Paint**: Generate paint operations

## Layout Invalidation
- Style change → Layout invalidation
- DOM mutation → Layout invalidation
- `element.offsetHeight` → Force synchronous layout

## Layout Vulnerability Patterns

### Style Recalc UAF
```javascript
let el = document.getElementById('target');
el.style.display = 'none';
el.offsetHeight;  // Force sync layout
el.remove();  // Remove during/after layout
// Stale layout objects may remain
```

### Table Layout Bugs
```javascript
// Tables have complex layout logic
// Cell spanning, column sizing issues
table.deleteRow(0);
table.insertRow(0);
// Race between DOM and layout updates
```

### Flexbox/Grid Bugs
```javascript
// Modern layout modes
container.style.display = 'flex';
// Complex calculations for flex items
// Potential for integer overflows
```
"""

BLINK_BINDINGS_KNOWLEDGE = """
# V8-Blink Bindings

## IDL Interface Definition
```idl
// Example: HTMLElement.idl
interface HTMLElement : Element {
    [Reflect] attribute DOMString title;
    [CallWith=ExecutionContext] void click();
    [RaisesException] attribute DOMString innerHTML;
};
```

## Binding Mechanisms
- **Reflect**: Direct attribute mapping
- **CallWith**: Pass execution context
- **RaisesException**: Can throw
- **Measure**: Usage tracking
- **Custom]: Hand-written binding

## Wrapper Lifecycle
1. JS object created → C++ wrapper exists
2. Wrapper weak reference from V8
3. C++ alive → Wrapper kept alive
4. C++ destroyed → Wrapper zombified

## Binding Vulnerabilities

### Callback-during-destruction
```javascript
let obj = new SomeObject();
obj.addEventListener('event', function() {
    // Callback during C++ object destruction
    // Can access partially destroyed state
});
```

### ExecutionContext Issues
```javascript
// Cross-origin access
let iframe = document.createElement('iframe');
iframe.src = 'http://evil.com';
document.body.appendChild(iframe);
// Access iframe.contentWindow properties
// Binding checks for same-origin may be bypassable
```

### Type Confusion in Bindings
```javascript
// IDL type mismatch
function expectsArray(arr) {
    // arr assumed to be Array
    // What if passed object with length?
}
```
"""

BLINK_SECURITY_FEATURES = """
# Blink Security Features

## Same-Origin Policy
- DOM access restricted by origin
- CrossOriginAccessible IDL attribute
- SecurityError for violations

## Content Security Policy (CSP)
- Script execution restrictions
- Inline script blocking
- eval() restrictions

## Site Isolation
- Cross-origin iframes in separate processes
- CORB (Cross-Origin Read Blocking)
- COOP/COEP headers

## Vulnerability Bypasses

### SOP Bypass Patterns
```javascript
// Object leak across origins
let iframe = document.createElement('iframe');
iframe.src = 'http://victim.com';
// Find way to access iframe.contentDocument
// Or leak information via timing/error
```

### CSP Bypass Patterns
```javascript
// Dangling markup injection
// Script gadgets in allowed libraries
// Base URL manipulation
```
"""

BLINK_VULNERABILITY_PATTERNS = """
# Common Blink Vulnerability Patterns

## 1. Use-After-Free in DOM

### Pattern
- Object removed from DOM
- Reference to object retained
- Access through stale reference

### Example Trigger
```html
<div id="container">
    <span id="target">text</span>
</div>
<script>
let target = document.getElementById('target');
let container = document.getElementById('container');

// Store reference
let range = document.createRange();
range.selectNode(target);

// Remove from DOM
container.innerHTML = '';

// Access freed node through Range
range.cloneContents();  // UAF
</script>
```

## 2. Type Confusion

### Pattern
- Object of one type treated as another
- Incorrect casting in C++ code
- Wrong IDL interface used

### Example Trigger
```javascript
// Create object of type A
// Through some path, treated as type B
// Access properties at wrong offsets
```

## 3. Integer Overflow in Layout

### Pattern
- Large dimensions or counts
- Multiplication/addition overflow
- Used for memory allocation → heap corruption

### Example Trigger
```html
<style>
.huge {
    width: 4294967295px;
    height: 2147483647px;
}
</style>
<div class="huge">
    <!-- Trigger layout calculation -->
</div>
```

## 4. Race Conditions

### Pattern
- Asynchronous operations
- State modified between check and use
- TOCTOU vulnerabilities

### Example Trigger
```javascript
// Setup race between main thread and worker
let sab = new SharedArrayBuffer(1024);
let view = new Int32Array(sab);

// Worker modifies while main thread reads
let worker = new Worker(URL.createObjectURL(new Blob([`
    let v = new Int32Array(sab);
    while(true) v[0] = Math.random() * 1000;
`])));

// Main thread accesses with stale length
```

## 5. Event Handler Vulnerabilities

### Pattern
- DOM modified during event handling
- Handler accesses removed elements
- Re-entrancy issues

### Example Trigger
```javascript
el.addEventListener('load', function() {
    this.remove();
    // Continue using 'this'
    this.src = 'x';  // Access after removal
});
```
"""

BLINK_DEBUGGING = """
# Blink Debugging Techniques

## Debug Flags
```
--enable-logging=stderr --v=1     # Verbose logging
--enable-blink-features=...       # Enable experimental features
--disable-blink-features=...      # Disable features
```

## Source Navigation
Key files for common subsystems:
- DOM: `core/dom/node.cc`, `core/dom/element.cc`
- Layout: `core/layout/layout_object.cc`
- Style: `core/css/resolver/style_resolver.cc`
- Bindings: `bindings/core/v8/v8_binding.h`

## Common DCHECK Locations
- `DCHECK(GetDocument().Lifecycle().StateAllowsLayoutInvalidation())`
- `DCHECK(node->GetLayoutObject())`
- `DCHECK(!context->IsContextDestroyed())`

## Memory Debugging
```bash
# Run with ASAN
./chrome --no-sandbox --disable-gpu \\
    --enable-logging=stderr poc.html

# HeapCheck
export HEAPCHECK=normal
./chrome ...
```

## Crash Analysis
- UAF: Look for "heap-use-after-free" in ASAN output
- Type confusion: Wrong vtable access
- OOB: "heap-buffer-overflow" or "stack-buffer-overflow"

## Reproducing Layout Bugs
```javascript
// Force synchronous layout
element.offsetHeight;
element.getBoundingClientRect();
getComputedStyle(element).width;

// Trigger style recalc
element.style.cssText = 'display: block';
element.className = 'new-class';
```
"""

BLINK_EXPLOITATION_PRIMITIVES = """
# Blink Exploitation Techniques

## DOM Corruption Primitives

### Arbitrary Object Access
1. Corrupt object pointer in DOM structure
2. Access controlled memory through DOM API
3. Use innerHTML, textContent for read

### Type Confusion Exploitation
1. Achieve type confusion between DOM objects
2. Object A's memory read as Object B
3. Control object layout for exploitation

## Memory Spray Techniques

### Heap Spray via DOM
```javascript
// Spray heap with controlled data
let spray = [];
for (let i = 0; i < 10000; i++) {
    spray.push(document.createElement('div'));
    spray[i].setAttribute('data', 'A'.repeat(0x1000));
}
```

### ArrayBuffer Spray
```javascript
// Spray with ArrayBuffers for controlled data
let spray = [];
for (let i = 0; i < 1000; i++) {
    let ab = new ArrayBuffer(0x1000);
    let view = new Uint32Array(ab);
    view.fill(0x41414141);
    spray.push(ab);
}
```

## UAF Exploitation

### Reclaim with Controlled Object
```javascript
// After triggering UAF
// Allocate objects of same size to reclaim
let controlled = [];
for (let i = 0; i < 100; i++) {
    controlled.push({
        a: 0x41414141,
        b: 0x42424242
    });
}
// Access UAF object → reads our data
```

### PartitionAlloc Considerations
- Blink uses PartitionAlloc
- Objects grouped by size class
- Need same-sized object for reclaim
- SuperPage/SlotSpan structure
"""


def get_blink_knowledge() -> str:
    """Get complete Blink knowledge base as a single string."""
    return "\n\n".join([
        BLINK_OVERVIEW,
        BLINK_DOM_KNOWLEDGE,
        BLINK_LAYOUT_KNOWLEDGE,
        BLINK_BINDINGS_KNOWLEDGE,
        BLINK_VULNERABILITY_PATTERNS,
        BLINK_DEBUGGING,
    ])


def get_blink_security_knowledge() -> str:
    """Get Blink security features and bypasses."""
    return BLINK_SECURITY_FEATURES


def get_blink_exploitation_knowledge() -> str:
    """Get Blink exploitation techniques."""
    return BLINK_EXPLOITATION_PRIMITIVES


# Knowledge sections for targeted inclusion
BLINK_KNOWLEDGE_SECTIONS = {
    "overview": BLINK_OVERVIEW,
    "dom": BLINK_DOM_KNOWLEDGE,
    "layout": BLINK_LAYOUT_KNOWLEDGE,
    "bindings": BLINK_BINDINGS_KNOWLEDGE,
    "security": BLINK_SECURITY_FEATURES,
    "patterns": BLINK_VULNERABILITY_PATTERNS,
    "debugging": BLINK_DEBUGGING,
    "exploitation": BLINK_EXPLOITATION_PRIMITIVES,
}
