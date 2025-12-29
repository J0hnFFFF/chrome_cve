/**
 * @name Extract GC Trigger Patterns
 * @description Identifies garbage collection triggers and memory allocation patterns
 * @kind problem
 * @problem.severity recommendation
 * @id js/extract-gc-triggers
 */

import javascript

/**
 * Detects explicit GC calls
 */
class GCCall extends CallExpr {
  GCCall() {
    this.getCalleeName() = "gc" or
    this.getCalleeName().matches("%CollectGarbage%")
  }
}

/**
 * Detects memory allocation patterns
 */
class MemoryAllocation extends NewExpr {
  MemoryAllocation() {
    this.getCalleeName() in [
      "ArrayBuffer",
      "Uint8Array",
      "Uint16Array",
      "Uint32Array",
      "Float32Array",
      "Float64Array",
      "BigInt64Array",
      "BigUint64Array"
    ]
  }

  string getAllocationType() {
    result = this.getCalleeName()
  }

  Expr getSizeArgument() {
    result = this.getArgument(0)
  }
}

/**
 * Detects array operations that may trigger GC
 */
class ArrayOperation extends MethodCallExpr {
  ArrayOperation() {
    this.getMethodName() in [
      "push",
      "pop",
      "shift",
      "unshift",
      "splice",
      "slice",
      "concat"
    ]
  }

  string getOperationType() {
    result = this.getMethodName()
  }
}

/**
 * Detects patterns where objects are allocated then freed
 */
predicate isAllocateThenFreePattern(VarDecl v, GCCall gc) {
  exists(MemoryAllocation alloc |
    v.getInit() = alloc and
    // GC is called after the allocation
    gc.getLocation().getStartLine() > alloc.getLocation().getStartLine() and
    // Within reasonable distance (same function or < 50 lines)
    gc.getLocation().getStartLine() - alloc.getLocation().getStartLine() < 50
  )
}

from MemoryAllocation alloc, GCCall gc
where isAllocateThenFreePattern(_, gc)
select alloc,
  "Memory allocation (" + alloc.getAllocationType() + 
  ") followed by GC at line " + gc.getLocation().getStartLine()
