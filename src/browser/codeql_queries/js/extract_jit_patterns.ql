/**
 * @name Extract JIT Optimization Patterns
 * @description Identifies V8 JIT optimization patterns in JavaScript PoC code
 * @kind problem
 * @problem.severity recommendation
 * @id js/extract-jit-patterns
 */

import javascript

/**
 * Detects calls to V8 native functions that trigger JIT optimization
 */
class JITOptimizationCall extends CallExpr {
  JITOptimizationCall() {
    // Match %OptimizeFunctionOnNextCall and similar intrinsics
    this.getCalleeName().matches("%Optimize%") or
    this.getCalleeName().matches("%PrepareFunctionForOptimization%") or
    this.getCalleeName().matches("%OptimizeOsr%") or
    this.getCalleeName().matches("%DeoptimizeFunction%") or
    this.getCalleeName().matches("%NeverOptimizeFunction%")
  }

  string getOptimizationType() {
    if this.getCalleeName().matches("%OptimizeFunctionOnNextCall%")
    then result = "optimize_on_next_call"
    else if this.getCalleeName().matches("%PrepareFunctionForOptimization%")
    then result = "prepare_for_optimization"
    else if this.getCalleeName().matches("%OptimizeOsr%")
    then result = "optimize_osr"
    else result = "other_optimization"
  }

  Function getTargetFunction() {
    result = this.getArgument(0).(VarAccess).getVariable().getAnAssignedExpr()
  }
}

/**
 * Detects loops that may be used for triggering JIT compilation
 */
class JITTriggerLoop extends ForStmt {
  JITTriggerLoop() {
    // Loop with large iteration count (> 1000)
    exists(NumberLiteral n |
      n = this.getTest().(RelationalComparison).getAnOperand() and
      n.getValue().toInt() > 1000
    )
  }

  int getIterationCount() {
    result = this.getTest().(RelationalComparison).getAnOperand().(NumberLiteral).getValue().toInt()
  }
}

from JITOptimizationCall jit, JITTriggerLoop loop
where
  // Find JIT calls within or near trigger loops
  jit.getEnclosingStmt().getParent*() = loop or
  loop.getASuccessor*() = jit.getEnclosingStmt()
select jit,
  "JIT optimization pattern: " + jit.getOptimizationType() +
  " with trigger loop of " + loop.getIterationCount() + " iterations"
