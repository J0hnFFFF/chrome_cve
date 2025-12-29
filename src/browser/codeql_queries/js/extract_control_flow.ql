/**
 * @name Extract Control Flow Patterns
 * @description Identifies critical control flow structures in PoC code
 * @kind problem
 * @problem.severity recommendation
 * @id js/extract-control-flow
 */

import javascript

/**
 * Detects nested loops that may be used for exploitation
 */
class NestedLoop extends ForStmt {
  NestedLoop() {
    exists(ForStmt inner |
      inner.getEnclosingStmt().getParent*() = this
    )
  }

  int getNestingDepth() {
    result = count(ForStmt inner |
      inner.getEnclosingStmt().getParent*() = this
    )
  }
}

/**
 * Detects conditional branches that check for specific values
 */
class CriticalConditional extends IfStmt {
  CriticalConditional() {
    // Checks involving typeof, instanceof, or property access
    exists(Expr test | test = this.getCondition() |
      test instanceof TypeofExpr or
      test instanceof InstanceofExpr or
      test.(PropAccess).getPropertyName() in ["length", "byteLength", "constructor"]
    )
  }

  string getCheckType() {
    if this.getCondition() instanceof TypeofExpr
    then result = "typeof_check"
    else if this.getCondition() instanceof InstanceofExpr
    then result = "instanceof_check"
    else result = "property_check"
  }
}

/**
 * Detects try-catch blocks that may be used to suppress errors
 */
class ErrorSuppression extends TryStmt {
  ErrorSuppression() {
    // Try-catch with empty or minimal catch block
    this.getCatchClause().getBody().getNumStmt() <= 1
  }
}

/**
 * Detects function calls within loops (potential trigger points)
 */
predicate isFunctionCallInLoop(CallExpr call, ForStmt loop) {
  call.getEnclosingStmt().getParent*() = loop.getBody()
}

from NestedLoop loop, CriticalConditional cond
where
  // Find conditionals within or after nested loops
  cond.getEnclosingStmt().getParent*() = loop or
  loop.getASuccessor*() = cond.getEnclosingStmt()
select loop,
  "Nested loop (depth: " + loop.getNestingDepth() + 
  ") with critical conditional: " + cond.getCheckType()
