"""
Test script for CodeQL-based pattern extraction

This script tests the newly implemented AST-based pattern extraction
using a sample V8 PoC.
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from browser.plugins.generators.helpers.template_auto_learner import TemplateAutoLearner
from browser.services.codeql_service import CodeQLService

# Sample V8 PoC with JIT optimization patterns
SAMPLE_POC = """
// V8 Type Confusion PoC
function trigger() {
    let arr = new Uint32Array(10);
    arr[0] = 0x41414141;
    return arr;
}

// Prepare for optimization
for (let i = 0; i < 10000; i++) {
    trigger();
}

// Trigger JIT compilation
%OptimizeFunctionOnNextCall(trigger);
trigger();

// Allocate and free to trigger GC
let buf = new ArrayBuffer(0x1000);
gc();

// Exploit
let victim = trigger();
console.log(victim[0].toString(16));
"""

def test_codeql_extraction():
    """Test CodeQL-based pattern extraction"""
    print("=" * 60)
    print("Testing CodeQL Pattern Extraction")
    print("=" * 60)
    
    # Check if CodeQL is available
    codeql_service = CodeQLService(source_path=".")
    if not codeql_service.is_available():
        print("\n⚠️  CodeQL CLI not found!")
        print("   Install from: https://github.com/github/codeql-cli-binaries")
        print("   Falling back to heuristic extraction...\n")
    else:
        print("\n✓ CodeQL CLI detected\n")
    
    # Initialize auto-learner
    learner = TemplateAutoLearner(
        codeql_service=codeql_service if codeql_service.is_available() else None
    )
    
    # Extract pattern
    print("Extracting pattern from sample PoC...")
    pattern = learner._extract_pattern(SAMPLE_POC)
    
    # Display results
    print("\n" + "=" * 60)
    print("Extraction Results")
    print("=" * 60)
    
    print(f"\n📋 Key Operations ({len(pattern.key_operations)}):")
    for op in pattern.key_operations:
        print(f"   • {op}")
    
    print(f"\n🔀 Control Flow ({len(pattern.control_flow)}):")
    for cf in pattern.control_flow:
        print(f"   • {cf}")
    
    print(f"\n🔢 Constants ({len(pattern.constants)}):")
    for const in pattern.constants[:5]:  # Show first 5
        print(f"   • {const['value']} at position {const['position']}")
    
    # Verify expected patterns
    print("\n" + "=" * 60)
    print("Verification")
    print("=" * 60)
    
    expected_ops = ['jit_optimization', 'ArrayBuffer', 'gc']
    found_ops = [op for op in expected_ops if any(op in key_op for key_op in pattern.key_operations)]
    
    print(f"\n✓ Found {len(found_ops)}/{len(expected_ops)} expected operations:")
    for op in found_ops:
        print(f"   ✓ {op}")
    
    missing_ops = [op for op in expected_ops if op not in found_ops]
    if missing_ops:
        print(f"\n⚠️  Missing operations:")
        for op in missing_ops:
            print(f"   ✗ {op}")
    
    print("\n" + "=" * 60)
    print("Test Complete")
    print("=" * 60)
    
    return len(found_ops) >= 2  # Success if at least 2/3 patterns found

if __name__ == "__main__":
    try:
        success = test_codeql_extraction()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
