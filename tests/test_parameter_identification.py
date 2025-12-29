"""
Test script for upgraded parameter identification

Tests the semantic parameter classification system.
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from browser.plugins.generators.helpers.template_auto_learner import (
    TemplateAutoLearner,
    Pattern
)

# Test cases with different parameter types
TEST_CASES = [
    {
        "name": "JIT Optimization Pattern",
        "code": """
function trigger() {
    let arr = new Uint32Array(10);
    return arr;
}

for (let i = 0; i < 10000; i++) {
    trigger();
}

%OptimizeFunctionOnNextCall(trigger);
""",
        "expected_params": ['jit_iterations', 'array_length']
    },
    {
        "name": "Memory Spray Pattern",
        "code": """
let spray = [];
for (let i = 0; i < 1000; i++) {
    spray.push(new ArrayBuffer(0x10000));
}
gc();
""",
        "expected_params": ['spray_count', 'buffer_size', 'allocation_size']
    },
    {
        "name": "Array Offset Exploit",
        "code": """
let arr = new Uint8Array(100);
let offset = 0x10;
arr[offset] = 0x41;
""",
        "expected_params": ['array_length', 'array_offset', 'magic_value']
    },
    {
        "name": "Nested Loop Pattern",
        "code": """
for (let i = 0; i < 100; i++) {
    for (let j = 0; j < 50; j++) {
        // Spray
    }
}
""",
        "expected_params": ['outer_loop_count', 'inner_loop_count']
    }
]

def test_parameter_identification():
    """Test upgraded parameter identification"""
    print("=" * 70)
    print("Testing Semantic Parameter Identification")
    print("=" * 70)
    
    learner = TemplateAutoLearner()
    
    total_tests = len(TEST_CASES)
    passed_tests = 0
    
    for i, test_case in enumerate(TEST_CASES, 1):
        print(f"\n{'='*70}")
        print(f"Test {i}/{total_tests}: {test_case['name']}")
        print(f"{'='*70}")
        
        # Extract pattern (using heuristic since we're testing parameter logic)
        pattern = learner._extract_pattern_heuristic(test_case['code'])
        
        # Identify parameters
        params = learner._identify_parameters(pattern)
        
        print(f"\n📋 Identified Parameters ({len(params)}):")
        for param in params:
            print(f"   • {param}")
        
        print(f"\n🎯 Expected Parameters:")
        for expected in test_case['expected_params']:
            print(f"   • {expected}")
        
        # Check if we found expected parameters
        found_count = sum(1 for exp in test_case['expected_params'] 
                         if any(exp in p for p in params))
        
        success_rate = found_count / len(test_case['expected_params'])
        
        print(f"\n📊 Match Rate: {found_count}/{len(test_case['expected_params'])} ", end="")
        print(f"({success_rate*100:.0f}%)")
        
        if success_rate >= 0.5:  # At least 50% match
            print("   ✅ PASS")
            passed_tests += 1
        else:
            print("   ❌ FAIL")
    
    # Summary
    print(f"\n{'='*70}")
    print("Test Summary")
    print(f"{'='*70}")
    print(f"Passed: {passed_tests}/{total_tests} ({passed_tests/total_tests*100:.0f}%)")
    
    return passed_tests == total_tests

def test_context_classification():
    """Test context-based constant classification"""
    print("\n" + "=" * 70)
    print("Testing Context-Based Classification")
    print("=" * 70)
    
    learner = TemplateAutoLearner()
    
    test_contexts = [
        ("0x10000", "new ArrayBuffer(0x10000)", "buffer_size"),
        ("10000", "for (let i = 0; i < 10000; i++)", "jit_iterations"),
        ("0x10", "arr[0x10]", "array_offset"),
        ("100", "new Array(100)", "spray_count"),
    ]
    
    passed = 0
    for value, context, expected in test_contexts:
        pattern = Pattern(code=context, key_operations=[], control_flow=[], constants=[])
        result = learner._classify_constant_by_context(value, context.lower(), pattern)
        
        match = expected in result or result in expected
        status = "✅" if match else "❌"
        
        print(f"\n{status} Value: {value}")
        print(f"   Context: {context}")
        print(f"   Expected: {expected}")
        print(f"   Got: {result}")
        
        if match:
            passed += 1
    
    print(f"\n📊 Context Classification: {passed}/{len(test_contexts)} passed")
    return passed == len(test_contexts)

if __name__ == "__main__":
    try:
        test1 = test_parameter_identification()
        test2 = test_context_classification()
        
        success = test1 and test2
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
