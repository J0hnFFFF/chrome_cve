/**
 * CodeQL Query Library Metadata
 * 
 * This directory contains CodeQL queries for extracting patterns from JavaScript PoC code.
 * These queries are used by the TemplateAutoLearner to perform AST-based pattern extraction.
 */

# CodeQL JavaScript Queries for PoC Analysis

## Overview
These queries analyze successful JavaScript PoC code to extract reusable patterns for template generation.

## Queries

### 1. extract_jit_patterns.ql
Identifies V8 JIT optimization patterns including:
- `%OptimizeFunctionOnNextCall()` calls
- `%PrepareFunctionForOptimization()` calls
- Trigger loops with high iteration counts
- Relationship between optimization calls and loops

### 2. extract_gc_triggers.ql
Identifies garbage collection and memory patterns:
- Explicit `gc()` calls
- Memory allocations (ArrayBuffer, TypedArrays)
- Allocate-then-free patterns
- Array operations that may trigger GC

### 3. extract_control_flow.ql
Identifies critical control flow structures:
- Nested loops (exploitation triggers)
- Type checks (`typeof`, `instanceof`)
- Property access checks (`length`, `byteLength`)
- Try-catch error suppression patterns

## Usage

These queries are automatically invoked by `TemplateAutoLearner._extract_pattern_with_codeql()`.

Manual usage:
```bash
# Create CodeQL database
codeql database create poc_db --language=javascript --source-root=./poc_code

# Run query
codeql query run extract_jit_patterns.ql --database=poc_db --output=results.sarif
```

## Requirements
- CodeQL CLI (https://github.com/github/codeql-cli-binaries)
- JavaScript CodeQL library
