"""
Plugin System for Chrome CVE Reproducer

This module provides the plugin architecture that allows:
1. Built-in plugins for common vulnerability types
2. Dynamic plugin generation by LLM when no matching plugin exists
3. Plugin registry and matching based on component/vuln_type

Plugin Types:
- AnalyzerPlugin: Analyzes patches → AnalysisResult
- GeneratorPlugin: Generates PoC → PoCResult
- VerifierPlugin: Verifies PoC → VerifyResult
"""

from .base import (
    PluginBase,
    AnalyzerPlugin,
    GeneratorPlugin,
    VerifierPlugin,
    AnalysisResult,
    PoCResult,
    VerifyResult,
)
from .registry import PluginRegistry, get_registry
from .dynamic import DynamicPluginGenerator

# Built-in plugins
from .analyzers import V8AnalyzerPlugin, BlinkAnalyzerPlugin, GenericAnalyzerPlugin
from .generators import JavaScriptGeneratorPlugin, HTMLGeneratorPlugin
from .verifiers import ChromeVerifierPlugin, D8VerifierPlugin

__all__ = [
    # Base classes
    'PluginBase',
    'AnalyzerPlugin',
    'GeneratorPlugin',
    'VerifierPlugin',
    'AnalysisResult',
    'PoCResult',
    'VerifyResult',
    # Registry
    'PluginRegistry',
    'get_registry',
    'DynamicPluginGenerator',
    # Built-in analyzers
    'V8AnalyzerPlugin',
    'BlinkAnalyzerPlugin',
    'GenericAnalyzerPlugin',
    # Built-in generators
    'JavaScriptGeneratorPlugin',
    'HTMLGeneratorPlugin',
    # Built-in verifiers
    'ChromeVerifierPlugin',
    'D8VerifierPlugin',
]


def register_builtin_plugins():
    """Register all built-in plugins to the global registry."""
    registry = get_registry()

    # Register analyzers
    registry.register_analyzer(V8AnalyzerPlugin())
    registry.register_analyzer(BlinkAnalyzerPlugin())
    registry.register_analyzer(GenericAnalyzerPlugin())

    # Register generators
    registry.register_generator(JavaScriptGeneratorPlugin())
    registry.register_generator(HTMLGeneratorPlugin())

    # Register verifiers
    registry.register_verifier(ChromeVerifierPlugin())
    registry.register_verifier(D8VerifierPlugin())


# Auto-register on import
register_builtin_plugins()
