"""
Built-in Analyzer Plugins

Pre-built analyzer plugins for common components.
"""

from .v8_analyzer import V8AnalyzerPlugin
from .blink_analyzer import BlinkAnalyzerPlugin
from .generic_analyzer import GenericAnalyzerPlugin

__all__ = [
    'V8AnalyzerPlugin',
    'BlinkAnalyzerPlugin',
    'GenericAnalyzerPlugin',
]
