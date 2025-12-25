"""
Built-in Generator Plugins

Pre-built PoC generator plugins.
"""

from .js_generator import JavaScriptGeneratorPlugin
from .html_generator import HTMLGeneratorPlugin

__all__ = [
    'JavaScriptGeneratorPlugin',
    'HTMLGeneratorPlugin',
]
