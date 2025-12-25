"""
Plugin Registry

Manages plugin registration, discovery, and matching.
"""

from typing import List, Dict, Type, Optional
from .base import PluginBase, AnalyzerPlugin, GeneratorPlugin, VerifierPlugin


class PluginRegistry:
    """
    Central registry for all plugins.

    Supports:
    - Plugin registration by type
    - Plugin matching by component/vuln_type
    - Built-in and dynamic plugin management
    """

    def __init__(self):
        self._analyzers: Dict[str, AnalyzerPlugin] = {}
        self._generators: Dict[str, GeneratorPlugin] = {}
        self._verifiers: Dict[str, VerifierPlugin] = {}

    def register_analyzer(self, plugin: AnalyzerPlugin) -> None:
        """Register an analyzer plugin."""
        self._analyzers[plugin.name] = plugin

    def register_generator(self, plugin: GeneratorPlugin) -> None:
        """Register a generator plugin."""
        self._generators[plugin.name] = plugin

    def register_verifier(self, plugin: VerifierPlugin) -> None:
        """Register a verifier plugin."""
        self._verifiers[plugin.name] = plugin

    def get_analyzer(
        self,
        component: str,
        vuln_type: str = None
    ) -> Optional[AnalyzerPlugin]:
        """Find a matching analyzer plugin."""
        for plugin in self._analyzers.values():
            if plugin.matches(component, vuln_type):
                return plugin
        return None

    def get_generator(
        self,
        component: str,
        vuln_type: str = None
    ) -> Optional[GeneratorPlugin]:
        """Find a matching generator plugin."""
        for plugin in self._generators.values():
            if plugin.matches(component, vuln_type):
                return plugin
        return None

    def get_verifier(
        self,
        component: str,
        vuln_type: str = None
    ) -> Optional[VerifierPlugin]:
        """Find a matching verifier plugin."""
        for plugin in self._verifiers.values():
            if plugin.matches(component, vuln_type):
                return plugin
        return None

    def list_analyzers(self) -> List[Dict]:
        """List all registered analyzer plugins."""
        return [p.get_info() for p in self._analyzers.values()]

    def list_generators(self) -> List[Dict]:
        """List all registered generator plugins."""
        return [p.get_info() for p in self._generators.values()]

    def list_verifiers(self) -> List[Dict]:
        """List all registered verifier plugins."""
        return [p.get_info() for p in self._verifiers.values()]


# Global registry instance
_global_registry: Optional[PluginRegistry] = None


def get_registry() -> PluginRegistry:
    """Get the global plugin registry."""
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginRegistry()
    return _global_registry
