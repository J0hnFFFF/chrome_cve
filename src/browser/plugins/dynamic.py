"""
Dynamic Plugin Generator

Uses LLM to generate new plugins when no matching plugin exists.
The generated plugin code follows the PluginBase interface.
"""

import importlib.util
import sys
from typing import Type, Optional, Dict, Any
from .base import AnalyzerPlugin, GeneratorPlugin, VerifierPlugin, PluginBase
from .registry import get_registry


class DynamicPluginGenerator:
    """
    Generates plugins dynamically using LLM.

    When no matching plugin exists for a component/vuln_type combination,
    this generator can create a new plugin by:
    1. Getting the PluginBase interface definition
    2. Finding similar existing plugins as reference
    3. Having LLM generate plugin code
    4. Dynamically loading and validating the plugin
    5. Storing successful plugins in knowledge base
    """

    def __init__(self, llm_model: str = "gpt-4o"):
        self.llm_model = llm_model
        self._generated_plugins: Dict[str, PluginBase] = {}

    def get_base_definition(self, plugin_type: str) -> str:
        """Get the base class definition for reference."""
        if plugin_type == "analyzer":
            import inspect
            return inspect.getsource(AnalyzerPlugin)
        elif plugin_type == "generator":
            import inspect
            return inspect.getsource(GeneratorPlugin)
        elif plugin_type == "verifier":
            import inspect
            return inspect.getsource(VerifierPlugin)
        return ""

    def find_similar_plugins(
        self,
        plugin_type: str,
        component: str,
        limit: int = 3
    ) -> list:
        """Find similar existing plugins as reference."""
        registry = get_registry()
        plugins = []

        if plugin_type == "analyzer":
            plugins = list(registry._analyzers.values())
        elif plugin_type == "generator":
            plugins = list(registry._generators.values())
        elif plugin_type == "verifier":
            plugins = list(registry._verifiers.values())

        # Sort by similarity (simple component matching for now)
        return plugins[:limit]

    def generate_analyzer(
        self,
        component: str,
        vuln_type: str,
        context: Dict[str, Any] = None
    ) -> Optional[AnalyzerPlugin]:
        """
        Generate a new analyzer plugin for the given component/vuln_type.

        Args:
            component: Target component (v8, blink, etc.)
            vuln_type: Vulnerability type (uaf, oob, etc.)
            context: Additional context for generation

        Returns:
            Generated AnalyzerPlugin or None if generation fails
        """
        # TODO: Implement LLM-based plugin generation
        # 1. Build prompt with base definition + similar plugins + context
        # 2. Call LLM to generate plugin code
        # 3. Load and validate the generated plugin
        # 4. Register and return if successful
        return None

    def generate_generator(
        self,
        component: str,
        vuln_type: str,
        context: Dict[str, Any] = None
    ) -> Optional[GeneratorPlugin]:
        """Generate a new generator plugin."""
        # TODO: Implement LLM-based plugin generation
        return None

    def generate_verifier(
        self,
        component: str,
        vuln_type: str,
        context: Dict[str, Any] = None
    ) -> Optional[VerifierPlugin]:
        """Generate a new verifier plugin."""
        # TODO: Implement LLM-based plugin generation
        return None

    def _load_plugin_from_code(
        self,
        code: str,
        plugin_name: str,
        base_class: Type[PluginBase]
    ) -> Optional[PluginBase]:
        """
        Dynamically load a plugin from generated code.

        Args:
            code: Python code defining the plugin class
            plugin_name: Name of the plugin class to instantiate
            base_class: Expected base class for validation

        Returns:
            Instantiated plugin or None if loading fails
        """
        try:
            # Create a module spec
            spec = importlib.util.spec_from_loader(
                f"dynamic_plugin_{plugin_name}",
                loader=None,
                origin="dynamic"
            )
            module = importlib.util.module_from_spec(spec)

            # Execute the code in the module namespace
            exec(code, module.__dict__)

            # Get the plugin class
            plugin_class = getattr(module, plugin_name, None)
            if plugin_class is None:
                return None

            # Validate it's a subclass of the expected base
            if not issubclass(plugin_class, base_class):
                return None

            # Instantiate and return
            return plugin_class()

        except Exception as e:
            print(f"Failed to load dynamic plugin: {e}")
            return None

    def _validate_plugin(self, plugin: PluginBase) -> bool:
        """Validate that a plugin implements required methods."""
        if isinstance(plugin, AnalyzerPlugin):
            return callable(getattr(plugin, 'analyze', None))
        elif isinstance(plugin, GeneratorPlugin):
            return callable(getattr(plugin, 'generate', None))
        elif isinstance(plugin, VerifierPlugin):
            return callable(getattr(plugin, 'verify', None))
        return False
