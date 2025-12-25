"""
Plugin Base Classes

Defines the abstract interfaces that all plugins must implement.
LLM can generate new plugins by following these interfaces.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class AnalysisResult:
    """Output from analyzer plugins."""
    vulnerability_type: str
    component: str
    root_cause: str
    trigger_conditions: List[str] = field(default_factory=list)
    trigger_approach: str = ""
    poc_strategy: str = ""
    confidence: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_type": self.vulnerability_type,
            "component": self.component,
            "root_cause": self.root_cause,
            "trigger_conditions": self.trigger_conditions,
            "trigger_approach": self.trigger_approach,
            "poc_strategy": self.poc_strategy,
            "confidence": self.confidence,
            **self.extra,
        }


@dataclass
class PoCResult:
    """Output from generator plugins."""
    code: str
    language: str  # javascript, html
    target_version: str = ""
    expected_behavior: str = ""
    success: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "language": self.language,
            "target_version": self.target_version,
            "expected_behavior": self.expected_behavior,
            "success": self.success,
            **self.extra,
        }


@dataclass
class VerifyResult:
    """Output from verifier plugins."""
    success: bool
    crash_type: str = ""
    crash_address: str = ""
    stack_trace: str = ""
    asan_report: str = ""
    reproducibility: str = ""  # always, sometimes, never
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "crash_type": self.crash_type,
            "crash_address": self.crash_address,
            "stack_trace": self.stack_trace,
            "asan_report": self.asan_report,
            "reproducibility": self.reproducibility,
            **self.extra,
        }


class PluginBase(ABC):
    """Base class for all plugins."""

    name: str = "base_plugin"
    version: str = "1.0.0"
    description: str = ""

    # Plugin matching criteria
    supported_components: List[str] = []
    supported_vuln_types: List[str] = []

    def matches(self, component: str, vuln_type: str = None) -> bool:
        """Check if this plugin matches the given criteria."""
        component_match = (
            not self.supported_components or
            component.lower() in [c.lower() for c in self.supported_components]
        )
        vuln_match = (
            not self.supported_vuln_types or
            not vuln_type or
            vuln_type.lower() in [v.lower() for v in self.supported_vuln_types]
        )
        return component_match and vuln_match

    def get_info(self) -> Dict[str, Any]:
        """Get plugin metadata."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_components": self.supported_components,
            "supported_vuln_types": self.supported_vuln_types,
        }


class AnalyzerPlugin(PluginBase):
    """
    Base class for patch analyzer plugins.

    Analyzer plugins take a patch diff and CVE info,
    then output structured vulnerability analysis.

    LLM can generate new analyzer plugins by implementing the analyze() method.
    """

    @abstractmethod
    def analyze(
        self,
        patch_diff: str,
        cve_info: Dict[str, Any],
        knowledge: str = ""
    ) -> AnalysisResult:
        """
        Analyze the patch and extract vulnerability information.

        Args:
            patch_diff: The git diff of the patch
            cve_info: CVE information dictionary
            knowledge: Additional knowledge context

        Returns:
            AnalysisResult with vulnerability details
        """
        pass


class GeneratorPlugin(PluginBase):
    """
    Base class for PoC generator plugins.

    Generator plugins take analysis results and generate PoC code.

    LLM can generate new generator plugins by implementing the generate() method.
    """

    @abstractmethod
    def generate(
        self,
        analysis: AnalysisResult,
        cve_info: Dict[str, Any],
        knowledge: str = ""
    ) -> PoCResult:
        """
        Generate PoC code based on the analysis.

        Args:
            analysis: The vulnerability analysis result
            cve_info: CVE information dictionary
            knowledge: Additional knowledge context

        Returns:
            PoCResult with generated PoC code
        """
        pass


class VerifierPlugin(PluginBase):
    """
    Base class for PoC verifier plugins.

    Verifier plugins run PoC and verify crash/exploitation.

    LLM can generate new verifier plugins by implementing the verify() method.
    """

    @abstractmethod
    def verify(
        self,
        poc: PoCResult,
        chrome_path: str = None,
        d8_path: str = None,
    ) -> VerifyResult:
        """
        Verify the PoC by running it.

        Args:
            poc: The PoC to verify
            chrome_path: Path to Chrome executable
            d8_path: Path to d8 (V8 shell) executable

        Returns:
            VerifyResult with crash information
        """
        pass
