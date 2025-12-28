"""
Plugin Helper Modules for Generators

Helper modules used by generator plugins.
"""

from .poc_template_library import (
    PoCTemplateLibrary,
    PoCTemplate,
)

from .iterative_poc_optimizer import (
    IterativePoCOptimizer,
    OptimizationResult,
)

from .template_auto_learner import (
    TemplateAutoLearner,
    Pattern,
)

from .cpp_to_js_converter import (
    CppToJsConverter,
)

from .exploit_chain import (  # Phase 5.2
    ExploitChain,
    ExploitStep,
    ChainOrchestrator,
    create_simple_chain,
)

__all__ = [
    "PoCTemplateLibrary",
    "PoCTemplate",
    "IterativePoCOptimizer",
    "OptimizationResult",
    "TemplateAutoLearner",
    "Pattern",
    "CppToJsConverter",
    "ExploitChain",
    "ExploitStep",
    "ChainOrchestrator",
    "create_simple_chain",
]
