# Browser CVE Reproduction Framework
#
# Multi-agent based CVE reproduction pipeline

from .data import ChromiumCVEProcessor, CVEInfo, PatchInfo

from .agents import (
    BrowserCVEAgent,
    BrowserCVEAgentWithTools,
    XMLOutputParser,
    BaseReproAgent,
    AgentMessage,
    AgentState,
    OrchestratorAgent,
    AnalyzerAgent,
    GeneratorAgent,
    VerifierAgent,
    CriticAgent,
)

from .services import (
    CodeQLService,
    GhidraService,
    LLMService,
    LLMSession,
    create_llm_service,
)

from .knowledge import (
    get_component_knowledge,
    get_vulnerability_patterns,
    get_debugging_guide,
    detect_component_from_path,
    normalize_component,
    get_knowledge_for_files,
    get_all_component_names,
)

__all__ = [
    # Data
    'ChromiumCVEProcessor',
    'CVEInfo',
    'PatchInfo',
    # Agents
    'BrowserCVEAgent',
    'BrowserCVEAgentWithTools',
    'XMLOutputParser',
    'BaseReproAgent',
    'AgentMessage',
    'AgentState',
    'OrchestratorAgent',
    'AnalyzerAgent',
    'GeneratorAgent',
    'VerifierAgent',
    'CriticAgent',
    # Services
    'CodeQLService',
    'GhidraService',
    'LLMService',
    'LLMSession',
    'create_llm_service',
    # Knowledge
    'get_component_knowledge',
    'get_vulnerability_patterns',
    'get_debugging_guide',
    'detect_component_from_path',
    'normalize_component',
    'get_knowledge_for_files',
    'get_all_component_names',
]
