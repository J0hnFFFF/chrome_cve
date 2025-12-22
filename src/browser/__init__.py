# Browser CVE Reproduction Framework

from .main import BrowserCVEReproducer
from .data import ChromiumCVEProcessor, CVEInfo, PatchInfo
from .agents import PatchAnalyzer, PoCGenerator, CrashVerifier
from .services import CodeQLService, GhidraService
from .knowledge import (
    get_component_knowledge,
    get_vulnerability_patterns,
    get_debugging_guide,
    detect_component_from_path,
    normalize_component,
    get_knowledge_for_files,
    get_all_component_names,
)
