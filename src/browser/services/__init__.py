# External Analysis Services (CodeQL, Ghidra, etc.)

from .codeql_service import (
    CodeQLService,
    CodeQLResult,
    create_codeql_service,
)

from .ghidra_service import (
    GhidraService,
    GhidraFunction,
    GhidraAnalysisResult,
    create_ghidra_service,
)
