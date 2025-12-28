"""
Settings Data Classes

Typed configuration settings.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass
class LLMConfig:
    """LLM-related configuration."""
    default_model: str = "gpt-4o"
    temperature: float = 0.0
    max_retries: int = 3
    timeout: int = 120
    openai_api_key: str = ""
    openai_base_url: str = ""  # Custom base URL for OpenAI-compatible APIs
    anthropic_api_key: str = ""
    anthropic_base_url: str = ""  # Custom base URL for Anthropic API


@dataclass
class IntelConfig:
    """Intelligence collection configuration."""
    nvd_api_key: str = ""
    github_token: str = ""
    timeout: int = 30
    cache_ttl: int = 3600


@dataclass
class ExecutionConfig:
    """Execution-related configuration."""
    chrome_path: str = ""
    d8_path: str = ""
    timeout: int = 60
    asan_enabled: bool = True


@dataclass
class MemoryConfig:
    """Memory system configuration."""
    storage_path: str = "./volumes/memory"
    vector_db_path: str = "./volumes/vectors"


@dataclass
class AgentConfig:
    """Agent-related configuration."""
    max_retries: int = 3
    critic_enabled: bool = True


@dataclass
class GeneralConfig:
    """General configuration."""
    output_dir: str = "./output"
    log_level: str = "INFO"


@dataclass
class BuildConfig:
    """Build system configuration."""
    mode: str = "lightweight"  # lightweight, local_windows, hybrid, docker
    auto_fallback: bool = True
    source_root: str = "D:/src"
    msvc_path: str = ""


@dataclass
class ReviewConfig:
    """Phase 5.3: Expert Review configuration."""
    expert_review_enabled: bool = True
    auto_accept_threshold: int = 4  # Auto-accept if quality >= 4
    editor: str = ""  # Leave empty to use $EDITOR or default


@dataclass
class KnowledgeConfig:
    """Phase 5.1: Dynamic Knowledge configuration."""
    enabled: bool = True
    nvd_api_key: str = ""  # For similar CVE retrieval
    cache_dir: str = "~/.chrome_cve_cache/knowledge"


@dataclass
class ChromiumConfig:
    """Chromium source configuration."""
    source_path: str = ""  # Path to chromium/src


@dataclass
class Settings:
    """Complete application settings."""
    general: GeneralConfig = field(default_factory=GeneralConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    intel: IntelConfig = field(default_factory=IntelConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    build: BuildConfig = field(default_factory=BuildConfig)
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    agents: AgentConfig = field(default_factory=AgentConfig)
    # Phase 5 configurations
    review: ReviewConfig = field(default_factory=ReviewConfig)
    knowledge: KnowledgeConfig = field(default_factory=KnowledgeConfig)
    chromium: ChromiumConfig = field(default_factory=ChromiumConfig)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Settings":
        """Create Settings from a dictionary."""
        return cls(
            general=GeneralConfig(**d.get("general", {})),
            llm=LLMConfig(**d.get("llm", {})),
            intel=IntelConfig(**d.get("intel", {})),
            execution=ExecutionConfig(**d.get("execution", {})),
            build=BuildConfig(**d.get("build", {})),
            memory=MemoryConfig(**d.get("memory", {})),
            agents=AgentConfig(**d.get("agents", {})),
            # Phase 5
            review=ReviewConfig(**d.get("review", {})),
            knowledge=KnowledgeConfig(**d.get("knowledge", {})),
            chromium=ChromiumConfig(**d.get("chromium", {})),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "general": {
                "output_dir": self.general.output_dir,
                "log_level": self.general.log_level,
            },
            "llm": {
                "default_model": self.llm.default_model,
                "temperature": self.llm.temperature,
                "max_retries": self.llm.max_retries,
                "timeout": self.llm.timeout,
            },
            "intel": {
                "timeout": self.intel.timeout,
                "cache_ttl": self.intel.cache_ttl,
            },
            "execution": {
                "chrome_path": self.execution.chrome_path,
                "d8_path": self.execution.d8_path,
                "timeout": self.execution.timeout,
                "asan_enabled": self.execution.asan_enabled,
            },
            "memory": {
                "storage_path": self.memory.storage_path,
                "vector_db_path": self.memory.vector_db_path,
            },
            "agents": {
                "max_retries": self.agents.max_retries,
                "critic_enabled": self.agents.critic_enabled,
            },
            # Phase 5
            "review": {
                "expert_review_enabled": self.review.expert_review_enabled,
                "auto_accept_threshold": self.review.auto_accept_threshold,
            },
            "knowledge": {
                "enabled": self.knowledge.enabled,
                "cache_dir": self.knowledge.cache_dir,
            },
            "chromium": {
                "source_path": self.chromium.source_path,
            },
        }

