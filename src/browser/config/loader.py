"""
Configuration Loader

Loads configuration from YAML files and environment variables.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from .settings import Settings


class ConfigLoader:
    """
    Loads and manages configuration.

    Priority order (highest to lowest):
    1. Environment variables
    2. User config file (~/.chrome_cve/config.yaml)
    3. Project config file (./config.yaml)
    4. Default values
    """

    DEFAULT_CONFIG_PATHS = [
        Path("config.yaml"),
        Path("config.yml"),
        Path.home() / ".chrome_cve" / "config.yaml",
    ]

    def __init__(self, config_path: str = None):
        self.config_path = Path(config_path) if config_path else None
        self._config: Dict[str, Any] = {}
        self._settings: Optional[Settings] = None

    def load(self) -> Settings:
        """Load configuration and return Settings object."""
        # Start with defaults
        self._config = self._get_defaults()

        # Load from file
        config_file = self._find_config_file()
        if config_file:
            file_config = self._load_yaml(config_file)
            self._merge_config(self._config, file_config)

        # Override with environment variables
        self._apply_env_overrides()

        # Create Settings object
        self._settings = Settings.from_dict(self._config)
        return self._settings

    def _find_config_file(self) -> Optional[Path]:
        """Find the configuration file to use."""
        if self.config_path and self.config_path.exists():
            return self.config_path

        for path in self.DEFAULT_CONFIG_PATHS:
            if path.exists():
                return path

        return None

    def _load_yaml(self, path: Path) -> Dict[str, Any]:
        """Load a YAML file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Warning: Failed to load config from {path}: {e}")
            return {}

    def _merge_config(self, base: Dict, override: Dict) -> None:
        """Merge override config into base config."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides."""
        env_mappings = {
            "OPENAI_API_KEY": ("llm", "openai_api_key"),
            "OPENAI_BASE_URL": ("llm", "openai_base_url"),
            "ANTHROPIC_API_KEY": ("llm", "anthropic_api_key"),
            "ANTHROPIC_BASE_URL": ("llm", "anthropic_base_url"),
            "LLM_MODEL": ("llm", "default_model"),
            "CHROME_PATH": ("execution", "chrome_path"),
            "D8_PATH": ("execution", "d8_path"),
            "OUTPUT_DIR": ("general", "output_dir"),
        }

        for env_var, path in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                self._set_nested(self._config, path, value)

    def _set_nested(self, d: Dict, path: tuple, value: Any) -> None:
        """Set a value at a nested path."""
        for key in path[:-1]:
            if key not in d:
                d[key] = {}
            d = d[key]
        d[path[-1]] = value

    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            "general": {
                "output_dir": "./output",
                "log_level": "INFO",
            },
            "llm": {
                "default_model": "gpt-4o",
                "temperature": 0.0,
                "max_retries": 3,
                "timeout": 120,
                "openai_base_url": "",
                "anthropic_base_url": "",
            },
            "intel": {
                "nvd_api_key": "",
                "github_token": "",
                "timeout": 30,
                "cache_ttl": 3600,
            },
            "execution": {
                "chrome_path": "",
                "d8_path": "",
                "timeout": 60,
                "asan_enabled": True,
            },
            "memory": {
                "storage_path": "./volumes/memory",
                "vector_db_path": "./volumes/vectors",
            },
            "agents": {
                "max_retries": 3,
                "critic_enabled": True,
            },
        }


# Global settings instance
_global_settings: Optional[Settings] = None


def load_config(config_path: str = None) -> Settings:
    """Load configuration and return Settings object."""
    global _global_settings
    loader = ConfigLoader(config_path)
    _global_settings = loader.load()
    return _global_settings


def get_settings() -> Settings:
    """Get the current settings. Load if not already loaded."""
    global _global_settings
    if _global_settings is None:
        return load_config()
    return _global_settings
