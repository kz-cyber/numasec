"""
NumaSec - Configuration Settings

Pydantic-based settings with environment variable and YAML file support.
"""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ══════════════════════════════════════════════════════════════════════════════
# Enums
# ══════════════════════════════════════════════════════════════════════════════


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    CLAUDE = "claude"
    DEEPSEEK = "deepseek"
    OPENAI = "openai"
    LOCAL = "local"


class ApprovalMode(str, Enum):
    """Human-in-the-loop approval modes."""

    SUPERVISED = "supervised"  # Approve everything
    SEMI_AUTO = "semi_auto"  # Auto-approve LOW, prompt for MEDIUM+
    AUTONOMOUS = "autonomous"  # Lab/Training only - no production!


class ReportTemplate(str, Enum):
    """Available report templates."""

    PTES = "ptes"
    OWASP = "owasp"
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    CUSTOM = "custom"


# ══════════════════════════════════════════════════════════════════════════════
# Sub-configurations
# ══════════════════════════════════════════════════════════════════════════════


class LLMSettings(BaseModel):
    """LLM provider configuration."""

    primary_provider: LLMProvider = LLMProvider.DEEPSEEK
    fallback_provider: LLMProvider | None = None

    # API Keys (loaded from environment)
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None
    deepseek_api_key: str | None = None

    # Model selection
    claude_model: str = "claude-sonnet-4-20250514"
    deepseek_model: str = "deepseek-chat"
    openai_model: str = "gpt-4o"
    local_model: str = "llama3.3"
    local_endpoint: str = "http://localhost:11434/v1"

    # Request settings
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout: int = 120


class CacheSettings(BaseModel):
    """Semantic cache configuration (LanceDB-based)."""

    enabled: bool = True
    path: Path = Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec"))) / "cache"
    similarity_threshold: float = 0.95
    ttl_hours: int = 168  # 7 days
    max_entries: int = 10000


class DatabaseSettings(BaseModel):
    """SQLite database configuration."""

    path: Path = Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec"))) / "numasec.db"
    echo: bool = False  # SQL logging


class KnowledgeSettings(BaseModel):
    """Knowledge base configuration."""

    path: Path = Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec"))) / "knowledge"
    embedding_model: str = "all-MiniLM-L6-v2"
    chunk_size: int = 512
    chunk_overlap: int = 50


class ReportingSettings(BaseModel):
    """Report generation configuration."""

    default_template: ReportTemplate = ReportTemplate.PTES
    output_dir: Path = Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec"))) / "reports"
    include_evidence: bool = True
    include_raw_output: bool = False


class ApprovalSettings(BaseModel):
    """Human-in-the-loop approval configuration."""

    default_mode: ApprovalMode = ApprovalMode.SUPERVISED
    timeout_seconds: int = 300  # 5 minutes
    require_reason_for_rejection: bool = True


class LoggingSettings(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    format: str = "json"  # json or console
    file: Path | None = None


# ══════════════════════════════════════════════════════════════════════════════
# Main Settings
# ══════════════════════════════════════════════════════════════════════════════


class Settings(BaseSettings):
    """
    Main configuration for NumaSec.

    Configuration is loaded in order of precedence:
    1. Environment variables (NUMASEC_*)
    2. YAML config file (~/.numasec/config.yaml)
    3. Default values

    Environment variables use NUMASEC_ prefix and double underscore for nesting:
        NUMASEC_LLM__PRIMARY_PROVIDER=claude
        NUMASEC_APPROVAL__DEFAULT_MODE=semi_auto
    """

    model_config = SettingsConfigDict(
        env_prefix="NUMASEC_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    # Sub-configurations
    llm: LLMSettings = Field(default_factory=LLMSettings)
    cache: CacheSettings = Field(default_factory=CacheSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    knowledge: KnowledgeSettings = Field(default_factory=KnowledgeSettings)
    reporting: ReportingSettings = Field(default_factory=ReportingSettings)
    approval: ApprovalSettings = Field(default_factory=ApprovalSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    # Global settings
    data_dir: Path = Field(
        default=Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec"))),
        description="Base directory for all NumaSec data",
    )
    engagement_dir: Path = Field(
        default=Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec"))) / "engagements",
        description="Directory for engagement data",
    )

    @field_validator("data_dir", "engagement_dir", mode="before")
    @classmethod
    def expand_path(cls, v: str | Path) -> Path:
        """Expand ~ in paths."""
        if isinstance(v, str):
            v = Path(v)
        return v.expanduser()

    def ensure_directories(self) -> None:
        """Create all required directories."""
        dirs = [
            self.data_dir,
            self.engagement_dir,
            self.cache.path,
            self.knowledge.path,
            self.reporting.output_dir,
            self.database.path.parent,
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_yaml(cls, path: Path | str) -> "Settings":
        """Load settings from YAML file."""
        path = Path(path)
        if not path.exists():
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        return cls(**data)

    def to_yaml(self, path: Path | str) -> None:
        """Save settings to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dict, handling enums and paths
        data = self._to_serializable_dict()

        with open(path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)

    def _to_serializable_dict(self) -> dict[str, Any]:
        """Convert settings to a serializable dictionary."""

        def convert(obj: Any) -> Any:
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, Path):
                return str(obj)
            if isinstance(obj, BaseModel):
                return {k: convert(v) for k, v in obj.model_dump().items()}
            if isinstance(obj, dict):
                return {k: convert(v) for k, v in obj.items()}
            return obj

        return convert(self.model_dump())


# ══════════════════════════════════════════════════════════════════════════════
# Settings Singleton
# ══════════════════════════════════════════════════════════════════════════════


@lru_cache
def get_settings() -> Settings:
    """
    Get the singleton Settings instance.

    Loads configuration from:
    1. Environment variables
    2. ~/.numasec/config.yaml (if exists)
    3. Default values
    """
    default_base = Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec")))
    config_path = default_base / "config.yaml"

    # Load from YAML if exists
    if config_path.exists():
        settings = Settings.from_yaml(config_path)
    else:
        settings = Settings()

    # Override with environment variables
    # (Pydantic handles this automatically via env_prefix)

    # Ensure directories exist
    settings.ensure_directories()

    return settings


def reset_settings() -> None:
    """Clear the cached settings (useful for testing)."""
    get_settings.cache_clear()


# ══════════════════════════════════════════════════════════════════════════════
# Default Config Template
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_CONFIG_YAML = """\
# NumaSec Configuration
# ~/.numasec/config.yaml

llm:
  primary_provider: deepseek
  fallback_provider: null
  # API keys should be set via environment variables:
  # NUMASEC_LLM__ANTHROPIC_API_KEY
  # NUMASEC_LLM__DEEPSEEK_API_KEY
  # NUMASEC_LLM__OPENAI_API_KEY
  claude_model: claude-sonnet-4-20250514
  deepseek_model: deepseek-chat
  openai_model: gpt-4o
  local_model: llama3.3
  local_endpoint: http://localhost:11434/v1
  max_tokens: 4096
  temperature: 0.7
  timeout: 120

cache:
  enabled: true
  path: ~/.numasec/cache
  similarity_threshold: 0.95
  ttl_hours: 168
  max_entries: 10000

database:
  path: ~/.numasec/numasec.db
  echo: false

knowledge:
  path: ~/.numasec/knowledge
  embedding_model: all-MiniLM-L6-v2
  chunk_size: 512
  chunk_overlap: 50

reporting:
  default_template: ptes
  output_dir: ~/.numasec/reports
  include_evidence: true
  include_raw_output: false

approval:
  # Modes: supervised, semi_auto, autonomous
  # WARNING: autonomous mode is for LAB/TRAINING only!
  default_mode: supervised
  timeout_seconds: 300
  require_reason_for_rejection: true

logging:
  level: INFO
  format: json
  file: null

# Global paths
data_dir: ~/.numasec
engagement_dir: ~/.numasec/engagements
"""


def create_default_config(path: Path | str | None = None) -> Path:
    """Create default configuration file."""
    if path is None:
        default_base = Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec")))
        path = default_base / "config.yaml"
    else:
        path = Path(path)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(DEFAULT_CONFIG_YAML)
    return path
