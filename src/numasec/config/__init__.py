"""Configuration package for NumaSec.

Pydantic-based settings with environment and YAML config support.
"""

from numasec.config.settings import Settings, get_settings

__all__ = ["Settings", "get_settings"]
