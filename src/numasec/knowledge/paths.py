"""NumaSec - Knowledge Base Path Resolution.

Provides reliable access to knowledge base files whether running from:
- Development (source checkout)
- Installed package (pip install numasec)
- Editable install (pip install -e .)

Uses importlib.resources for Python 3.11+ compatibility.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator
import logging

logger = logging.getLogger(__name__)


def get_knowledge_dir() -> Path:
    """
    Get the path to the knowledge_data directory.
    
    Returns:
        Path to knowledge_data directory containing .md files
        
    Raises:
        RuntimeError: If knowledge directory cannot be found
    """
    if sys.version_info >= (3, 9):
        from importlib.resources import files, as_file
        
        try:
            # Try to get from installed package
            pkg_files = files("numasec.knowledge_data")
            # For traversable, we need to get the actual path
            # This works for both installed packages and editable installs
            with as_file(pkg_files) as path:
                if path.exists():
                    return Path(path)
        except (TypeError, ModuleNotFoundError):
            pass
    
    # Fallback: Try relative to this file
    # knowledge/paths.py -> knowledge/ -> numasec/ -> knowledge_data/
    fallback_path = Path(__file__).parent.parent / "knowledge_data"
    if fallback_path.exists():
        return fallback_path
    
    # Last resort: Check if we're in a development environment
    # Look for knowledge_data relative to src/numasec
    dev_path = Path(__file__).parent.parent / "knowledge_data"
    if dev_path.exists():
        return dev_path
    
    raise RuntimeError(
        "Could not find knowledge_data directory. "
        "This might indicate a broken installation. "
        "Try reinstalling: pip install --force-reinstall numasec"
    )


def get_knowledge_subdir(subdir: str) -> Path:
    """
    Get a subdirectory within the knowledge base.
    
    Args:
        subdir: Subdirectory name (e.g., "payloads", "enterprise", "attack_chains")
        
    Returns:
        Path to the subdirectory
        
    Raises:
        RuntimeError: If directory doesn't exist
    """
    base = get_knowledge_dir()
    path = base / subdir
    
    if not path.exists():
        raise RuntimeError(f"Knowledge subdirectory not found: {subdir}")
    
    return path


def iter_knowledge_files(pattern: str = "*.md") -> Iterator[Path]:
    """
    Iterate over knowledge files matching a pattern.
    
    Args:
        pattern: Glob pattern (default: "*.md")
        
    Yields:
        Path objects for matching files
    """
    base = get_knowledge_dir()
    yield from base.glob(pattern)


def iter_knowledge_files_recursive(pattern: str = "**/*.md") -> Iterator[Path]:
    """
    Recursively iterate over knowledge files matching a pattern.
    
    Args:
        pattern: Glob pattern (default: "**/*.md" for all markdown files)
        
    Yields:
        Path objects for matching files
    """
    base = get_knowledge_dir()
    yield from base.glob(pattern)


# Pre-compute common paths for performance
_KNOWLEDGE_DIR: Path | None = None


def get_cached_knowledge_dir() -> Path:
    """Get cached knowledge directory path (faster for repeated calls)."""
    global _KNOWLEDGE_DIR
    if _KNOWLEDGE_DIR is None:
        _KNOWLEDGE_DIR = get_knowledge_dir()
    return _KNOWLEDGE_DIR
