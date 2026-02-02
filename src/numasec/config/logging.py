"""
Logging configuration for NumaSec.

Structured logging with proper levels for RAG system visibility.
"""

import logging
import sys
from pathlib import Path


def setup_logging(level: str = "INFO", log_file: Path | None = None):
    """
    Setup structured logging for NumaSec.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file path for logging
    """
    
    # Map string to logging level
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }
    
    log_level = level_map.get(level.upper(), logging.INFO)
    
    # Format with colors for console
    format_string = (
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(format_string))
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)  # Always DEBUG in file
        file_handler.setFormatter(logging.Formatter(format_string))
        root_logger.addHandler(file_handler)
    
    # Set specific logger levels
    # External libraries should be quieter
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("lancedb").setLevel(logging.WARNING)
    
    # NumaSec loggers should be visible
    logging.getLogger("numasec").setLevel(log_level)
    logging.getLogger("numasec.agent").setLevel(log_level)
    logging.getLogger("numasec.rag").setLevel(log_level)  # RAG system
    
    logging.info(f"Logging initialized at {level} level")
