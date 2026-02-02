"""
NumaSec - CLI UI Components

Rich-based UI components for the CLI.
"""

from .display import (
    console,
    get_severity_style,
    severity_badge,
    finding_card,
    finding_table,
    phase_indicator,
    phase_details,
    scope_tree,
    scope_table,
    engagement_status,
    tool_output,
    tool_approval,
    progress_bar,
    success_message,
    error_message,
    warning_message,
    info_message,
)

from .theme import (
    NumaSecUI,
    get_ui,
    Colors,
    RICH_AVAILABLE,
)

__all__ = [
    # Display components
    "console",
    "get_severity_style",
    "severity_badge",
    "finding_card",
    "finding_table",
    "phase_indicator",
    "phase_details",
    "scope_tree",
    "scope_table",
    "engagement_status",
    "tool_output",
    "tool_approval",
    "progress_bar",
    "success_message",
    "error_message",
    "warning_message",
    "info_message",
    # Theme components
    "NumaSecUI",
    "get_ui",
    "Colors",
    "RICH_AVAILABLE",
]
