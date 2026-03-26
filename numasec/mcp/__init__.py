"""MCP server — primary interface for numasec.

Three tool layers:
  - Atomic tools bridged from ToolRegistry
  - Intelligence tools (KB, CWE, planner)
  - State & reporting tools (findings, reports)
"""

from numasec.mcp._security import is_internal_target
from numasec.mcp.server import (
    InvalidTarget,
    RateLimiter,
    RateLimitExceeded,
    SessionRateLimiter,
    create_mcp_server,
    run_mcp_server,
    validate_target,
)

__all__ = [
    "InvalidTarget",
    "RateLimitExceeded",
    "RateLimiter",
    "SessionRateLimiter",
    "create_mcp_server",
    "is_internal_target",
    "run_mcp_server",
    "validate_target",
]
