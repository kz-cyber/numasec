"""MCP Server package for NumaSec.

This module implements the Model Context Protocol (MCP) server,
exposing 26 tools, 5 resources, and 12 prompts for AI integration.
"""

from numasec.mcp.server import (
    create_server,
    get_server_state,
    run_server,
    ServerState,
)
from numasec.mcp.tools import (
    call_tool,
    get_all_tool_definitions,
    TOOL_RISK_MAP,
)
from numasec.mcp.resources import (
    read_resource,
    get_all_resource_definitions,
)
from numasec.mcp.prompts import (
    get_prompt,
    get_all_prompt_definitions,
)

__all__ = [
    # Server
    "create_server",
    "get_server_state",
    "run_server",
    "ServerState",
    # Tools
    "call_tool",
    "get_all_tool_definitions",
    "TOOL_RISK_MAP",
    # Resources
    "read_resource",
    "get_all_resource_definitions",
    # Prompts
    "get_prompt",
    "get_all_prompt_definitions",
]
