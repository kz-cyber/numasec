"""
NumaSec - Direct Transport

In-process transport that calls MCP handlers directly.
Fastest option for local execution - no subprocess overhead.
"""

from __future__ import annotations

import logging
from typing import Any

from numasec.client.transports.base import (
    Transport,
    TransportConfig,
    ProtocolError,
)


logger = logging.getLogger("numasec.transport.direct")


class DirectTransport(Transport):
    """
    In-process MCP transport.
    
    Calls MCP tool handlers directly without spawning a subprocess.
    This is the fastest option for local execution.
    
    Features:
    - Zero overhead (no subprocess, no serialization)
    - Perfect for testing
    - Same API as StdioTransport
    
    Usage:
        async with DirectTransport() as transport:
            result = await transport.send_request("tools/call", {
                "name": "web_request",
                "arguments": {"url": "https://example.com"}
            })
    """
    
    def __init__(self, config: TransportConfig | None = None):
        super().__init__(config)
        self._tools: list[dict] = []
        self._server_info: dict = {}
    
    async def connect(self) -> None:
        """Load MCP tools directly."""
        if self._connected:
            return
        
        from numasec.mcp import get_all_tool_definitions
        
        self._tools = get_all_tool_definitions()
        self._server_info = {
            "name": "numasec-mcp-direct",
            "version": "2.3.0"
        }
        self._connected = True
        
        logger.info(f"Direct transport connected. {len(self._tools)} tools available.")
    
    async def disconnect(self) -> None:
        """No-op for direct transport."""
        self._connected = False
        logger.info("Direct transport disconnected")
    
    async def send_request(
        self, 
        method: str, 
        params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Handle MCP request directly."""
        params = params or {}
        
        # Route to appropriate handler
        if method == "initialize":
            return self._handle_initialize(params)
        elif method == "tools/list":
            return self._handle_tools_list(params)
        elif method == "tools/call":
            return await self._handle_tools_call(params)
        elif method == "resources/list":
            return self._handle_resources_list(params)
        elif method == "resources/read":
            return await self._handle_resources_read(params)
        elif method == "prompts/list":
            return self._handle_prompts_list(params)
        elif method == "prompts/get":
            return self._handle_prompts_get(params)
        else:
            raise ProtocolError(-32601, f"Method not found: {method}")
    
    def _handle_initialize(self, params: dict) -> dict:
        """Handle initialize request."""
        return {
            "protocolVersion": "2024-11-05",
            "serverInfo": self._server_info,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"listChanged": False},
                "prompts": {"listChanged": False},
            }
        }
    
    def _handle_tools_list(self, params: dict) -> dict:
        """Handle tools/list request."""
        return {"tools": self._tools}
    
    async def _handle_tools_call(self, params: dict) -> dict:
        """Handle tools/call request."""
        from numasec.mcp import call_tool
        
        name = params.get("name", "")
        arguments = params.get("arguments", {})
        
        result = await call_tool(name, arguments)
        return result
    
    def _handle_resources_list(self, params: dict) -> dict:
        """Handle resources/list request."""
        from numasec.mcp.resources import get_all_resource_definitions
        return {"resources": get_all_resource_definitions()}
    
    async def _handle_resources_read(self, params: dict) -> dict:
        """Handle resources/read request."""
        from numasec.mcp.resources import read_resource
        uri = params.get("uri", "")
        return await read_resource(uri)
    
    def _handle_prompts_list(self, params: dict) -> dict:
        """Handle prompts/list request."""
        from numasec.mcp.prompts import get_all_prompt_definitions
        return {"prompts": get_all_prompt_definitions()}
    
    def _handle_prompts_get(self, params: dict) -> dict:
        """Handle prompts/get request."""
        from numasec.mcp.prompts import get_prompt
        name = params.get("name", "")
        arguments = params.get("arguments", {})
        return get_prompt(name, arguments)
