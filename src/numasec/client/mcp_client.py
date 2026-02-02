"""
NumaSec - Async MCP Client

Core MCP protocol client with full async support.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from numasec.client.transports.base import Transport, TransportError
from numasec.client.providers.base import ToolDefinition


logger = logging.getLogger("numasec.mcp_client")


@dataclass
class ToolResult:
    """Result from an MCP tool call."""
    tool_name: str
    success: bool
    content: str
    is_error: bool = False
    raw: dict | None = None


@dataclass 
class Resource:
    """An MCP resource."""
    uri: str
    name: str
    description: str
    mime_type: str = "text/plain"


@dataclass
class Prompt:
    """An MCP prompt."""
    name: str
    description: str
    arguments: list[dict]


class AsyncMCPClient:
    """
    Async MCP protocol client.
    
    Provides a high-level interface for interacting with MCP servers,
    handling protocol details and providing typed responses.
    
    Features:
    - Transport-agnostic (works with Stdio, SSE, or Direct)
    - Full MCP protocol support (tools, resources, prompts)
    - Parallel tool execution
    - Automatic error handling
    
    Usage:
        transport = StdioTransport()
        async with AsyncMCPClient(transport) as client:
            tools = await client.list_tools()
            result = await client.call_tool("web_request", {"url": "..."})
    """
    
    def __init__(self, transport: Transport):
        self.transport = transport
        self._tools: list[ToolDefinition] = []
        self._resources: list[Resource] = []
        self._prompts: list[Prompt] = []
        self._server_info: dict = {}
        self._session_data: dict[str, Any] = {}  # Persistent session state
    
    @property
    def tools(self) -> list[ToolDefinition]:
        """Get cached tool definitions."""
        return self._tools
    
    @property
    def server_info(self) -> dict:
        """Get server information."""
        return self._server_info
    
    async def connect(self) -> None:
        """Connect to MCP server and load capabilities."""
        await self.transport.connect()
        await self._load_capabilities()
        logger.info(f"MCP client connected. {len(self._tools)} tools available.")
    
    async def disconnect(self) -> None:
        """Disconnect from MCP server."""
        await self.transport.disconnect()
        self._tools.clear()
        self._resources.clear()
        self._prompts.clear()
    
    async def _load_capabilities(self) -> None:
        """Load tools, resources, and prompts from server."""
        # Load tools
        tools_response = await self.transport.send_request("tools/list", {})
        self._tools = [
            ToolDefinition.from_mcp_format(t)
            for t in tools_response.get("tools", [])
        ]
        
        # Load resources (optional, may not be supported)
        try:
            resources_response = await self.transport.send_request("resources/list", {})
            self._resources = [
                Resource(
                    uri=r.get("uri", ""),
                    name=r.get("name", ""),
                    description=r.get("description", ""),
                    mime_type=r.get("mimeType", "text/plain"),
                )
                for r in resources_response.get("resources", [])
            ]
        except Exception:
            self._resources = []
        
        # Load prompts (optional)
        try:
            prompts_response = await self.transport.send_request("prompts/list", {})
            self._prompts = [
                Prompt(
                    name=p.get("name", ""),
                    description=p.get("description", ""),
                    arguments=p.get("arguments", []),
                )
                for p in prompts_response.get("prompts", [])
            ]
        except Exception:
            self._prompts = []
    
    async def call_tool(
        self, 
        name: str, 
        arguments: dict[str, Any] | None = None
    ) -> ToolResult:
        """
        Call an MCP tool.
        
        Args:
            name: Tool name
            arguments: Tool arguments
            
        Returns:
            ToolResult with content and status
        """
        arguments = arguments or {}
        
        # Inject session data for stateful tools (e.g., cookies)
        if name == "web_request" and self._session_data.get("cookies"):
            if "cookies" not in arguments:
                arguments["cookies"] = self._session_data["cookies"]
        
        try:
            result = await self.transport.send_request("tools/call", {
                "name": name,
                "arguments": arguments
            })
            
            # Extract content from MCP response
            content_items = result.get("content", [])
            is_error = result.get("isError", False)
            
            content_text = ""
            for item in content_items:
                if item.get("type") == "text":
                    content_text += item.get("text", "")
            
            # Update session data from tool results
            self._update_session_from_result(name, content_text)
            
            return ToolResult(
                tool_name=name,
                success=not is_error,
                content=content_text,
                is_error=is_error,
                raw=result,
            )
            
        except TransportError as e:
            return ToolResult(
                tool_name=name,
                success=False,
                content=f"Transport error: {e}",
                is_error=True,
            )
        except Exception as e:
            return ToolResult(
                tool_name=name,
                success=False,
                content=f"Error calling {name}: {e}",
                is_error=True,
            )
    
    async def call_tools_parallel(
        self, 
        calls: list[tuple[str, dict[str, Any]]]
    ) -> list[ToolResult]:
        """
        Execute multiple tool calls in parallel.
        
        Args:
            calls: List of (tool_name, arguments) tuples
            
        Returns:
            List of ToolResults in same order as input
        """
        import asyncio
        
        tasks = [
            self.call_tool(name, args)
            for name, args in calls
        ]
        return await asyncio.gather(*tasks)
    
    def _update_session_from_result(self, tool_name: str, content: str) -> None:
        """Extract and save session data from tool results."""
        if tool_name != "web_request":
            return
        
        try:
            import json
            data = json.loads(content)
            
            # Save cookies
            if data.get("cookies"):
                if "cookies" not in self._session_data:
                    self._session_data["cookies"] = {}
                self._session_data["cookies"].update(data["cookies"])
                logger.debug(f"Session cookies updated: {list(data['cookies'].keys())}")
                
        except (json.JSONDecodeError, KeyError):
            pass
    
    async def read_resource(self, uri: str) -> str:
        """Read a resource by URI."""
        result = await self.transport.send_request("resources/read", {"uri": uri})
        contents = result.get("contents", [])
        if contents:
            return contents[0].get("text", "")
        return ""
    
    async def get_prompt(
        self, 
        name: str, 
        arguments: dict[str, Any] | None = None
    ) -> str:
        """Get a prompt by name."""
        result = await self.transport.send_request("prompts/get", {
            "name": name,
            "arguments": arguments or {}
        })
        messages = result.get("messages", [])
        return "\n".join(m.get("content", {}).get("text", "") for m in messages)
    
    async def __aenter__(self) -> "AsyncMCPClient":
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.disconnect()
