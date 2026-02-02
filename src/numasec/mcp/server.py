"""
NumaSec - MCP Server

Model Context Protocol server implementation.
Exposes 26 tools, 5 resources, and 12 prompts for AI integration.

Protocol Version: 2024-11-05
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from rich.console import Console

from .tools import get_all_tool_definitions, call_tool as tools_call_tool
from .resources import get_all_resource_definitions, read_resource as resources_read
from .prompts import get_all_prompt_definitions, get_prompt as prompts_get

console = Console(stderr=True)


# ══════════════════════════════════════════════════════════════════════════════
# Server State
# ══════════════════════════════════════════════════════════════════════════════

class ServerState:
    """Global server state."""

    def __init__(self) -> None:
        self.initialized: bool = False
        self.client_info: dict[str, Any] = {}
        self.capabilities: dict[str, Any] = {}
        self.current_engagement_id: str | None = None

    def set_engagement(self, engagement_id: str) -> None:
        """Set the current engagement."""
        self.current_engagement_id = engagement_id

    def get_engagement(self) -> str | None:
        """Get the current engagement ID."""
        return self.current_engagement_id


# Global server state
_state = ServerState()


# ══════════════════════════════════════════════════════════════════════════════
# MCP Server Implementation
# ══════════════════════════════════════════════════════════════════════════════


async def run_server(stdio: bool = True, port: int | None = None) -> None:
    """
    Run the MCP server.

    Args:
        stdio: Use stdio transport (default for Claude Desktop)
        port: Port for SSE transport (alternative to stdio)
    """
    console.print("[blue]NumaSec MCP Server v2.3.0[/blue]")
    console.print(f"[dim]Protocol: 2024-11-05[/dim]")
    console.print(f"[dim]Tools: {len(get_all_tool_definitions())} | Resources: {len(get_all_resource_definitions())} | Prompts: {len(get_all_prompt_definitions())}[/dim]")

    if stdio:
        await run_stdio_server()
    elif port:
        await run_sse_server(port)
    else:
        console.print("[red]Error: Must specify --stdio or --port[/red]")


async def run_stdio_server() -> None:
    """Run MCP server over stdio with proper message framing."""
    console.print("[dim]Running in stdio mode...[/dim]")

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

    writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
        asyncio.streams.FlowControlMixin,
        sys.stdout
    )
    writer = asyncio.StreamWriter(writer_transport, writer_protocol, None, asyncio.get_event_loop())

    try:
        while True:
            # Read line-delimited JSON
            line = await reader.readline()

            if not line:
                break

            try:
                line_str = line.decode('utf-8').strip()
                if not line_str:
                    continue

                request = json.loads(line_str)
                response = await handle_request(request)

                # Write response
                response_bytes = (json.dumps(response) + '\n').encode('utf-8')
                writer.write(response_bytes)
                await writer.drain()

            except json.JSONDecodeError as e:
                error_response = {
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                    "id": None,
                }
                writer.write((json.dumps(error_response) + '\n').encode('utf-8'))
                await writer.drain()

    except KeyboardInterrupt:
        console.print("[yellow]Server stopped.[/yellow]")
    except Exception as e:
        console.print(f"[red]Server error: {e}[/red]")


async def run_sse_server(port: int) -> None:
    """Run MCP server over SSE (Server-Sent Events)."""
    console.print(f"[dim]Starting SSE server on port {port}...[/dim]")

    # SSE implementation for web clients
    try:
        from aiohttp import web

        async def handle_sse(request: web.Request) -> web.StreamResponse:
            """Handle SSE connection."""
            response = web.StreamResponse()
            response.headers['Content-Type'] = 'text/event-stream'
            response.headers['Cache-Control'] = 'no-cache'
            response.headers['Connection'] = 'keep-alive'
            response.headers['Access-Control-Allow-Origin'] = '*'
            await response.prepare(request)

            # Send server info
            await response.write(
                f"data: {json.dumps({'type': 'connected', 'server': 'numasec', 'version': '2.3.0'})}\n\n".encode()
            )

            return response

        async def handle_message(request: web.Request) -> web.Response:
            """Handle JSON-RPC message over HTTP."""
            try:
                body = await request.json()
                response = await handle_request(body)
                return web.json_response(response)
            except Exception as e:
                return web.json_response({
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": str(e)},
                    "id": None,
                })

        app = web.Application()
        app.router.add_get('/sse', handle_sse)
        app.router.add_post('/message', handle_message)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', port)
        await site.start()

        console.print(f"[green]SSE server running on http://localhost:{port}[/green]")
        console.print(f"[dim]SSE endpoint: /sse[/dim]")
        console.print(f"[dim]Message endpoint: /message[/dim]")

        # Keep running
        await asyncio.Event().wait()

    except ImportError:
        console.print("[red]SSE server requires aiohttp. Install with: pip install aiohttp[/red]")


async def handle_request(request: dict[str, Any]) -> dict[str, Any]:
    """Handle an MCP JSON-RPC request."""
    method = request.get("method", "")
    request_id = request.get("id")
    params = request.get("params", {})

    try:
        result = await dispatch_method(method, params)
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result,
        }
    except MethodNotFoundError as e:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32601,
                "message": str(e),
            },
        }
    except InvalidParamsError as e:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32602,
                "message": str(e),
            },
        }
    except Exception as e:
        console.print(f"[red]Error handling {method}: {e}[/red]")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32603,
                "message": f"Internal error: {e}",
            },
        }


class MethodNotFoundError(Exception):
    """Method not found error."""
    pass


class InvalidParamsError(Exception):
    """Invalid parameters error."""
    pass


async def dispatch_method(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a method call to the appropriate handler."""

    # ──────────────────────────────────────────────────────────────────────────
    # Lifecycle Methods
    # ──────────────────────────────────────────────────────────────────────────

    if method == "initialize":
        _state.initialized = True
        _state.client_info = params.get("clientInfo", {})
        _state.capabilities = params.get("capabilities", {})

        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": True, "listChanged": True},
                "prompts": {"listChanged": True},
                "logging": {},
            },
            "serverInfo": {
                "name": "numasec",
                "version": "2.3.0",
            },
        }

    if method == "initialized":
        # Client acknowledged initialization
        console.print("[green]Client connected successfully[/green]")
        return {}

    if method == "ping":
        return {}

    # ──────────────────────────────────────────────────────────────────────────
    # Tools Methods
    # ──────────────────────────────────────────────────────────────────────────

    if method == "tools/list":
        cursor = params.get("cursor")
        tools = get_all_tool_definitions()

        # Handle pagination if needed
        return {
            "tools": tools,
        }

    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})

        if not tool_name:
            raise InvalidParamsError("Missing tool name")

        console.print(f"[dim]Calling tool: {tool_name}[/dim]")

        # Call the tool handler
        result = await tools_call_tool(tool_name, tool_args, _state)

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # Resources Methods
    # ──────────────────────────────────────────────────────────────────────────

    if method == "resources/list":
        return {
            "resources": get_all_resource_definitions(),
        }

    if method == "resources/read":
        uri = params.get("uri")

        if not uri:
            raise InvalidParamsError("Missing resource URI")

        console.print(f"[dim]Reading resource: {uri}[/dim]")

        content = await resources_read(uri, _state)

        return {
            "contents": [content],
        }

    if method == "resources/subscribe":
        uri = params.get("uri")
        console.print(f"[dim]Subscribed to resource: {uri}[/dim]")
        return {}

    if method == "resources/unsubscribe":
        uri = params.get("uri")
        console.print(f"[dim]Unsubscribed from resource: {uri}[/dim]")
        return {}

    # ──────────────────────────────────────────────────────────────────────────
    # Prompts Methods
    # ──────────────────────────────────────────────────────────────────────────

    if method == "prompts/list":
        return {
            "prompts": get_all_prompt_definitions(),
        }

    if method == "prompts/get":
        prompt_name = params.get("name")
        prompt_args = params.get("arguments", {})

        if not prompt_name:
            raise InvalidParamsError("Missing prompt name")

        console.print(f"[dim]Getting prompt: {prompt_name}[/dim]")

        result = await prompts_get(prompt_name, prompt_args)

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # Logging Methods
    # ──────────────────────────────────────────────────────────────────────────

    if method == "logging/setLevel":
        level = params.get("level", "info")
        console.print(f"[dim]Log level set to: {level}[/dim]")
        return {}

    # ──────────────────────────────────────────────────────────────────────────
    # Completion Methods (optional)
    # ──────────────────────────────────────────────────────────────────────────

    if method == "completion/complete":
        # Auto-completion support
        ref = params.get("ref", {})
        ref_type = ref.get("type")

        if ref_type == "ref/prompt":
            # Complete prompt argument
            return {"completion": {"values": []}}
        elif ref_type == "ref/resource":
            # Complete resource URI
            return {"completion": {"values": []}}

        return {"completion": {"values": []}}

    # Unknown method
    raise MethodNotFoundError(f"Method not found: {method}")


# ══════════════════════════════════════════════════════════════════════════════
# Notifications (Server → Client)
# ══════════════════════════════════════════════════════════════════════════════


async def notify_resource_updated(uri: str) -> None:
    """Notify client that a resource has been updated."""
    # This would write to stdout in stdio mode
    notification = {
        "jsonrpc": "2.0",
        "method": "notifications/resources/updated",
        "params": {"uri": uri},
    }
    print(json.dumps(notification), flush=True)


async def notify_resource_list_changed() -> None:
    """Notify client that the resource list has changed."""
    notification = {
        "jsonrpc": "2.0",
        "method": "notifications/resources/list_changed",
    }
    print(json.dumps(notification), flush=True)


async def notify_tool_list_changed() -> None:
    """Notify client that the tool list has changed."""
    notification = {
        "jsonrpc": "2.0",
        "method": "notifications/tools/list_changed",
    }
    print(json.dumps(notification), flush=True)


async def send_log_message(level: str, message: str, data: Any = None) -> None:
    """Send a log message to the client."""
    notification = {
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": {
            "level": level,
            "logger": "numasec",
            "data": message if data is None else {"message": message, **data},
        },
    }
    print(json.dumps(notification), flush=True)


# ══════════════════════════════════════════════════════════════════════════════
# Server Factory
# ══════════════════════════════════════════════════════════════════════════════


def create_server() -> ServerState:
    """Create and return the MCP server state."""
    return _state


def get_server_state() -> ServerState:
    """Get the global server state."""
    return _state


def main() -> None:
    """Entry point for MCP server."""
    asyncio.run(run_server(stdio=True))


if __name__ == "__main__":
    main()
