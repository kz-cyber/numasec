"""
NumaSec - Stdio Transport

Async subprocess-based transport for MCP communication via stdin/stdout.
This is the standard transport for local MCP servers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from dataclasses import dataclass, field
from typing import Any

from numasec.client.transports.base import (
    Transport,
    TransportConfig,
    TransportError,
    ConnectionError,
    ProtocolError,
)


logger = logging.getLogger("numasec.transport.stdio")


@dataclass
class StdioConfig(TransportConfig):
    """Stdio transport configuration."""
    command: list[str] = field(default_factory=lambda: [
        sys.executable, "-m", "numasec.mcp", "--stdio"
    ])
    startup_timeout: float = 10.0


class StdioTransport(Transport):
    """
    Async stdio-based MCP transport.
    
    Spawns the MCP server as a subprocess and communicates
    via JSON-RPC over stdin/stdout.
    
    Features:
    - Non-blocking async I/O
    - Automatic process lifecycle management
    - Graceful shutdown with cleanup
    - Request/response correlation
    
    Usage:
        async with StdioTransport() as transport:
            result = await transport.send_request("tools/list", {})
    """
    
    def __init__(self, config: StdioConfig | None = None):
        super().__init__(config)
        self.config: StdioConfig = config or StdioConfig()
        self._process: asyncio.subprocess.Process | None = None
        self._pending_requests: dict[int, asyncio.Future] = {}
        self._reader_task: asyncio.Task | None = None
        self._read_lock = asyncio.Lock()
    
    async def connect(self) -> None:
        """Start MCP server subprocess and initialize connection."""
        if self._connected:
            return
        
        logger.info(f"Starting MCP server: {' '.join(self.config.command)}")
        
        try:
            self._process = await asyncio.create_subprocess_exec(
                *self.config.command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as e:
            raise ConnectionError(f"Failed to start MCP server: {e}") from e
        
        # Start background reader task
        self._reader_task = asyncio.create_task(self._read_responses())
        
        # Initialize MCP protocol
        try:
            init_result = await asyncio.wait_for(
                self.send_request("initialize", {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                        "prompts": {},
                    },
                    "clientInfo": {
                        "name": "numasec-client",
                        "version": "2.3.0"
                    }
                }),
                timeout=self.config.startup_timeout
            )
            logger.info(f"MCP initialized: {init_result.get('serverInfo', {})}")
            self._connected = True
            
        except asyncio.TimeoutError:
            await self.disconnect()
            raise ConnectionError("MCP server initialization timed out")
        except Exception as e:
            await self.disconnect()
            raise ConnectionError(f"MCP initialization failed: {e}") from e
    
    async def disconnect(self) -> None:
        """Stop MCP server subprocess."""
        self._connected = False
        
        # Cancel reader task
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None
        
        # Terminate process
        if self._process:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
            except ProcessLookupError:
                pass  # Already dead
            self._process = None
        
        # Cancel pending requests
        for future in self._pending_requests.values():
            if not future.done():
                future.cancel()
        self._pending_requests.clear()
        
        logger.info("MCP transport disconnected")
    
    async def send_request(
        self, 
        method: str, 
        params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Send JSON-RPC request and wait for response."""
        if not self._process or not self._process.stdin:
            raise TransportError("Not connected to MCP server")
        
        request_id = self._next_request_id()
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {}
        }
        
        # Create future for response
        response_future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_requests[request_id] = response_future
        
        try:
            # Send request
            request_json = json.dumps(request) + "\n"
            self._process.stdin.write(request_json.encode())
            await self._process.stdin.drain()
            
            logger.debug(f"Sent: {method} (id={request_id})")
            
            # Wait for response with timeout
            response = await asyncio.wait_for(
                response_future,
                timeout=self.config.timeout
            )
            
            return response
            
        except asyncio.TimeoutError:
            raise TimeoutError(f"Request {method} timed out after {self.config.timeout}s")
        finally:
            self._pending_requests.pop(request_id, None)
    
    async def _read_responses(self) -> None:
        """Background task to read and dispatch responses."""
        if not self._process or not self._process.stdout:
            return
        
        try:
            while self._connected or self._pending_requests:
                line = await self._process.stdout.readline()
                if not line:
                    break
                
                try:
                    response = json.loads(line.decode())
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON from MCP server: {e}")
                    continue
                
                request_id = response.get("id")
                if request_id is None:
                    # Notification (no id) - log and ignore for now
                    logger.debug(f"Received notification: {response.get('method')}")
                    continue
                
                future = self._pending_requests.get(request_id)
                if not future:
                    logger.warning(f"Received response for unknown request: {request_id}")
                    continue
                
                if "error" in response:
                    error = response["error"]
                    future.set_exception(ProtocolError(
                        code=error.get("code", -1),
                        message=error.get("message", "Unknown error"),
                        data=error.get("data")
                    ))
                else:
                    future.set_result(response.get("result", {}))
                    
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error reading MCP responses: {e}")
            # Fail all pending requests
            for future in self._pending_requests.values():
                if not future.done():
                    future.set_exception(TransportError(f"Connection lost: {e}"))
