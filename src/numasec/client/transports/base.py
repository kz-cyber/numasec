"""
NumaSec - Transport Base Class

Abstract interface for MCP communication transports.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class TransportConfig:
    """Transport configuration."""
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0


class Transport(ABC):
    """
    Abstract base class for MCP transports.
    
    Transports handle the low-level communication with MCP servers,
    abstracting away the protocol details (stdio, HTTP, etc.).
    """
    
    def __init__(self, config: TransportConfig | None = None):
        self.config = config or TransportConfig()
        self._connected = False
        self._request_id = 0
    
    @property
    def connected(self) -> bool:
        """Check if transport is connected."""
        return self._connected
    
    def _next_request_id(self) -> int:
        """Get next request ID for JSON-RPC."""
        self._request_id += 1
        return self._request_id
    
    @abstractmethod
    async def connect(self) -> None:
        """
        Establish connection to MCP server.
        
        Raises:
            ConnectionError: If connection fails
        """
        ...
    
    @abstractmethod
    async def disconnect(self) -> None:
        """
        Close connection to MCP server.
        
        Should be idempotent (safe to call multiple times).
        """
        ...
    
    @abstractmethod
    async def send_request(
        self, 
        method: str, 
        params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Send a JSON-RPC request and wait for response.
        
        Args:
            method: JSON-RPC method name (e.g., "tools/call")
            params: Method parameters
            
        Returns:
            Response result dict
            
        Raises:
            TransportError: If sending/receiving fails
            TimeoutError: If response times out
        """
        ...
    
    async def __aenter__(self) -> "Transport":
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.disconnect()


class TransportError(Exception):
    """Base exception for transport errors."""
    pass


class ConnectionError(TransportError):
    """Failed to connect to MCP server."""
    pass


class ProtocolError(TransportError):
    """MCP protocol error."""
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"MCP error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data
