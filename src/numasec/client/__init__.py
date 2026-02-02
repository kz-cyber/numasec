"""
NumaSec - MCP Client Package

A modular, provider-agnostic MCP client for AI-powered penetration testing.

Usage:
    from numasec.client import Orchestrator, AsyncMCPClient
    from numasec.client.transports import DirectTransport
    from numasec.client.providers import DeepSeekProvider
    
    async def main():
        # Create transport and client
        transport = DirectTransport()
        async with AsyncMCPClient(transport) as mcp:
            # Create provider
            provider = DeepSeekProvider()
            
            # Create orchestrator
            orchestrator = Orchestrator(mcp, provider)
            
            # Solve a challenge
            result = await orchestrator.solve(
                target="http://example.com",
                objective="Find the flag"
            )
            print(f"Flag: {result.flag}")
"""

from numasec.client.mcp_client import AsyncMCPClient, ToolResult
from numasec.client.orchestrator import (
    Orchestrator,
    OrchestratorConfig,
    SolveResult,
    create_default_orchestrator,
)
from numasec.client.context import ContextManager, ContextConfig

__all__ = [
    # Core
    "AsyncMCPClient",
    "Orchestrator",
    "ContextManager",
    # Config
    "OrchestratorConfig",
    "ContextConfig",
    # Results
    "ToolResult",
    "SolveResult",
    # Factory
    "create_default_orchestrator",
]