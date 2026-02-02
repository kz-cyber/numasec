"""
MCP Server entry point.

Usage:
    python -m numasec.mcp --stdio
    python -m numasec.mcp --port 3000
"""

import asyncio
import sys

from .server import run_server


def main():
    """CLI entry point for MCP server."""
    # Parse simple args
    stdio = "--stdio" in sys.argv
    port = None
    
    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
    
    # Default to stdio if nothing specified
    if not stdio and not port:
        stdio = True
    
    asyncio.run(run_server(stdio=stdio, port=port))


if __name__ == "__main__":
    main()
