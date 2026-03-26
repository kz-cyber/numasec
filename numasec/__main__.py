"""numasec — MCP Security Tool Server.

Usage:
    numasec              # MCP server (stdio, default)
    numasec --mcp        # MCP server (stdio, explicit)
    numasec --mcp-http   # MCP server (HTTP)
    numasec --version    # Show version
"""

import os
import sys

from numasec import __version__


def main() -> None:
    """Entry point for console_scripts."""
    if "--version" in sys.argv:
        print(f"numasec {__version__}")
        return

    try:
        transport = "stdio"
        if "--mcp-http" in sys.argv or os.environ.get("MCP_TRANSPORT") == "http":
            transport = "http"
        elif os.environ.get("MCP_TRANSPORT"):
            transport = os.environ["MCP_TRANSPORT"]

        from numasec.mcp.server import create_mcp_server

        server = create_mcp_server()
        server.run(transport=transport)
    except KeyboardInterrupt:
        print("\nInterrupted. Goodbye!")
        sys.exit(0)


if __name__ == "__main__":
    main()
