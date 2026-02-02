"""
NumaSec - The MCP-Native Pentesting Copilot

AI-powered penetration testing assistant with human-in-the-loop safety.
"""

__version__ = "2.3.0"
__author__ = "FrancescoStabile"
__license__ = "MIT"


def main():
    """Entry point for numasec command."""
    from numasec.__main__ import main as _main
    _main()


__all__ = ["__version__", "main"]
