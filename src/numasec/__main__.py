"""
NumaSec - God Mode Terminal

Launch with just 'numasec' for the revolutionary cyberpunk CLI.
"""

from __future__ import annotations

import sys


def main():
    """Main entry point."""
    # If no args, start the CYBERPUNK CLI
    if len(sys.argv) == 1:
        from numasec.cli.cyberpunk_interface import run
        run()
    else:
        # Delegate to subcommand CLI for backwards compatibility
        from numasec.client.__main__ import main as cli_main
        sys.exit(cli_main())


if __name__ == "__main__":
    main()
