"""CLI package for NumaSec.

Revolutionary Cyberpunk CLI with:
- Async interruptible agent loops
- Real-time streaming output (like Claude Code)
- ESC key to interrupt mid-execution
- Rich terminal UI with Matrix/Mr. Robot aesthetics
"""

from numasec.cli.app import app
from numasec.cli.cyberpunk_interface import NumaSecCLI, run

__all__ = ["app", "NumaSecCLI", "run"]
