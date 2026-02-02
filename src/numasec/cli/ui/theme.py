"""
NumaSec UI Theme - Premium Terminal Experience

Design philosophy:
- Clean, minimal, professional
- Information hierarchy through styling
- Animations that inform, not distract
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime

from numasec import __version__
from typing import Any

# Rich imports with graceful fallback
try:
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.live import Live
    from rich.markdown import Markdown
    from rich.syntax import Syntax
    from rich.style import Style
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None

# ══════════════════════════════════════════════════════════════════════════════
# Color Palette (Cyberpunk/Hacker aesthetic)
# ══════════════════════════════════════════════════════════════════════════════

class Colors:
    """NumaSec color palette."""
    PRIMARY = "#00D4FF"      # Cyan - primary brand
    SECONDARY = "#FF6B6B"    # Coral - accents
    SUCCESS = "#00FF88"      # Green - success states
    WARNING = "#FFB800"      # Amber - warnings
    ERROR = "#FF4757"        # Red - errors
    MUTED = "#6B7280"        # Gray - secondary text
    BG_DARK = "#0D1117"      # Dark background
    TEXT = "#E6EDF3"         # Light text


# ══════════════════════════════════════════════════════════════════════════════
# ASCII Art Banner
# ══════════════════════════════════════════════════════════════════════════════

BANNER_ASCII = r"""
[bold cyan]
 ██╗██████╗  ██████╗ ███╗   ██╗████████╗██████╗  █████╗  ██████╗███████╗
 ██║██╔══██╗██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
 ██║██████╔╝██║   ██║██╔██╗ ██║   ██║   ██████╔╝███████║██║     █████╗  
 ██║██╔══██╗██║   ██║██║╚██╗██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
 ██║██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║  ██║██║  ██║╚██████╗███████╗
 ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
[/bold cyan]
[dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]
[bold white]                    ⚡ AI-Powered Security Testing[/bold white]
"""

BANNER_MINIMAL = """
[bold cyan]◆ NumaSec[/bold cyan] [dim]v{version}[/dim]  [bold white]AI Security Agent[/bold white]
"""


# ══════════════════════════════════════════════════════════════════════════════
# UI Components
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SessionStats:
    """Track session statistics for display."""
    start_time: datetime = field(default_factory=datetime.now)
    steps: int = 0
    requests: int = 0
    findings: int = 0
    
    @property
    def elapsed(self) -> str:
        delta = datetime.now() - self.start_time
        return f"{delta.seconds}s"


class NumaSecUI:
    """Premium terminal UI for NumaSec."""
    
    def __init__(self, console: Console | None = None):
        self.console = console or (Console() if RICH_AVAILABLE else None)
        self.stats = SessionStats()
        self._live: Live | None = None
    
    # ─────────────────────────────────────────────────────────────────────────
    # Banner & Initialization
    # ─────────────────────────────────────────────────────────────────────────
    
    def print_banner(self, minimal: bool = False):
        """Print the NumaSec banner."""
        if not RICH_AVAILABLE:
            print(f"\n=== NumaSec v{__version__} - AI Security Agent ===\n")
            return
        
        if minimal:
            self.console.print(BANNER_MINIMAL.format(version=__version__))
        else:
            self.console.print(BANNER_ASCII)
            self.console.print()
    
    def print_ready(self, tool_count: int):
        """Print ready status."""
        if RICH_AVAILABLE:
            self.console.print(
                f"[bold green]●[/bold green] Ready  "
                f"[dim]│[/dim]  [cyan]{tool_count}[/cyan] tools  "
                f"[dim]│[/dim]  Type [bold]/help[/bold] for commands"
            )
            self.console.print()
        else:
            print(f"Ready! {tool_count} tools loaded.")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Status & Progress
    # ─────────────────────────────────────────────────────────────────────────
    
    def status(self, msg: str, style: str = "dim"):
        """Print a status message."""
        if RICH_AVAILABLE:
            self.console.print(f"[{style}]{msg}[/{style}]")
        else:
            print(f"[*] {msg}")
    
    def error(self, msg: str):
        """Print an error message."""
        if RICH_AVAILABLE:
            self.console.print(f"[bold red]✗[/bold red] {msg}")
        else:
            print(f"[!] Error: {msg}")
    
    def success(self, msg: str):
        """Print a success message."""
        if RICH_AVAILABLE:
            self.console.print(f"[bold green]✓[/bold green] {msg}")
        else:
            print(f"[+] {msg}")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Autonomous Mode UI
    # ─────────────────────────────────────────────────────────────────────────
    
    def start_autonomous(self, target: str, objective: str):
        """Display autonomous mode start."""
        self.stats = SessionStats()  # Reset stats
        
        if not RICH_AVAILABLE:
            print(f"\n[*] Target: {target}")
            print(f"[*] Objective: {objective}")
            print("[*] Ctrl+C to interrupt\n")
            return
        
        # Truncate long URLs
        display_target = target if len(target) < 60 else target[:57] + "..."
        
        panel = Panel(
            f"[bold]{objective}[/bold]\n\n"
            f"[cyan]Target:[/cyan] {display_target}\n"
            f"[dim]Press Ctrl+C to take control[/dim]",
            title="[bold cyan]◆ Autonomous Mode[/bold cyan]",
            border_style="cyan",
            padding=(1, 2)
        )
        self.console.print()
        self.console.print(panel)
        self.console.print()
    
    def show_step(self, step: int, max_steps: int, action: str = "Analyzing..."):
        """Show current step in autonomous mode."""
        self.stats.steps = step
        
        if not RICH_AVAILABLE:
            print(f"[{step}/{max_steps}] {action}")
            return
        
        # Clean progress indicator
        progress = f"[dim]Step {step}/{max_steps}[/dim]"
        self.console.print(f"  {progress}  [cyan]●[/cyan] {action}")
    
    def show_action_result(self, tool: str, result: dict | str):
        """Show action result in a clean format."""
        self.stats.requests += 1
        
        if not RICH_AVAILABLE:
            print(f"  ✓ {tool}")
            return
        
        # Parse result for clean display
        summary = self._summarize_result(tool, result)
        self.console.print(f"       [green]✓[/green] {summary}")
    
    def show_thinking(self, content: str):
        """Display LLM thinking/analysis."""
        if not content or not content.strip():
            return
            
        if not RICH_AVAILABLE:
            print(f"\n{content}\n")
            return
        
        # Show as markdown in a subtle panel
        self.console.print()
        self.console.print(Panel(
            Markdown(content),
            border_style="dim",
            padding=(0, 1)
        ))
    
    def show_flag_found(self, flag: str):
        """Display victory screen with captured flag."""
        if not RICH_AVAILABLE:
            print(f"\n{'='*60}")
            print(f"  VULNERABILITY FOUND: {flag}")
            print(f"{'='*60}\n")
            return
        
        # Victory panel with stats
        stats_line = (
            f"[dim]⏱️ {self.stats.elapsed}[/dim]  "
            f"[dim]│[/dim]  [dim]📊 {self.stats.requests} requests[/dim]  "
            f"[dim]│[/dim]  [dim]🧠 {self.stats.steps} steps[/dim]"
        )
        
        victory_content = f"""

[bold green]{flag}[/bold green]

{stats_line}
"""
        
        self.console.print()
        self.console.print(Panel(
            Align.center(victory_content),
            title="[bold green]🏆 VULNERABILITY FOUND[/bold green]",
            border_style="green",
            padding=(1, 4)
        ))
        self.console.print()
    
    def show_complete(self, findings: int = 0):
        """Display completion without flag (pentest mode)."""
        if not RICH_AVAILABLE:
            print(f"\n[*] Complete. {findings} findings documented.\n")
            return
        
        self.console.print()
        self.console.print(Panel(
            f"[bold]Assessment Complete[/bold]\n\n"
            f"[cyan]{findings}[/cyan] findings documented\n"
            f"[dim]⏱️ {self.stats.elapsed} │ {self.stats.steps} steps[/dim]",
            title="[bold cyan]◆ Done[/bold cyan]",
            border_style="cyan",
            padding=(1, 2)
        ))
    
    # ─────────────────────────────────────────────────────────────────────────
    # Help & Commands
    # ─────────────────────────────────────────────────────────────────────────
    
    def print_help(self):
        """Print help message with conversational examples."""
        if not RICH_AVAILABLE:
            print("""
NumaSec - AI Security Copilot (Phase 2)

CONVERSATIONAL MODE (just chat naturally):
  "Test this login form for SQL injection"
  "I found a weird API endpoint at /api/users"
  "Try to bypass the WAF on this target"
  "What vulnerabilities should I look for here?"

COMMANDS:
  /assess <target> - Autonomous security assessment
  /tools           - List available tools
  /clear           - Clear conversation history
  /quit            - Exit

PRO TIP: NumaSec remembers your conversation. It learns from each interaction.
""")
            return
        
        # Chat mode examples
        chat_examples = Table(show_header=False, box=None, padding=(0, 1))
        chat_examples.add_column("Example", style="green")
        chat_examples.add_row("💬 \"Test for SQL injection\"")
        chat_examples.add_row("💬 \"Analyze this API endpoint\"")
        chat_examples.add_row("💬 \"What should I test next?\"")
        
        # Commands table
        help_table = Table(show_header=False, box=None, padding=(0, 2))
        help_table.add_column("Command", style="cyan bold")
        help_table.add_column("Description", style="dim")
        
        help_table.add_row("/assess <target>", "Autonomous security assessment")
        help_table.add_row("/tools", "List available security tools")
        help_table.add_row("/clear", "Clear conversation history")
        help_table.add_row("/quit", "Exit NumaSec")
        
        self.console.print()
        self.console.print(Panel(
            Group(
                Text("CONVERSATIONAL MODE", style="bold cyan"),
                Text("Just chat naturally with NumaSec:", style="dim"),
                chat_examples,
                Text(""),
                Text("COMMANDS", style="bold cyan"),
                help_table
            ),
            title="[bold]NumaSec - Usage Guide[/bold]",
            subtitle="[dim]Phase 2: Conversational Intelligence[/dim]",
            border_style="cyan",
            padding=(1, 2)
        ))
        self.console.print()
        self.console.print("[dim]💡 NumaSec remembers your conversation and avoids repeating tests[/dim]")
        self.console.print()
    
    def print_tools(self, tools: list):
        """Print available tools."""
        if not RICH_AVAILABLE:
            for t in tools:
                print(f"  • {t.name}")
            return
        
        table = Table(show_header=True, header_style="bold cyan", box=None)
        table.add_column("Tool", style="cyan")
        table.add_column("Description", style="dim")
        
        for t in tools:
            desc = t.description[:50] + "..." if len(t.description) > 50 else t.description
            table.add_row(t.name, desc)
        
        self.console.print()
        self.console.print(Panel(table, title=f"[bold]{len(tools)} Tools[/bold]", border_style="dim"))
        self.console.print()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────
    
    def _summarize_result(self, tool: str, result: dict | str) -> str:
        """Create a clean one-line summary of tool result."""
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except (json.JSONDecodeError, TypeError):
                # Raw string result - truncate
                return result[:60] + "..." if len(result) > 60 else result
        
        if not isinstance(result, dict):
            return str(result)[:60]
        
        # Web request summary
        if "status_code" in result:
            status = result.get("status_code", "?")
            content_type = result.get("headers", {}).get("content-type", "")
            
            # Extract just the mime type
            mime = content_type.split(";")[0] if content_type else "unknown"
            mime_short = {
                "text/html": "HTML",
                "application/json": "JSON",
                "text/css": "CSS",
                "application/javascript": "JS",
                "text/javascript": "JS",
            }.get(mime, mime.split("/")[-1].upper() if "/" in mime else mime)
            
            url = result.get("url", "")
            path = url.split("://")[-1].split("/", 1)[-1] if "://" in url else url
            path = "/" + path if path and not path.startswith("/") else path or "/"
            path = path[:30] + "..." if len(path) > 30 else path
            
            return f"[cyan]GET[/cyan] {path} → [green]{status}[/green] ({mime_short})"
        
        # Script execution summary  
        if "script_type" in result or "exit_code" in result:
            exit_code = result.get("exit_code", 0)
            status = "[green]OK[/green]" if exit_code == 0 else f"[red]Exit {exit_code}[/red]"
            stdout = result.get("stdout", "")
            preview = stdout[:40].replace("\n", " ") + "..." if len(stdout) > 40 else stdout.replace("\n", " ")
            return f"[magenta]Script[/magenta] {status} {preview}"
        
        # Finding created
        if "finding_id" in result:
            title = result.get("title", "Finding")[:40]
            severity = result.get("severity", "info")
            sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan"}.get(severity, "dim")
            return f"[{sev_color}]●[/{sev_color}] Finding: {title}"
        
        # Generic success/failure
        if "success" in result:
            status = "[green]✓[/green]" if result["success"] else "[red]✗[/red]"
            msg = result.get("message", "")[:40]
            return f"{status} {msg}"
        
        # Fallback
        return str(result)[:60] + "..."


# ══════════════════════════════════════════════════════════════════════════════
# Singleton instance for easy access
# ══════════════════════════════════════════════════════════════════════════════

_ui: NumaSecUI | None = None

def get_ui() -> NumaSecUI:
    """Get the global UI instance."""
    global _ui
    if _ui is None:
        _ui = NumaSecUI()
    return _ui
