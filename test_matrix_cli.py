#!/usr/bin/env python3
"""
Quick visual test of the Matrix-style CLI upgrade
"""

from rich.console import Console
from rich.panel import Panel
from rich import box
from src.numasec.cli.cyberpunk_theme import (
    MATRIX_GREEN, CYBER_PURPLE, HACK_RED, ELECTRIC_CYAN, 
    GHOST_GRAY, GOLD, CyberpunkAssets, CYBERPUNK_THEME
)

console = Console(theme=CYBERPUNK_THEME)

# Test banner
logo = f"""[{CYBER_PURPLE}]███╗   ██╗██╗   ██╗███╗   ███╗ █████╗ ███████╗███████╗ ██████╗[/]
[{CYBER_PURPLE}]████╗  ██║██║   ██║████╗ ████║██╔══██╗██╔════╝██╔════╝██╔════╝[/]
[{ELECTRIC_CYAN}]██╔██╗ ██║██║   ██║██╔████╔██║███████║███████╗█████╗  ██║     [/]
[{ELECTRIC_CYAN}]██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══██║╚════██║██╔══╝  ██║     [/]
[{MATRIX_GREEN}]██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║  ██║███████║███████╗╚██████╗[/]
[{MATRIX_GREEN}]╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝[/]

[{GHOST_GRAY}]Elite Penetration Testing Framework · v2.5 · AI-Powered[/]"""

console.print("\n")
console.print(Panel(
    logo,
    border_style=MATRIX_GREEN,
    box=box.DOUBLE,
    padding=(1, 2)
))

console.print(f"[{GHOST_GRAY}]Type [/][{MATRIX_GREEN}]/help[/][{GHOST_GRAY}] for commands  ·  [/][{MATRIX_GREEN}]/engage <target>[/][{GHOST_GRAY}] to breach  ·  [/][{CYBER_PURPLE}]Ctrl-C[/][{GHOST_GRAY}] to pause[/]\n")

# Test operation output
console.print(f"[{MATRIX_GREEN}][✓] SYSTEM ONLINE[/] [{GHOST_GRAY}](28 tools armed)[/]\n")

# Test analysis
console.print(f"[{CYBER_PURPLE}]>> ANALYSIS:[/]")
console.print(f"[{GHOST_GRAY}]   Target appears vulnerable to SQL injection[/]")
console.print(f"[{GHOST_GRAY}]   Planning exploitation strategy[/]\n")

# Test tool execution
console.print(f"[{ELECTRIC_CYAN}]├─ web_request[/]")
console.print(f"[{GHOST_GRAY}]│[/]  [dim]#42[/dim]")
console.print(f"[{MATRIX_GREEN}]│  [✓][/] Server responded with 200 OK")
console.print(f"[{GHOST_GRAY}]└─ LAT: 234ms | TOK: 1024>2048 | COST: $0.0012 | MDL: DEEPSEEK[/]\n")

# Test finding
console.print(f"[{GOLD}]>> TARGET ACQUIRED #1[/]")
console.print(f"[{GOLD}]   SQL Injection vulnerability in login form[/]\n")

# Test error
console.print(f"[{HACK_RED}][X] BREACH FAILED: Connection timeout[/]")
console.print(f"[{GHOST_GRAY}]   [!] Use /status or Ctrl-C to pause[/]\n")

# Test panel
console.print(Panel(
    "Operation complete. Target successfully breached.\n\nRecommended next steps: privilege escalation",
    border_style=MATRIX_GREEN,
    box=box.HEAVY,
    title=f"[{MATRIX_GREEN}]>> AGENT OUTPUT[/]"
))

console.print(f"\n[{MATRIX_GREEN}]Matrix vibes achieved! 🚀[/]\n")
