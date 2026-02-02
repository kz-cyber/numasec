"""
Cyberpunk Theme System for NumaSec
========================================
Dark Mode + Neon aesthetics (Matrix/Mr. Robot vibes)
SOTA 2026: Minimalist, Ephemeral, Nerd Font Integrated
"""

from typing import Literal
from rich.console import Console
from rich.theme import Theme
from rich.text import Text
from rich.style import Style

# ═══════════════════════════════════════════════════════════════════════════
# CYBERPUNK COLOR PALETTE (2026 Standard)
# ═══════════════════════════════════════════════════════════════════════════

NEON_GREEN = "#00ff00"
CYBER_PURPLE = "#bd93f9"
WARNING_RED = "#ff5555"
ELECTRIC_BLUE = "#00d9ff"
DARK_BG = "#0a0e14"
DIM_GRAY = "#4b5263"
MUTED_TEXT = "#6272a4"
GOLD = "#ffb86c"

# Create custom theme for Rich
CYBERPUNK_THEME = Theme({
    "info": f"bold {NEON_GREEN}",
    "warning": f"bold {WARNING_RED}",
    "error": f"bold {WARNING_RED}",
    "success": f"bold {NEON_GREEN}",
    "thinking": f"italic {CYBER_PURPLE}",
    "tool": f"bold {ELECTRIC_BLUE}",
    "dim": f"{DIM_GRAY}",
    "prompt": f"bold {NEON_GREEN}",
    "agent": f"bold {CYBER_PURPLE}",
    "muted": f"{MUTED_TEXT}",
    "highlight": f"bold {GOLD}",
})


class CyberpunkAssets:
    """SOTA Visual Elements & Animations"""
    
    # 2026 Minimalist Header
    BANNER_SMALL = f"[{CYBER_PURPLE}]NumaSec[/] [{DIM_GRAY}]v2.5[/]"
    
    # Icons (Nerd Fonts)
    ICON_THINK = "🧠"
    ICON_TOOL = "⚡"
    ICON_SUCCESS = "✓"
    ICON_ERROR = "✗"
    ICON_WARN = "⚠"
    ICON_INFO = "ℹ"
    ICON_LOCK = "🔒"
    ICON_KEY = "🔑"
    
    # Spinners
    # Smooth fade dot spinner
    SPINNER_DOTS = "dots8Bit" 
    
    # Custom "Matrix" cascade frames (manual implementation if needed)
    MATRIX_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    @staticmethod
    def get_status_style(status: str) -> str:
        if status == "running": return ELECTRIC_BLUE
        if status == "success": return NEON_GREEN
        if status == "error": return WARNING_RED
        return DIM_GRAY

    @staticmethod
    def format_latency(ms: float) -> str:
        color = NEON_GREEN if ms < 500 else (GOLD if ms < 2000 else WARNING_RED)
        return f"[{color}]{ms:.0f}ms[/]"
