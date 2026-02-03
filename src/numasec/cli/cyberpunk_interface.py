"""
NumaSec - SOTA Cyberpunk CLI Interface (v2.5)
===================================================

"The Claude Code Experience"
Linear, Ephemeral, High-Performance.

Architecture:
- OutputManager: Stores full logs of every action.
- Ephemeral Rendering: Active actions are "Live", then collapse to summaries.
- Linear History: No TUI redraws, just append-only log with live updates at the tip.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime

# Async input & styling
from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style as PromptStyle

# Rich UI
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.spinner import Spinner
from rich.style import Style
from rich.table import Table
from rich.layout import Layout
from rich import box

# Internal imports
from numasec.cli.cyberpunk_theme import (
    CYBERPUNK_THEME,
    CyberpunkAssets,
    MATRIX_GREEN,
    NEON_GREEN,
    CYBER_PURPLE,
    HACK_RED,
    WARNING_RED,
    ELECTRIC_CYAN,
    ELECTRIC_BLUE,
    GHOST_GRAY,
    DIM_GRAY,
    MUTED_TEXT,
    GOLD,
)
from numasec.agent import NumaSecAgent, AgentConfig
from numasec.agent.events import Event, EventType
from numasec.ai.router import LLMRouter, LLMProvider
from numasec.client.mcp_client import AsyncMCPClient
from numasec.client.transports.direct import DirectTransport
from numasec.core.approval import ApprovalMode


# ═══════════════════════════════════════════════════════════════════════════
# OUTPUT MANAGER: The "Memory" of the CLI
# ═══════════════════════════════════════════════════════════════════════════

class ActionRecord:
    def __init__(self, id: int, type: str, content: str, duration: float):
        self.id = id
        self.type = type  # 'tool', 'think', 'error'
        self.content = content
        self.duration = duration
        self.timestamp = datetime.now()

class OutputManager:
    """Manages full output for expandable history."""
    
    def __init__(self):
        self.records: Dict[int, ActionRecord] = {}
        self.counter = 1
        
    def add(self, type: str, content: str, duration: float) -> int:
        id = self.counter
        self.records[id] = ActionRecord(id, type, content, duration)
        self.counter += 1
        return id
        
    def get(self, id: int) -> Optional[ActionRecord]:
        return self.records.get(id)
    
    def clear(self) -> None:
        """Clear all records and reset counter."""
        self.records.clear()
        self.counter = 1


# ═══════════════════════════════════════════════════════════════════════════
# SOTA CLI IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════════════════

class NumaSecCLI:
    """
    SOTA CLI with Linear Ephemeral Rendering + Tactical Pause.
    
    State Machine (Boolean Flags):
    - current_agent_task: Active asyncio.Task running agent loop (None = IDLE)
    - interrupt_requested: Legacy flag (unused in v2.5)
    - pause_requested: Ctrl-C pressed during execution → triggers supervisor menu
    - verbose_mode: Show extended debug output
    
    Flow:
    1. IDLE: No task running, waiting for user input
    2. BUSY: Task running, pause_requested=False → stream events
    3. PAUSED: pause_requested=True → show menu, await supervisor decision
    4. Return to BUSY (resume) or IDLE (stop)
    """
    def __init__(self):
        # UI Components
        self.console = Console(theme=CYBERPUNK_THEME, highlight=False)
        self.output_manager = OutputManager()
        
        # State Machine Flags (see class docstring for flow)
        self.current_agent_task: Optional[asyncio.Task] = None
        self.interrupt_requested = False
        self.pause_requested = False  # Tactical Pause Flag
        self.verbose_mode = False
        
        # Session Metrics (Minimal)
        self.session_start_time = time.time()
        self.total_cost = 0.0
        self.total_tokens_in = 0
        self.total_tokens_out = 0
        self.iteration_count = 0
        self.findings_count = 0
        self.cost_thresholds = [1.0, 5.0, 10.0]
        self.cost_warned_at = set()
        self.current_model = "unknown"  # Track model used
        
        # AI Components
        self.mcp_client: Optional[AsyncMCPClient] = None
        self.router: Optional[LLMRouter] = None
        self.agent: Optional[NumaSecAgent] = None
        
        # Input
        self.session: Optional[PromptSession] = None
        
    async def connect(self) -> bool:
        """Initialize connection with MATRIX boot sequence."""
        self._load_env()
        
        # MATRIX BOOT ANIMATION
        await self._matrix_boot_sequence()
        
        try:
            # 1. MCP
            self._boot_step("LOADING MCP CLIENT")
            transport = DirectTransport()
            self.mcp_client = AsyncMCPClient(transport)
            await self.mcp_client.connect()
            self._boot_complete("MCP CLIENT READY")
            
            # 2. Router
            self._boot_step("INITIALIZING AI ROUTER")
            self.router = LLMRouter(primary=LLMProvider.DEEPSEEK)
            self._boot_complete("AI ROUTER ONLINE")
            
            # 3. Agent
            self._boot_step("SPAWNING AGENT PROCESS")
            self.agent = NumaSecAgent.create(
                router=self.router,
                mcp_client=self.mcp_client,
                target="interactive",
                approval_mode=ApprovalMode.SUPERVISED
            )
            self._boot_complete("AGENT ARMED")
            
            # Success Banner with pulse effect
            self.console.print()
            for _ in range(3):
                self.console.print(f"[{MATRIX_GREEN} bold]>> SYSTEM ONLINE <<[/] [{DIM_GRAY}]({len(self.mcp_client.tools)} tools armed)[/]", end="\r")
                await asyncio.sleep(0.15)
                self.console.print(f"[{MATRIX_GREEN}]>> SYSTEM ONLINE <<[/] [{DIM_GRAY}]({len(self.mcp_client.tools)} tools armed)[/]", end="\r")
                await asyncio.sleep(0.15)
            self.console.print(f"[{MATRIX_GREEN} bold]>> SYSTEM ONLINE <<[/] [{DIM_GRAY}]({len(self.mcp_client.tools)} tools armed)[/]")
            
            # Check for active engagement (session contamination prevention)
            await self._check_and_display_active_engagement()
            
            return True
            
        except Exception as e:
            self.console.print(f"[{HACK_RED} blink][X] BOOT FAILED:[/] {e}")
            return False

    async def disconnect(self):
        # Pause active engagement to prevent session contamination
        await self._pause_active_engagement()
        
        if self.mcp_client: await self.mcp_client.disconnect()
        if self.router: await self.router.close()
    
    async def _pause_active_engagement(self):
        """Pause ALL active engagements to ensure clean session isolation."""
        try:
            from numasec.data.database import get_session, init_database
            from numasec.data.repositories.engagement import EngagementRepository
            from numasec.data.models import EngagementStatus, Engagement
            from sqlalchemy import select
            
            await init_database()
            async with get_session() as session:
                # Get ALL active engagements (not just first one)
                query = select(Engagement).where(Engagement.status == EngagementStatus.ACTIVE)
                result = await session.execute(query)
                active_engagements = result.scalars().all()
                
                # Pause each one
                repo = EngagementRepository(session)
                for engagement in active_engagements:
                    await repo.update_status(engagement.id, EngagementStatus.PAUSED)
                
                if active_engagements:
                    await session.commit()
        except Exception:
            pass  # Silent fail on exit - don't block shutdown

    def _load_env(self):
        check = Path.cwd()
        for _ in range(5):
            env_file = check / ".env"
            if env_file.exists():
                for line in env_file.read_text().splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, _, v = line.partition("=")
                        os.environ.setdefault(k.strip(), v.strip())
                return
            check = check.parent
    
    async def _check_and_display_active_engagement(self):
        """Check for paused engagement and offer to resume."""
        try:
            from numasec.data.database import get_session, init_database
            from numasec.data.repositories.engagement import EngagementRepository
            from numasec.data.models import EngagementStatus
            
            await init_database()
            async with get_session() as session:
                repo = EngagementRepository(session)
                
                # Check for PAUSED engagement (from previous session)
                from sqlalchemy import select
                from numasec.data.models import Engagement
                
                query = (
                    select(Engagement)
                    .where(Engagement.status == EngagementStatus.PAUSED)
                    .order_by(Engagement.updated_at.desc())
                    .limit(1)
                )
                from sqlalchemy.orm import selectinload
                query = query.options(selectinload(Engagement.scope_entries))
                result = await session.execute(query)
                paused_engagement = result.scalar_one_or_none()
                
                if paused_engagement:
                    scope_preview = ", ".join([s.target for s in paused_engagement.scope_entries[:3]])
                    if len(paused_engagement.scope_entries) > 3:
                        scope_preview += "..."
                    
                    self.console.print()
                    self.console.print(Panel(
                        f"[{GOLD}]ℹ Paused Engagement Detected[/]\n\n"
                        f"[{DIM_GRAY}]Client:[/] {paused_engagement.client_name}\n"
                        f"[{DIM_GRAY}]Project:[/] {paused_engagement.project_name}\n"
                        f"[{DIM_GRAY}]Scope:[/] {scope_preview}\n\n"
                        f"[{MUTED_TEXT}]Type[/] [{ELECTRIC_BLUE}]/resume[/] [{MUTED_TEXT}]to continue or[/] [{ELECTRIC_BLUE}]/new[/] [{MUTED_TEXT}]to start fresh[/]",
                        title=f"[{GOLD}]Session Recovery[/]",
                        border_style=GOLD,
                        box=box.ROUNDED
                    ))
        except Exception:
            pass  # Silent fail - don't block startup

    # ══════════════════════════════════════════════════════════════════════
    # MATRIX BOOT ANIMATIONS
    # ══════════════════════════════════════════════════════════════════════
    
    async def _matrix_boot_sequence(self):
        """Epic matrix-style boot animation."""
        import random
        
        # Matrix rain effect (brief) - ASCII hacker style
        matrix_chars = "01ABCDEFGHIJKLMNOPQRSTUVWXYZ#@+-/%\\|*<>[]{}()"
        cols = 20
        
        for frame in range(8):
            line = "".join(random.choice(matrix_chars) for _ in range(cols))
            self.console.print(f"[{MATRIX_GREEN} dim]{line}[/]", end="\r")
            await asyncio.sleep(0.05)
        
        self.console.print(" " * cols)  # Clear
        
        # Boot messages with typing effect
        boot_msgs = [
            ">> INITIALIZING NEURAL CORE",
            ">> LOADING ATTACK VECTORS",
            ">> ESTABLISHING ENCRYPTED TUNNEL",
        ]
        
        for msg in boot_msgs:
            for i in range(len(msg) + 1):
                self.console.print(f"[{ELECTRIC_CYAN}]{msg[:i]}[/]", end="\r")
                await asyncio.sleep(0.02)
            self.console.print(f"[{MATRIX_GREEN}]{msg} [✓][/]")
            await asyncio.sleep(0.1)
        
        self.console.print()
    
    def _boot_step(self, msg: str):
        """Show boot step."""
        self.console.print(f"[{DIM_GRAY}]>> {msg}...[/]")
    
    def _boot_complete(self, msg: str):
        """Mark boot step complete."""
        self.console.print(f"[{MATRIX_GREEN}]   [✓] {msg}[/]")
    
    # ══════════════════════════════════════════════════════════════════════
    # WELCOME BANNER (ASCII ART)
    # ══════════════════════════════════════════════════════════════════════
    
    def _display_welcome_banner(self):
        """Display epic matrix ASCII art banner with side panel."""
        from rich.table import Table
        from rich.text import Text
        
        # Left: ASCII Art Logo
        logo_text = Text()
        logo_text.append("███╗   ██╗██╗   ██╗███╗   ███╗ █████╗ ███████╗███████╗ ██████╗\n", style=CYBER_PURPLE)
        logo_text.append("████╗  ██║██║   ██║████╗ ████║██╔══██╗██╔════╝██╔════╝██╔════╝\n", style=CYBER_PURPLE)
        logo_text.append("██╔██╗ ██║██║   ██║██╔████╔██║███████║███████╗█████╗  ██║     \n", style=ELECTRIC_CYAN)
        logo_text.append("██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══██║╚════██║██╔══╝  ██║     \n", style=ELECTRIC_CYAN)
        logo_text.append("██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║  ██║███████║███████╗╚██████╗\n", style=MATRIX_GREEN)
        logo_text.append("╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝\n\n", style=MATRIX_GREEN)
        logo_text.append("AI-Powered Pentesting Framework", style="bold white")
        logo_text.no_wrap = True
        
        # Right: Quick Start Guide
        guide_text = Text()
        guide_text.append("QUICK START\n\n", style="bold white")
        guide_text.append(">>> ", style=DIM_GRAY)
        guide_text.append("Type your objective to begin breach\n", style="white")
        guide_text.append(">>> ", style=DIM_GRAY)
        guide_text.append("/help", style=f"bold {MATRIX_GREEN}")
        guide_text.append(" - Show all commands\n", style="white")
        guide_text.append(">>> ", style=DIM_GRAY)
        guide_text.append("/metrics", style=f"bold {MATRIX_GREEN}")
        guide_text.append(" - Session statistics\n", style="white")
        guide_text.append(">>> ", style=DIM_GRAY)
        guide_text.append("Ctrl-C", style=f"bold {CYBER_PURPLE}")
        guide_text.append(" - Tactical pause", style="white")
        
        # Create table layout with fixed columns
        layout = Table.grid(padding=(0, 4))
        layout.add_column(width=68, no_wrap=True)  # Logo column - fits full NUMASEC
        layout.add_column(width=1, justify="center")  # Separator
        layout.add_column()  # Guide column - flexible
        
        separator = Text("│\n" * 10, style=DIM_GRAY)
        layout.add_row(logo_text, separator, guide_text)
        
        # Print in panel
        self.console.print()
        self.console.print(Panel(
            layout,
            border_style=MATRIX_GREEN,
            box=box.DOUBLE,
            padding=(1, 2)
        ))
        self.console.print()

    # ══════════════════════════════════════════════════════════════════════
    # MAIN LOOP
    # ══════════════════════════════════════════════════════════════════════

    async def run_loop(self):
        """The main input loop with Tactical Pause support."""
        # Key bindings
        kb = KeyBindings()
        @kb.add('c-c')
        def _(event):
            if self.current_agent_task and not self.current_agent_task.done():
                # TACTICAL PAUSE TRIGGER
                self.pause_requested = True
                # Do NOT cancel task immediately
            else:
                event.app.exit(exception=KeyboardInterrupt)

        self.session = PromptSession(key_bindings=kb)
        
        # Epic ASCII Art Welcome
        self._display_welcome_banner()
        
        while True:
            try:
                self.interrupt_requested = False
                self.pause_requested = False
                
                # SOTA Prompt styling
                user_input = await self.session.prompt_async(
                    HTML(f'<style fg="{MATRIX_GREEN}">❯</style> '),
                    style=PromptStyle.from_dict({'': MATRIX_GREEN})
                )
                
                if not user_input.strip(): continue
                
                # Slash Commands
                if user_input.startswith("/"):
                    should_continue = await self._handle_command(user_input)
                    if not should_continue: break
                    continue
                
                # Run Agent
                self.current_agent_task = asyncio.create_task(self._run_agent(user_input))
                try:
                    await self.current_agent_task
                except asyncio.CancelledError:
                    pass # Handled gracefully in _run_agent
                    
            except KeyboardInterrupt:
                break
            except EOFError:
                break
            except Exception as e:
                self.console.print(f"[{WARNING_RED}]ERROR:[/] {e}")

    # ══════════════════════════════════════════════════════════════════════
    # SUPERVISOR MODE (Tactical Pause)
    # ══════════════════════════════════════════════════════════════════════
    
    async def _handle_pause_menu(self) -> bool:
        """
        Handles the Tactical Pause Menu.
        Returns True if execution should resume, False if it should stop.
        """
        self.console.print()
        self.console.print(Panel(
            "[bold white]>> OPERATION PAUSED <<[/]\n"
            f"[{MATRIX_GREEN}][R]esume[/]  [{ELECTRIC_CYAN}][I]nject Command[/]  [{HACK_RED}][S]top[/]",
            title="[bold yellow][!] SUPERVISOR OVERRIDE[/]",
            border_style="yellow",
            box=box.DOUBLE
        ))
        
        while True:
            try:
                # Use a specific session for the menu to avoid main loop bindings issues
                choice = await self.session.prompt_async(
                    HTML(f'<style fg="yellow">OVERRIDE ❯</style> '),
                    style=PromptStyle.from_dict({'': 'yellow'})
                )
                choice = choice.strip().lower()
                
                if choice in ('r', 'resume', ''):
                    return True
                    
                elif choice in ('s', 'stop', 'kill', 'q'):
                    return False
                    
                elif choice in ('i', 'inject', 'hint'):
                    self.console.print(f"[{DIM_GRAY}]Enter tactical command:[/]")
                    hint = await self.session.prompt_async(
                        HTML(f'<style fg="{ELECTRIC_CYAN}">CMD ❯</style> '),
                        style=PromptStyle.from_dict({'': ELECTRIC_CYAN})
                    )
                    if hint.strip():
                        # Inject into agent state as high-priority user message
                        self.agent.state.add_message("user", f"[SUPERVISOR OVERRIDE]: {hint}")
                        self.console.print(f"[{MATRIX_GREEN}][✓] Command injected.[/]")
                        return True
                    else:
                        self.console.print(f"[{DIM_GRAY}]No command. Resuming...[/]")
                        return True
                
                else:
                    self.console.print(f"[{HACK_RED}]Invalid. Use R/I/S.[/]")
                        
            except KeyboardInterrupt:
                # Ctrl-C in menu -> Resume
                self.console.print(f"[{DIM_GRAY}]Resuming...[/]")
                return True

    # ══════════════════════════════════════════════════════════════════════
    # EXECUTION ENGINE (Linear Flow - Claude Code Style)
    # ══════════════════════════════════════════════════════════════════════

    async def _run_agent(self, user_input: str):
        """Stream agent execution with transparent reasoning."""
        
        # State tracking
        current_step_type = "init"
        current_step_content = ""
        start_time = time.perf_counter()
        action_start_time = time.perf_counter()
        
        # Spinner frames for smooth animation
        spinner_frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        spinner_idx = 0
        
        # Helper: render thinking with REAL-TIME streaming (character-by-character)
        def render_thinking(reasoning: str, elapsed: float, is_streaming: bool = True) -> Group:
            nonlocal spinner_idx
            spinner = spinner_frames[spinner_idx % len(spinner_frames)]
            spinner_idx += 1
            
            content = Text()
            # Animated header
            content.append(f"{spinner} ", style=CYBER_PURPLE)
            content.append("BREACHING SYSTEM...", style=f"bold {MATRIX_GREEN}")
            
            # Show reasoning with live cursor if still streaming
            if is_streaming:
                content.append(" ▊", style=f"blink {ELECTRIC_CYAN}")  # Blinking cursor
            
            content.append("\n")
            
            # Show ALL reasoning lines (streaming)
            lines = reasoning.strip().split("\n")
            for line in lines:
                if line.strip():
                    content.append(f"   >> {line.strip()}\n", style=f"{DIM_GRAY}")
            
            return content
        
        # Helper: render tool execution
        def render_tool(tool_name: str, elapsed: float) -> Text:
            nonlocal spinner_idx
            spinner = spinner_frames[spinner_idx % len(spinner_frames)]
            spinner_idx += 1
            
            content = Text()
            content.append(f"├─ {tool_name}\n", style=f"bold {ELECTRIC_CYAN}")
            content.append(f"│  {spinner} INFILTRATING...\n", style=ELECTRIC_CYAN)
            
            return content

        # THE LIVE CONTEXT (Single Column) - High refresh for streaming
        live = Live(console=self.console, refresh_per_second=20, transient=True)
        live.start()
        
        try:
            # Create Generator
            agent_generator = self.agent.chat(user_input)
            
            while True:
                # 1. CHECK PAUSE (Tactical Interruption)
                # Note: This check happens between events. For immediate response,
                # agent must yield events frequently (every tool call, thinking step)
                if self.pause_requested:
                    self.pause_requested = False
                    
                    # Stop Live to show menu
                    live.stop()
                    
                    # Show Supervisor Menu
                    should_resume = await self._handle_pause_menu()
                    if not should_resume:
                        self.console.print(f"[{WARNING_RED}]✗ Operation terminated by supervisor.[/]")
                        return # Stop everything
                        
                    # Resume
                    self.console.print(f"[{NEON_GREEN}]→ Resuming operation...[/]")
                    live.start()
                
                # 2. GET NEXT EVENT
                try:
                    # Retrieve next event from agent (Manual Iteration)
                    # Tactical pause is checked before each event for responsiveness
                    event = await agent_generator.__anext__()
                except StopAsyncIteration:
                    break
                except Exception as e:
                    # Break on unexpected error in generator
                    self.console.print(f"[{WARNING_RED}]Err in agent: {e}[/]")
                    break
                
                # 3. PROCESS EVENT
                elapsed = time.perf_counter() - start_time
                
                # ═══════════════════════════════════════════════════════════
                # SOTA 2026: TRUE STREAMING - THINK_CHUNK events
                # Real-time token display as they arrive from LLM
                # ═══════════════════════════════════════════════════════════
                if event.event_type == EventType.THINK_CHUNK:
                    phase = event.data.get("phase", "")
                    delta = event.data.get("delta", "")
                    
                    if phase == "stream_start":
                        # Initialize streaming display
                        if current_step_type != 'think':
                            current_step_type = 'think'
                            current_step_content = ""
                            start_time = time.perf_counter()
                    
                    elif phase in ("content", "reasoning"):
                        # TRUE STREAMING: Display delta immediately (no fake sleep!)
                        current_step_content += delta
                        elapsed = time.perf_counter() - start_time
                        live.update(render_thinking(current_step_content, elapsed, is_streaming=True))
                    
                    elif phase == "stream_end":
                        # Stream complete - keep display active until next event
                        pass
                
                elif event.event_type == EventType.THINK:
                    # Legacy THINK event (full block) - for compatibility
                    # Skip if we already have content from streaming
                    if current_step_type == 'think' and current_step_content:
                        # Already streamed, skip this legacy event
                        pass
                    else:
                        # Fallback: non-streaming path (e.g., errors, system messages)
                        if current_step_type != 'think':
                            current_step_type = 'think'
                            current_step_content = ""
                            start_time = time.perf_counter()
                        
                        reasoning = event.data.get("reasoning", "")
                        current_step_content = reasoning
                        live.update(render_thinking(current_step_content, elapsed, is_streaming=True))
                
                elif event.event_type == EventType.ACTION_PROPOSED:
                    # FLUSH THINKING - Show FULL reasoning (viral X potential)
                    if current_step_type == 'think':
                        elapsed_think = time.perf_counter() - start_time
                        
                        # Stop spinner and show final state (no cursor)
                        live.update(render_thinking(current_step_content, elapsed_think, is_streaming=False))
                        await asyncio.sleep(0.3)  # Brief pause to show final state
                        live.update(Text(""))
                        
                        lines = [l.strip() for l in current_step_content.strip().splitlines() if l.strip()]
                        if lines:
                            # Print ALL reasoning lines (not just last one)
                            self.console.print(f"[{CYBER_PURPLE}]>> ANALYSIS:[/]")
                            for line in lines:
                                self.console.print(f"[{DIM_GRAY}]   {line}[/]")
                            self.console.print("")  # Spacing
                    
                    # Start Tool Mode with glitch effect
                    tool = event.data.get("tool", "unknown")
                    params = event.data.get("params", {})
                    param_str = " ".join(f"{k}={v}" for k,v in params.items())[:60]
                    
                    # Glitch effect on tool name
                    glitch_chars = "█▓▒░"
                    import random
                    for _ in range(3):
                        glitched = "".join(random.choice([c, random.choice(glitch_chars)]) for c in tool)
                        self.console.print(f"[{HACK_RED}]├─ {glitched}[/]", end="\r")
                        await asyncio.sleep(0.05)
                    
                    current_step_type = 'tool'
                    current_step_content = f"{tool} {param_str}"
                    action_start_time = time.perf_counter()
                    
                    live.update(render_tool(tool, 0))
                
                elif event.event_type == EventType.ACTION_COMPLETE:
                    # FLUSH TOOL
                    tool = event.data.get("tool", "action")
                    result = event.data.get("result", "")
                    elapsed = time.perf_counter() - action_start_time
                    
                    rec_id = self.output_manager.add('tool', result, elapsed)
                    live.update(Text(""))
                    
                    # Tree-based output
                    clean_result = result.replace("\n", " ").strip()
                    summary = clean_result[:80] + "..." if len(clean_result) > 80 else clean_result
                    if not summary:
                        summary = "BREACH COMPLETE"
                    
                    # Animated progress bar
                    self.console.print(f"[{ELECTRIC_CYAN}]├─ {tool}[/]")
                    self.console.print(f"[{DIM_GRAY}]│[/]  [dim]#{rec_id}[/dim]")
                    
                    # Progress animation
                    bar_len = 30
                    for i in range(bar_len + 1):
                        filled = "█" * i
                        empty = "░" * (bar_len - i)
                        percent = int((i / bar_len) * 100)
                        self.console.print(f"[{DIM_GRAY}]│[/]  [{MATRIX_GREEN}]{filled}[{DIM_GRAY}]{empty}[/] {percent}%", end="\r")
                        await asyncio.sleep(0.01)
                    
                    self.console.print(f"[{MATRIX_GREEN}]│  [✓][/] {summary}                                ")
                    
                    # METRICS (Footer style - compact)
                    metrics = event.data.get("metrics", {})
                    if metrics:
                        tokens_in = metrics.get("input_tokens", 0)
                        tokens_out = metrics.get("output_tokens", 0)
                        cost = metrics.get("cost", 0.0)
                        latency = metrics.get("latency_ms", 0)
                        model = metrics.get("model", "unknown")
                        
                        self.total_tokens_in += tokens_in
                        self.total_tokens_out += tokens_out
                        self.total_cost += cost
                        self.current_model = model
                        
                        # Compact footer
                        footer_parts = []
                        if latency > 0:
                            footer_parts.append(f"LAT: {latency:.0f}ms")
                        if tokens_in > 0 or tokens_out > 0:
                            footer_parts.append(f"TOK: {tokens_in}>{tokens_out}")
                        if cost > 0:
                            footer_parts.append(f"COST: ${cost:.4f}")
                        if model:
                            footer_parts.append(f"MDL: {model.split('-')[0].upper()}")
                        
                        if footer_parts:
                            footer = " | ".join(footer_parts)
                            self.console.print(f"[{DIM_GRAY}]└─ {footer}[/]")
                        
                        await self._check_cost_threshold()
                    else:
                        self.console.print(f"[{DIM_GRAY}]└─ ({elapsed:.1f}s)[/]")
                    
                    self.console.print()  # Blank line for spacing
                    self.iteration_count += 1
                    
                    current_step_type = 'idle'
                    start_time = time.perf_counter()
                    
                elif event.event_type == EventType.RESPONSE:
                    content = event.data.get("content", "")
                    live.update(Text(""))
                    
                    self.console.print()
                    
                    # Typing animation for responses (hacker movie style)
                    if len(content) < 500 and not self.verbose_mode:
                        # Show typing effect for short responses
                        self.console.print(f"[{MATRIX_GREEN}]>> AGENT OUTPUT[/]")
                        self.console.print()
                        
                        displayed = ""
                        for char in content:
                            displayed += char
                            self.console.print(displayed, end="\r")
                            await asyncio.sleep(0.01)  # Fast typing
                        
                        self.console.print(displayed)  # Final print
                    else:
                        # Long content: show in panel without animation
                        self.console.print(Panel(
                            content,
                            border_style=MATRIX_GREEN,
                            box=box.HEAVY,
                            title=f"[{MATRIX_GREEN}]>> AGENT OUTPUT[/]"
                        ))
                    
                    self.console.print()
                
                elif event.event_type == EventType.FINDING:
                    self.findings_count += 1
                    finding = event.data.get("finding", "")
                    live.update(Text(""))
                    
                    self.console.print()
                    self.console.print(f"[{GOLD}]>> TARGET ACQUIRED #{self.findings_count}[/]")
                    self.console.print(f"[{GOLD}]   {finding}[/]")
                    self.console.print()
                
                elif event.event_type == EventType.FLAG:
                    # Professional finding notification (discrete)
                    finding_type = event.data.get("finding_type", "vulnerability")
                    vuln_type = event.data.get("vulnerability", "security_issue")
                    severity = event.data.get("severity", "MEDIUM")
                    
                    if finding_type == "vulnerability":
                        self.findings_count += 1
                        live.update(Text(""))
                        
                        self.console.print()
                        self.console.print(f"[{GOLD}]>> FINDING #{self.findings_count}: {vuln_type.upper()} ({severity})[/]")
                        self.console.print(f"[{DIM_GRAY}]   Use finding_list to view details[/]")
                        self.console.print()
                
                elif event.event_type == EventType.START:
                    start_time = time.perf_counter()
                
                elif event.event_type == EventType.ERROR:
                    msg = event.data.get("error", "Unknown")
                    error_detail = event.data.get("detail", "")
                    traceback_snippet = event.data.get("traceback", "")
                    
                    live.update(Text(""))
                    
                    self.console.print()
                    self.console.print(f"[{HACK_RED}][X] BREACH FAILED: {msg}[/]")
                    
                    if error_detail:
                        self.console.print(f"[{DIM_GRAY}]   {error_detail}[/]")
                    
                    if traceback_snippet:
                        tb_lines = traceback_snippet.strip().split("\n")[-3:]
                        self.console.print(f"[{DIM_GRAY}]   Trace:[/]")
                        for line in tb_lines:
                            self.console.print(f"[{DIM_GRAY}]     {line}[/]")
                    
                    self.console.print(f"[{DIM_GRAY}]   [!] Use /status or Ctrl+C to pause[/]")
                    self.console.print()
                    
                    # Log to file
                    if traceback_snippet:
                        error_log = Path.home() / ".numasec" / "errors.log"
                        error_log.parent.mkdir(exist_ok=True)
                        with open(error_log, "a") as f:
                            f.write(f"\n{'='*60}\n")
                            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                            f.write(f"Error: {msg}\n")
                            if error_detail:
                                f.write(f"Detail: {error_detail}\n")
                            f.write(f"Traceback:\n{traceback_snippet}\n")
        
        finally:
            live.stop()

    # ══════════════════════════════════════════════════════════════════════
    # COMMANDS
    # ══════════════════════════════════════════════════════════════════════

    async def _handle_command(self, cmd: str) -> bool:
        parts = cmd.strip().split()
        command = parts[0].lower()
        args = parts[1:]
        
        if command in ("/quit", "/exit", "/q"):
            return False
            
        elif command == "/help":
            self.console.print(Panel(
                "/show <id>     : Show full output of action #id\n"
                "/tools         : List available tools\n"
                "/new           : Start new engagement (pauses current)\n"
                "/resume        : Resume paused engagement\n"
                "/status        : Show engagement status\n"
                "/metrics       : Show session performance metrics\n"
                "/export [file] : Export session to JSON\n"
                "/purge         : Delete ALL engagements from database\n"
                "/clear         : Clear context\n"
                "/quit          : Exit",
                title=">> COMMANDS", border_style=MATRIX_GREEN
            ))
        
        elif command == "/new":
            await self._handle_new_engagement()
            
        elif command == "/resume":
            await self._handle_resume_engagement()
        
        elif command == "/status":
            await self._handle_engagement_status()
        
        elif command == "/metrics":
            self._show_session_metrics()
        
        elif command == "/export":
            filename = args[0] if args else f"numasec-session-{int(time.time())}.json"
            await self._handle_export(filename)
            
        elif command == "/show":
            if not args or not args[0].isdigit():
                self.console.print(f"[{HACK_RED}]Usage: /show <id>[/]")
                return True
                
            rec_id = int(args[0])
            record = self.output_manager.get(rec_id)
            if record:
                self.console.print(Panel(
                    record.content,
                    title=f"[{ELECTRIC_CYAN}]>> Action #{rec_id} Output[/]",
                    border_style=ELECTRIC_CYAN,
                    box=box.DOUBLE
                ))
            else:
                self.console.print(f"[{HACK_RED}]ID #{rec_id} not found.[/]")
                
        elif command == "/tools":
            if self.mcp_client and self.mcp_client.tools:
                table = Table(box=box.SIMPLE, show_header=True, header_style=MATRIX_GREEN)
                table.add_column("Tool", style=ELECTRIC_CYAN)
                table.add_column("Description", style=GHOST_GRAY)
                for tool in self.mcp_client.tools:
                    desc = tool.description[:60] + "..." if len(tool.description) > 60 else tool.description
                    table.add_row(tool.name, desc)
                self.console.print(table)
            else:
                self.console.print(f"[{HACK_RED}]No tools loaded.[/]")
            
        elif command == "/clear":
            # Clear agent state and output history
            if self.agent and hasattr(self.agent, 'state'):
                # Clear message history but keep system prompt
                if hasattr(self.agent.state, 'messages'):
                    system_msgs = [m for m in self.agent.state.messages if m.role == "system"]
                    self.agent.state.messages = system_msgs
                    self.console.print(f"[{MATRIX_GREEN}][✓] Agent context cleared.[/]")
            
            # Clear output manager
            self.output_manager.clear()
            self.console.print(f"[{MATRIX_GREEN}][✓] Output history cleared.[/]")
        
        elif command == "/purge":
            # Dangerous: delete ALL engagements from database
            self.console.print(f"[{HACK_RED}][!] WARNING: This will delete ALL engagements from the database.[/]")
            self.console.print(f"[{DIM_GRAY}]Type 'yes' to confirm, anything else to cancel.[/]")
            
            try:
                # Use async prompt to avoid event loop conflict
                confirm_session = PromptSession()
                confirm = await confirm_session.prompt_async("Confirm purge: ")
                confirm = confirm.strip().lower()
                
                if confirm == "yes":
                    await self._purge_all_engagements()
                    self.console.print(f"[{MATRIX_GREEN}][✓] All engagements deleted.[/]")
                else:
                    self.console.print(f"[{DIM_GRAY}]Purge cancelled.[/]")
            except Exception as e:
                self.console.print(f"[{HACK_RED}]Error: {e}[/]")
        
        else:
            # FALLBACK: Try to execute as MCP tool (e.g., /report_preview, /finding_list)
            tool_name = command[1:]  # Remove leading /
            if self.mcp_client and any(t.name == tool_name for t in self.mcp_client.tools):
                await self._execute_direct_tool(tool_name, args)
            else:
                self.console.print(f"[{HACK_RED}]Unknown command: {command}[/]")
                self.console.print(f"[{DIM_GRAY}]Type /help for available commands.[/]")
            
        return True
    
    async def _handle_new_engagement(self):
        """Pause current engagement and reset for new one."""
        await self._pause_active_engagement()
        
        # Reset session metrics
        self.session_start_time = time.time()
        self.total_cost = 0.0
        self.total_tokens_in = 0
        self.total_tokens_out = 0
        self.iteration_count = 0
        self.findings_count = 0
        self.cost_warned_at.clear()
        self.current_model = "unknown"
        
        # Clear agent state
        if self.agent and hasattr(self.agent, 'state'):
            if hasattr(self.agent.state, 'messages'):
                system_msgs = [m for m in self.agent.state.messages if m.role == "system"]
                self.agent.state.messages = system_msgs
        
        # Clear output history
        self.output_manager.clear()
        
        self.console.print(f"[{MATRIX_GREEN}][✓] Previous engagement paused.[/]")
        self.console.print(f"[{MATRIX_GREEN}][✓] Session state reset.[/]")
        self.console.print(f"[{CYBER_PURPLE}]Ready for new engagement.[/]")
    
    async def _handle_resume_engagement(self):
        """Resume paused engagement."""
        try:
            from numasec.data.database import get_session, init_database
            from numasec.data.repositories.engagement import EngagementRepository
            from numasec.data.models import EngagementStatus
            
            await init_database()
            async with get_session() as session:
                repo = EngagementRepository(session)
                
                # Get most recent paused engagement
                from sqlalchemy import select
                from numasec.data.models import Engagement
                from sqlalchemy.orm import selectinload
                
                query = (
                    select(Engagement)
                    .where(Engagement.status == EngagementStatus.PAUSED)
                    .order_by(Engagement.updated_at.desc())
                    .options(selectinload(Engagement.scope_entries))
                    .limit(1)
                )
                result = await session.execute(query)
                engagement = result.scalar_one_or_none()
                
                if engagement:
                    await repo.update_status(engagement.id, EngagementStatus.ACTIVE)
                    await session.commit()
                    
                    scope_preview = ", ".join([s.target for s in engagement.scope_entries[:3]])
                    self.console.print(Panel(
                        f"[{NEON_GREEN}]✓ Engagement Resumed[/]\n\n"
                        f"Client: {engagement.client_name}\n"
                        f"Project: {engagement.project_name}\n"
                        f"Scope: {scope_preview}",
                        border_style=NEON_GREEN,
                        box=box.ROUNDED
                    ))
                else:
                    self.console.print(f"[{WARNING_RED}]No paused engagement found.[/]")
        except Exception as e:
            self.console.print(f"[{WARNING_RED}]Error resuming engagement: {e}[/]")
    
    async def _handle_engagement_status(self):
        """Show current engagement status."""
        try:
            from numasec.data.database import get_session, init_database
            from numasec.data.repositories.engagement import EngagementRepository
            from sqlalchemy.orm import selectinload
            
            await init_database()
            async with get_session() as session:
                repo = EngagementRepository(session)
                engagement = await repo.get_active()
                
                if engagement:
                    scope_list = "\n".join([f"  • {s.target}" for s in engagement.scope_entries])
                    self.console.print(Panel(
                        f"[{NEON_GREEN}]Active Engagement[/]\n\n"
                        f"ID: {engagement.id}\n"
                        f"Client: {engagement.client_name}\n"
                        f"Project: {engagement.project_name}\n"
                        f"Status: {engagement.status.value}\n"
                        f"Phase: {engagement.current_phase.value}\n\n"
                        f"Scope:\n{scope_list}",
                        border_style=NEON_GREEN,
                        box=box.ROUNDED
                    ))
                else:
                    self.console.print(f"[{DIM_GRAY}]No active engagement.[/]")
        except Exception as e:
            self.console.print(f"[{WARNING_RED}]Error: {e}[/]")
    
    async def _purge_all_engagements(self):
        """Delete ALL engagements from database. Use with caution."""
        try:
            from numasec.data.database import get_session, init_database
            from numasec.data.models import Engagement
            from sqlalchemy import delete
            
            await init_database()
            async with get_session() as session:
                # Delete all engagements (cascades to scope_entries, findings, etc.)
                await session.execute(delete(Engagement))
                await session.commit()
        except Exception as e:
            raise Exception(f"Purge failed: {e}")
    
    # ═══════════════════════════════════════════════════════════════
    # METRICS & OBSERVABILITY (Minimal)
    # ═══════════════════════════════════════════════════════════════
    
    def _latency_color(self, latency_ms: float) -> str:
        """Color code latency: green <500ms, yellow <2000ms, red >=2000ms."""
        if latency_ms < 500:
            return NEON_GREEN
        elif latency_ms < 2000:
            return WARNING_RED.replace("red", "yellow")  # Fallback to yellow
        else:
            return WARNING_RED
    
    async def _check_cost_threshold(self):
        """Check if cost crossed any threshold and warn user."""
        for threshold in self.cost_thresholds:
            if self.total_cost >= threshold and threshold not in self.cost_warned_at:
                self.cost_warned_at.add(threshold)
                self.console.print()
                self.console.print(Panel(
                    f"[{HACK_RED}][!] COST ALERT[/]\n\n"
                    f"Session has exceeded ${threshold:.2f}\n"
                    f"Current total: ${self.total_cost:.4f}\n\n"
                    f"Use /metrics to view detailed stats.",
                    border_style=HACK_RED,
                    box=box.DOUBLE
                ))
                self.console.print()
    
    def _format_elapsed(self) -> str:
        """Format elapsed time as human-readable string."""
        elapsed = time.time() - self.session_start_time
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def _show_session_metrics(self):
        """Show current session performance metrics."""
        elapsed = self._format_elapsed()
        
        # Create metrics table
        table = Table(title=">> SESSION METRICS", box=box.DOUBLE, border_style=MATRIX_GREEN)
        table.add_column("Metric", style=ELECTRIC_CYAN)
        table.add_column("Value", justify="right", style=MATRIX_GREEN)
        
        table.add_row("SESSION TIME", elapsed)
        table.add_row("OPERATIONS", str(self.iteration_count))
        table.add_row("TARGETS FOUND", str(self.findings_count))
        table.add_row("TOKENS IN", f"{self.total_tokens_in:,}")
        table.add_row("TOKENS OUT", f"{self.total_tokens_out:,}")
        table.add_row("TOKENS TOTAL", f"{self.total_tokens_in + self.total_tokens_out:,}")
        table.add_row("COST TOTAL", f"${self.total_cost:.4f}", style=GOLD)
        
        # Cost efficiency
        if self.iteration_count > 0:
            cost_per_iteration = self.total_cost / self.iteration_count
            table.add_row("COST/OP", f"${cost_per_iteration:.4f}")
        
        # Token efficiency
        total_tokens = self.total_tokens_in + self.total_tokens_out
        if total_tokens > 0:
            cost_per_1k = (self.total_cost / total_tokens) * 1000
            table.add_row("COST/1K TOK", f"${cost_per_1k:.4f}")
        
        self.console.print()
        self.console.print(table)
        self.console.print()
    
    async def _execute_direct_tool(self, tool_name: str, args: list[str]):
        """
        Execute MCP tool directly from slash command.
        
        Example: /report_preview → report_preview()
                 /finding_list → finding_list()
        """
        try:
            self.console.print(f"[{DIM_GRAY}]Executing tool: {tool_name}...[/]")
            
            # Parse arguments if provided
            # Simple parser: assumes key=value pairs
            tool_args = {}
            for arg in args:
                if "=" in arg:
                    key, value = arg.split("=", 1)
                    tool_args[key] = value
            
            # Execute tool via MCP client
            result = await self.mcp_client.call_tool(tool_name, tool_args)
            
            # Display result
            self.console.print(Panel(
                result.content,
                title=f"[{ELECTRIC_CYAN}]>> {tool_name}[/]",
                border_style=MATRIX_GREEN,
                box=box.ROUNDED
            ))
            
        except Exception as e:
            self.console.print(f"[{HACK_RED}]Error executing {tool_name}: {e}[/]")
            import traceback
            self.console.print(f"[{DIM_GRAY}]{traceback.format_exc()}[/]")
    
    async def _handle_export(self, filename: str):
        """Export full session to JSON."""
        try:
            from pathlib import Path
            import json
            
            # Build export data
            export_data = {
                "metadata": {
                    "tool": "NumaSec",
                    "version": "2.5",
                    "export_time": datetime.now().isoformat(),
                    "session_start": datetime.fromtimestamp(self.session_start_time).isoformat(),
                    "session_duration_seconds": time.time() - self.session_start_time,
                },
                "metrics": {
                    "iterations": self.iteration_count,
                    "findings": self.findings_count,
                    "total_tokens_in": self.total_tokens_in,
                    "total_tokens_out": self.total_tokens_out,
                    "total_tokens": self.total_tokens_in + self.total_tokens_out,
                    "total_cost_usd": round(self.total_cost, 4),
                },
                "actions": [],
            }
            
            # Export all recorded actions
            for rec_id in sorted(self.output_manager.records.keys()):
                record = self.output_manager.get(rec_id)
                if record:
                    export_data["actions"].append({
                        "id": record.id,
                        "type": record.type,
                        "content": record.content[:1000] if len(record.content) > 1000 else record.content,  # Truncate very long
                        "content_length": len(record.content),
                        "duration_seconds": round(record.duration, 3),
                        "timestamp": record.timestamp.isoformat(),
                    })
            
            # Get engagement data if available
            try:
                from numasec.data.database import get_session, init_database
                from numasec.data.repositories.engagement import EngagementRepository
                
                await init_database()
                async with get_session() as session:
                    repo = EngagementRepository(session)
                    engagement = await repo.get_active()
                    
                    if engagement:
                        export_data["engagement"] = {
                            "id": engagement.id,
                            "client_name": engagement.client_name,
                            "project_name": engagement.project_name,
                            "status": engagement.status.value,
                            "scope": [s.target for s in engagement.scope_entries],
                        }
            except Exception:
                pass  # Engagement data optional
            
            # Write to file
            output_path = Path.cwd() / filename
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            file_size = output_path.stat().st_size
            size_kb = file_size / 1024
            
            self.console.print(Panel(
                f"[{MATRIX_GREEN}][✓] SESSION EXPORTED[/]\n\n"
                f"File: [{ELECTRIC_CYAN}]{output_path}[/]\n"
                f"Size: [{DIM_GRAY}]{size_kb:.1f} KB[/]\n\n"
                f"Actions: {len(export_data['actions'])}\n"
                f"Total Cost: [{GOLD}]${self.total_cost:.4f}[/]\n\n"
                f"[{DIM_GRAY}]Share for collaboration or bug reports[/]",
                title=f"[{MATRIX_GREEN}]>> EXPORT COMPLETE[/]",
                border_style=MATRIX_GREEN,
                box=box.DOUBLE
            ))
            
        except Exception as e:
            self.console.print(f"[{HACK_RED}][X] Export failed: {e}[/]")

async def main():
    cli = NumaSecCLI()
    if await cli.connect():
        await cli.run_loop()
    await cli.disconnect()

def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Fatal: {e}")

if __name__ == "__main__":
    run()
