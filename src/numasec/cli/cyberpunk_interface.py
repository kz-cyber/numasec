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
    NEON_GREEN,
    CYBER_PURPLE,
    WARNING_RED,
    ELECTRIC_BLUE,
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
        """Initialize connection with SOTA spinner."""
        self._load_env()
        
        with self.console.status(f"[{CYBER_PURPLE}]INIT[_] System Boot...", spinner=CyberpunkAssets.SPINNER_DOTS, spinner_style=CYBER_PURPLE):
            try:
                # 1. MCP
                transport = DirectTransport()
                self.mcp_client = AsyncMCPClient(transport)
                await self.mcp_client.connect()
                
                # 2. Router
                self.router = LLMRouter(primary=LLMProvider.DEEPSEEK)
                
                # 3. Agent
                self.agent = NumaSecAgent.create(
                    router=self.router,
                    mcp_client=self.mcp_client,
                    target="interactive",
                    approval_mode=ApprovalMode.SUPERVISED
                )
                
                # Success Banner
                self.console.print(f"[{NEON_GREEN}]✓ SYSTEM ONLINE[/] [{DIM_GRAY}]({len(self.mcp_client.tools)} tools loaded)[/]")
                
                # Check for active engagement (session contamination prevention)
                await self._check_and_display_active_engagement()
                
                return True
                
            except Exception as e:
                self.console.print(f"[{WARNING_RED}]✗ BOOT FAILED:[/] {e}")
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
        
        # Welcome message
        self.console.print(Panel(
            f"[{CYBER_PURPLE}]NumaSec[/] [{DIM_GRAY}]v2.5[/]\n"
            f"[{DIM_GRAY}]SOTA Pentesting Agent · Type /help for commands[/]",
            border_style=DIM_GRAY, box=box.ROUNDED
        ))
        
        while True:
            try:
                self.interrupt_requested = False
                self.pause_requested = False
                
                # SOTA Prompt styling
                user_input = await self.session.prompt_async(
                    HTML(f'<style fg="{NEON_GREEN}">❯</style> '),
                    style=PromptStyle.from_dict({'': NEON_GREEN})
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
            "[bold white]TACTICAL PAUSE INITIATED[/]\n"
            f"[{NEON_GREEN}][R]esume[/]  [{ELECTRIC_BLUE}][I]nject Hint[/]  [{WARNING_RED}][S]top[/]",
            title="[bold yellow]⚠ SUPERVISOR INTERVENTION[/]",
            border_style="yellow",
            box=box.HEAVY
        ))
        
        while True:
            try:
                # Use a specific session for the menu to avoid main loop bindings issues
                choice = await self.session.prompt_async(
                    HTML(f'<style fg="yellow">SUPERVISOR ❯</style> '),
                    style=PromptStyle.from_dict({'': 'yellow'})
                )
                choice = choice.strip().lower()
                
                if choice in ('r', 'resume', ''):
                    return True
                    
                elif choice in ('s', 'stop', 'kill', 'q'):
                    return False
                    
                elif choice in ('i', 'inject', 'hint'):
                    self.console.print(f"[{DIM_GRAY}]Enter strategic guidance for the agent:[/]")
                    hint = await self.session.prompt_async(
                        HTML(f'<style fg="{ELECTRIC_BLUE}">HINT ❯</style> '),
                        style=PromptStyle.from_dict({'': ELECTRIC_BLUE})
                    )
                    if hint.strip():
                        # Inject into agent state as high-priority user message
                        self.agent.state.add_message("user", f"[SUPERVISOR INTERVENTION]: {hint}")
                        self.console.print(f"[{NEON_GREEN}]✓ Strategic hint injected into agent context.[/]")
                        return True
                    else:
                        self.console.print(f"[{DIM_GRAY}]No hint provided. Resuming without changes...[/]")
                        return True
                
                else:
                    self.console.print(f"[{WARNING_RED}]Invalid choice. Use R/I/S.[/]")
                        
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
        
        # Helper: render thinking with streaming reasoning (FULL, NO TRUNCATION)
        def render_thinking(reasoning: str, elapsed: float) -> Group:
            nonlocal spinner_idx
            spinner = spinner_frames[spinner_idx % len(spinner_frames)]
            spinner_idx += 1
            
            content = Text()
            content.append(f"{spinner} ", style=CYBER_PURPLE)
            content.append("Thinking...\n", style=f"bold {CYBER_PURPLE}")
            
            # Show ALL reasoning lines (no truncation for viral effect)
            lines = reasoning.strip().split("\n")
            for line in lines:
                if line.strip():
                    content.append(f"   {line.strip()}\n", style=f"italic {DIM_GRAY}")
            
            return content
        
        # Helper: render tool execution
        def render_tool(tool_name: str, elapsed: float) -> Text:
            nonlocal spinner_idx
            spinner = spinner_frames[spinner_idx % len(spinner_frames)]
            spinner_idx += 1
            
            content = Text()
            content.append(f"├─ {tool_name}\n", style=f"bold {ELECTRIC_BLUE}")
            content.append(f"│  {spinner} Executing...\n", style=ELECTRIC_BLUE)
            
            return content

        # THE LIVE CONTEXT (Single Column)
        live = Live(console=self.console, refresh_per_second=12, transient=True)
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
                
                if event.event_type == EventType.THINK:
                    if current_step_type != 'think':
                        current_step_type = 'think'
                        current_step_content = ""
                        start_time = time.perf_counter()
                    
                    reasoning = event.data.get("reasoning", "")
                    current_step_content += reasoning
                    
                    # Stream thinking with transparent reasoning
                    live.update(render_thinking(current_step_content, elapsed))
                
                elif event.event_type == EventType.ACTION_PROPOSED:
                    # FLUSH THINKING - Show FULL reasoning (viral X potential)
                    if current_step_type == 'think':
                        elapsed_think = time.perf_counter() - start_time
                        
                        # Stop spinner
                        live.update(Text(""))
                        
                        lines = [l.strip() for l in current_step_content.strip().splitlines() if l.strip()]
                        if lines:
                            # Print ALL reasoning lines (not just last one)
                            self.console.print(f"[{CYBER_PURPLE}]🧠 Reasoning:[/]")
                            for line in lines:
                                self.console.print(f"[dim italic {DIM_GRAY}]   {line}[/]")
                            self.console.print("")  # Spacing
                    
                    # Start Tool Mode
                    tool = event.data.get("tool", "unknown")
                    params = event.data.get("params", {})
                    param_str = " ".join(f"{k}={v}" for k,v in params.items())[:60]
                    
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
                        summary = "Done"
                    
                    self.console.print(f"[{ELECTRIC_BLUE}]├─ {tool}[/]")
                    self.console.print(f"[{DIM_GRAY}]│[/]  [dim]#{rec_id}[/dim]")
                    self.console.print(f"[{NEON_GREEN}]│  ✓[/] {summary}")
                    
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
                            footer_parts.append(f"⏱ {latency:.0f}ms")
                        if tokens_in > 0 or tokens_out > 0:
                            footer_parts.append(f"📊 {tokens_in}+{tokens_out}")
                        if cost > 0:
                            footer_parts.append(f"💰 ${cost:.4f}")
                        if model:
                            footer_parts.append(f"🧠 {model.split('-')[0]}")
                        
                        if footer_parts:
                            footer = " │ ".join(footer_parts)
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
                    self.console.print(Panel(
                        content,
                        border_style=NEON_GREEN,
                        box=box.ROUNDED,
                        title=f"[{CYBER_PURPLE}]Agent Response[/]"
                    ))
                    self.console.print()
                
                elif event.event_type == EventType.FINDING:
                    self.findings_count += 1
                    finding = event.data.get("finding", "")
                    live.update(Text(""))
                    
                    self.console.print()
                    self.console.print(f"[{GOLD}]🎯 FINDING #{self.findings_count}[/]")
                    self.console.print(f"[{GOLD}]   {finding}[/]")
                    self.console.print()
                
                elif event.event_type == EventType.FLAG:
                    self.findings_count += 1
                    flag = event.data.get("flag", "")
                    live.update(Text(""))
                    
                    self.console.print()
                    self.console.print(Panel(
                        f"[{GOLD}]🏁 FLAG CAPTURED[/]\n\n{flag}",
                        border_style=GOLD,
                        box=box.HEAVY
                    ))
                    self.console.print()
                
                elif event.event_type == EventType.START:
                    start_time = time.perf_counter()
                
                elif event.event_type == EventType.ERROR:
                    msg = event.data.get("error", "Unknown")
                    error_detail = event.data.get("detail", "")
                    traceback_snippet = event.data.get("traceback", "")
                    
                    live.update(Text(""))
                    
                    self.console.print()
                    self.console.print(f"[{WARNING_RED}]✗ ERROR: {msg}[/]")
                    
                    if error_detail:
                        self.console.print(f"[{DIM_GRAY}]   {error_detail}[/]")
                    
                    if traceback_snippet:
                        tb_lines = traceback_snippet.strip().split("\n")[-3:]
                        self.console.print(f"[{DIM_GRAY}]   Traceback:[/]")
                        for line in tb_lines:
                            self.console.print(f"[{DIM_GRAY}]     {line}[/]")
                    
                    self.console.print(f"[{DIM_GRAY}]   💡 Use /status or Ctrl+P to pause[/]")
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
                title="Commands", border_style=DIM_GRAY
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
                self.console.print(f"[{WARNING_RED}]Usage: /show <id>[/]")
                return True
                
            rec_id = int(args[0])
            record = self.output_manager.get(rec_id)
            if record:
                self.console.print(Panel(
                    record.content,
                    title=f"[{ELECTRIC_BLUE}]Action #{rec_id} Output[/]",
                    border_style=ELECTRIC_BLUE,
                    box=box.ROUNDED
                ))
            else:
                self.console.print(f"[{WARNING_RED}]ID #{rec_id} not found.[/]")
                
        elif command == "/tools":
            if self.mcp_client and self.mcp_client.tools:
                table = Table(box=box.SIMPLE, show_header=True, header_style=NEON_GREEN)
                table.add_column("Tool", style=ELECTRIC_BLUE)
                table.add_column("Description", style=DIM_GRAY)
                for tool in self.mcp_client.tools:
                    desc = tool.description[:60] + "..." if len(tool.description) > 60 else tool.description
                    table.add_row(tool.name, desc)
                self.console.print(table)
            else:
                self.console.print(f"[{WARNING_RED}]No tools loaded.[/]")
            
        elif command == "/clear":
            # Clear agent state and output history
            if self.agent and hasattr(self.agent, 'state'):
                # Clear message history but keep system prompt
                if hasattr(self.agent.state, 'messages'):
                    system_msgs = [m for m in self.agent.state.messages if m.role == "system"]
                    self.agent.state.messages = system_msgs
                    self.console.print(f"[{NEON_GREEN}]✓ Agent context cleared.[/]")
            
            # Clear output manager
            self.output_manager.clear()
            self.console.print(f"[{NEON_GREEN}]✓ Output history cleared.[/]")
        
        elif command == "/purge":
            # Dangerous: delete ALL engagements from database
            self.console.print(f"[{WARNING_RED}]⚠ WARNING: This will delete ALL engagements from the database.[/]")
            self.console.print(f"[{DIM_GRAY}]Type 'yes' to confirm, anything else to cancel.[/]")
            
            try:
                # Use async prompt to avoid event loop conflict
                confirm_session = PromptSession()
                confirm = await confirm_session.prompt_async("Confirm purge: ")
                confirm = confirm.strip().lower()
                
                if confirm == "yes":
                    await self._purge_all_engagements()
                    self.console.print(f"[{NEON_GREEN}]✓ All engagements deleted.[/]")
                else:
                    self.console.print(f"[{DIM_GRAY}]Purge cancelled.[/]")
            except Exception as e:
                self.console.print(f"[{WARNING_RED}]Error: {e}[/]")
            
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
        
        self.console.print(f"[{NEON_GREEN}]✓ Previous engagement paused.[/]")
        self.console.print(f"[{NEON_GREEN}]✓ Session state reset.[/]")
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
                    f"[{WARNING_RED}]⚠ Cost Alert[/]\n\n"
                    f"Session has exceeded ${threshold:.2f}\n"
                    f"Current total: ${self.total_cost:.4f}\n\n"
                    f"Use /metrics to view detailed stats.",
                    border_style=WARNING_RED,
                    box=box.HEAVY
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
        table = Table(title="Session Metrics", box=box.ROUNDED, border_style=CYBER_PURPLE)
        table.add_column("Metric", style=ELECTRIC_BLUE)
        table.add_column("Value", justify="right", style=NEON_GREEN)
        
        table.add_row("Session Duration", elapsed)
        table.add_row("Iterations", str(self.iteration_count))
        table.add_row("Findings", str(self.findings_count))
        table.add_row("Total Tokens (in)", f"{self.total_tokens_in:,}")
        table.add_row("Total Tokens (out)", f"{self.total_tokens_out:,}")
        table.add_row("Total Tokens", f"{self.total_tokens_in + self.total_tokens_out:,}")
        table.add_row("Total Cost", f"${self.total_cost:.4f}", style=GOLD)
        
        # Cost efficiency
        if self.iteration_count > 0:
            cost_per_iteration = self.total_cost / self.iteration_count
            table.add_row("Cost/Iteration", f"${cost_per_iteration:.4f}")
        
        # Token efficiency
        total_tokens = self.total_tokens_in + self.total_tokens_out
        if total_tokens > 0:
            cost_per_1k = (self.total_cost / total_tokens) * 1000
            table.add_row("Cost/1K Tokens", f"${cost_per_1k:.4f}")
        
        self.console.print()
        self.console.print(table)
        self.console.print()
    
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
                f"[{NEON_GREEN}]✓ Session Exported Successfully[/]\n\n"
                f"File: [{ELECTRIC_BLUE}]{output_path}[/]\n"
                f"Size: [{MUTED_TEXT}]{size_kb:.1f} KB[/]\n\n"
                f"Actions: {len(export_data['actions'])}\n"
                f"Total Cost: [{GOLD}]${self.total_cost:.4f}[/]\n\n"
                f"[{DIM_GRAY}]Share this file for collaboration or bug reports[/]",
                title=f"[{NEON_GREEN}]📦 Export Complete[/]",
                border_style=NEON_GREEN,
                box=box.ROUNDED
            ))
            
        except Exception as e:
            self.console.print(f"[{WARNING_RED}]Export failed: {e}[/]")

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
