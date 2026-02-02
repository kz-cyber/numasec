"""
Engage Command - Interactive pentesting session with AI Agent.

This command launches the NumaSec Ultimate agent for autonomous
penetration testing with human-in-the-loop oversight.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from numasec.core.approval import ApprovalMode
from numasec.compliance import PTESPhase, get_ptes_controller
from numasec.data.database import get_session, init_database
from numasec.data.repositories.engagement import EngagementRepository

console = Console()


# ══════════════════════════════════════════════════════════════════════════════
# Agent Mode - Real AI Agent Loop
# ══════════════════════════════════════════════════════════════════════════════


async def run_agent(
    target: str,
    objective: str = "",
    mode: ApprovalMode = ApprovalMode.SUPERVISED,
    max_iterations: int = 100,  # Increased from 50 for complex assessments
    verbose: bool = True,
    debug: bool = False,
) -> dict:
    """
    Run the NumaSec Ultimate agent.
    
    Args:
        target: Target URL or description
        objective: What to achieve
        mode: Approval mode
        max_iterations: Maximum iterations
        verbose: Show verbose output
        debug: Show full debug output (code, responses, etc.)
        
    Returns:
        Results dictionary
    """
    from numasec.ai.router import LLMRouter
    from numasec.agent import NumaSecAgent, AgentConfig
    from numasec.agent.events import EventType
    from rich.syntax import Syntax
    from rich.panel import Panel as RichPanel
    
    console.print(
        Panel(
            f"[bold green]🚀 Starting NumaSec Ultimate Agent[/bold green]\n\n"
            f"🎯 Target: [cyan]{target}[/cyan]\n"
            f"📋 Objective: {objective or 'Find vulnerabilities'}\n"
            f"🎚️ Mode: [yellow]{mode.value}[/yellow]\n"
            f"🔄 Max Iterations: {max_iterations}"
            + (f"\n[dim]🔍 Debug mode: ON[/dim]" if debug else ""),
            title="🧠 AI Agent",
            border_style="green",
        )
    )
    
    # Initialize LLM Router
    try:
        router = LLMRouter()
        console.print("[green]✓[/green] LLM Router initialized")
    except Exception as e:
        console.print(f"[red]✗ Failed to initialize LLM Router: {e}[/red]")
        console.print("[dim]Make sure ANTHROPIC_API_KEY, OPENAI_API_KEY, or DEEPSEEK_API_KEY is set[/dim]")
        return {"success": False, "error": str(e)}
    
    # Initialize Agent using factory method (includes V2 components)
    config = AgentConfig(
        max_iterations=max_iterations,
    )
    
    agent = NumaSecAgent.create(
        router=router,
        target=target,
        approval_mode=mode,
        config=config,
    )
    
    # Event handler for UI
    findings = []
    flag = None
    last_code = None  # Track last Python code for debug display
    
    def on_event(event):
        nonlocal flag, last_code
        
        if event.event_type == EventType.THINK:
            reasoning = event.data.get("reasoning", "")
            confidence = event.data.get("confidence", 0)
            method = event.data.get("method", "single")
            
            if debug:
                # Full reasoning in debug mode
                console.print(f"\n[bold cyan]🧠 REASONING ({method}, {confidence:.0%} confidence):[/bold cyan]")
                console.print(f"[dim]{reasoning}[/dim]\n")
            elif verbose:
                console.print(
                    f"[dim]🧠 [{method}] {reasoning[:100]}... "
                    f"(confidence: {confidence:.0%})[/dim]"
                )
        
        elif event.event_type == EventType.ACTION_PROPOSED:
            tool = event.data.get("tool", "")
            params = event.data.get("params", {})
            
            if debug and tool in ("run_python", "python_script"):
                # Show the full Python code being executed
                code = params.get("code", params.get("script", ""))
                if code:
                    last_code = code
                    console.print(f"\n[bold yellow]⚡ EXECUTING PYTHON:[/bold yellow]")
                    try:
                        syntax = Syntax(code, "python", theme="monokai", line_numbers=True)
                        console.print(syntax)
                    except:
                        console.print(f"[dim]{code}[/dim]")
            elif debug and tool in ("run_shell", "shell_script"):
                # Show shell command
                cmd = params.get("command", params.get("script", ""))
                console.print(f"\n[bold yellow]⚡ EXECUTING SHELL:[/bold yellow]")
                console.print(f"[green]{cmd}[/green]")
            else:
                params_str = ", ".join(f"{k}={str(v)[:30]}" for k, v in list(params.items())[:3])
                console.print(f"[cyan]⚡ {tool}({params_str})[/cyan]")
        
        elif event.event_type == EventType.ACTION_COMPLETE:
            reward = event.data.get("reward", 0)
            duration = event.data.get("duration_ms", 0)
            result = event.data.get("result", "")
            
            if debug:
                # Show full result in debug mode
                console.print(f"\n[bold green]📤 RESULT (reward: {reward:.2f}, {duration:.0f}ms):[/bold green]")
                if isinstance(result, str) and len(result) > 500:
                    console.print(f"[dim]{result[:2000]}{'...[truncated]' if len(result) > 2000 else ''}[/dim]")
                else:
                    console.print(f"[dim]{result}[/dim]")
                console.print("")  # Blank line for readability
            elif verbose:
                console.print(f"[dim]   → reward: {reward:.2f}, time: {duration:.0f}ms[/dim]")
        
        elif event.event_type == EventType.DISCOVERY:
            for disc in event.data.get("discoveries", []):
                console.print(f"[green]   🔍 {disc['type']}: {disc['value'][:60]}[/green]")
        
        elif event.event_type == EventType.FLAG:
            flag = event.data.get("flag", "")
            console.print(f"\n[bold green]🎉 VULNERABILITY FOUND: {flag}[/bold green]\n")
        
        elif event.event_type == EventType.FINDING:
            findings.append(event.data)
            severity = event.data.get("severity", "medium")
            title = event.data.get("title", "Unknown")
            console.print(f"[yellow]📋 Finding: [{severity}] {title}[/yellow]")
        
        elif event.event_type == EventType.ERROR:
            if event.data.get("recoverable"):
                console.print(f"[yellow]⚠️ {event.data.get('message', '')}[/yellow]")
            else:
                console.print(f"[red]❌ {event.data.get('message', '')}[/red]")
        
        elif event.event_type == EventType.COMPLETE:
            pass  # Handled after loop
    
    agent.on_event(on_event)
    
    # Run agent
    start_time = datetime.now(timezone.utc)
    iterations = 0
    max_iteration_seen = 0
    
    console.print("\n[dim]═══ Agent Running ═══[/dim]\n")
    
    try:
        async for event in agent.run(target=target, objective=objective):
            # Track the highest iteration number seen
            if hasattr(event, 'iteration') and event.iteration > max_iteration_seen:
                max_iteration_seen = event.iteration
            
            if event.event_type == EventType.COMPLETE:
                # Use the iteration count from complete event if available
                if hasattr(event, 'iterations'):
                    iterations = event.iterations
                else:
                    iterations = max_iteration_seen
                break
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Agent stopped by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Agent error: {e}[/red]")
        import traceback
        if verbose:
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
    
    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    
    # Show summary
    console.print("\n[dim]═══ Agent Summary ═══[/dim]\n")
    
    stats = agent.get_stats()
    
    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Key", style="cyan")
    summary_table.add_column("Value")
    
    summary_table.add_row("Iterations", str(iterations))
    summary_table.add_row("Duration", f"{duration:.1f}s")
    summary_table.add_row("Findings", str(len(findings)))
    summary_table.add_row("Flag", flag or "Not found")
    summary_table.add_row("Exploration Efficiency", 
                          f"{stats['explorer']['exploration_efficiency']:.0%}")
    
    console.print(summary_table)
    
    return {
        "success": bool(flag),
        "flag": flag,
        "findings": findings,
        "iterations": iterations,
        "duration_seconds": duration,
        "stats": stats,
    }


class EngageSession:
    """Interactive engagement session with AI."""

    def __init__(
        self,
        engagement_id: str,
        mode: ApprovalMode = ApprovalMode.SUPERVISED,
    ) -> None:
        self.engagement_id = engagement_id
        self.mode = mode
        self.running = False
        self.current_phase = PTESPhase.PRE_ENGAGEMENT
        self.ptes = get_ptes_controller()

    async def run(self) -> None:
        """Run the interactive session."""
        self.running = True

        self._show_welcome()

        while self.running:
            try:
                await self._session_loop()
            except KeyboardInterrupt:
                if Confirm.ask("\n[yellow]Exit session?[/yellow]"):
                    self.running = False
                    console.print("[dim]Session ended.[/dim]")
                    break

    def _show_welcome(self) -> None:
        """Show session welcome message."""
        console.print(
            Panel(
                f"[bold green]Interactive Session Started[/bold green]\n\n"
                f"📋 Engagement: {self.engagement_id[:8]}...\n"
                f"🎚️ Mode: {self.mode.value}\n"
                f"📍 Phase: {self.current_phase.value}\n\n"
                "[dim]Commands: help, status, phase, suggest, tool, finding, exit[/dim]",
                title="🎯 NumaSec - Engage Mode",
                border_style="green",
            )
        )

    async def _session_loop(self) -> None:
        """Main session command loop."""
        command = Prompt.ask("\n[cyan]numasec[/cyan]")

        if not command.strip():
            return

        parts = command.strip().split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if cmd in ("exit", "quit", "q"):
            if Confirm.ask("[yellow]Exit session?[/yellow]"):
                self.running = False
        elif cmd == "help":
            self._show_help()
        elif cmd == "status":
            await self._show_status()
        elif cmd == "phase":
            await self._handle_phase(args)
        elif cmd == "suggest":
            await self._suggest_action(args)
        elif cmd == "tool":
            await self._run_tool(args)
        elif cmd == "finding":
            await self._handle_finding(args)
        elif cmd == "scan":
            await self._quick_scan(args)
        else:
            console.print(f"[yellow]Unknown command: {cmd}[/yellow]")
            console.print("[dim]Type 'help' for available commands[/dim]")

    def _show_help(self) -> None:
        """Show help message."""
        table = Table(title="Available Commands", show_header=True)
        table.add_column("Command", style="cyan")
        table.add_column("Description")
        table.add_column("Example", style="dim")

        commands = [
            ("help", "Show this help message", "help"),
            ("status", "Show current engagement status", "status"),
            ("phase [name]", "Show/change PTES phase", "phase intelligence"),
            ("suggest [topic]", "Get AI suggestions", "suggest recon"),
            ("tool <name> [args]", "Run a security tool", "tool nmap -p 80 target"),
            ("finding [add|list]", "Manage findings", "finding add"),
            ("scan <target>", "Quick vulnerability scan", "scan example.com"),
            ("exit", "Exit the session", "exit"),
        ]

        for cmd, desc, example in commands:
            table.add_row(cmd, desc, example)

        console.print(table)

    async def _show_status(self) -> None:
        """Show current engagement status."""
        # Get phase info
        phase_def = self.ptes.get_phase_definition(self.current_phase)
        progress = self.ptes.get_phase_progress(self.current_phase)

        # Phase table
        phase_table = Table(title="Current Phase", show_header=False)
        phase_table.add_column("Key", style="cyan")
        phase_table.add_column("Value")

        phase_table.add_row("Phase", phase_def.name)
        phase_table.add_row("Description", phase_def.description[:60] + "...")
        phase_table.add_row("Risk Level", phase_def.risk_level.upper())
        phase_table.add_row("Progress", f"{progress['percentage']}%")
        phase_table.add_row("Recommended Tools", ", ".join(phase_def.tools) or "N/A")

        console.print(phase_table)

        # All phases summary
        console.print()
        summary_table = Table(title="PTES Phases", show_header=True)
        summary_table.add_column("#", style="dim")
        summary_table.add_column("Phase")
        summary_table.add_column("Status")

        for i, phase in enumerate(PTESPhase, 1):
            phase_def = self.ptes.get_phase_definition(phase)
            status = "🔵 Current" if phase == self.current_phase else (
                "✅ Complete" if i < list(PTESPhase).index(self.current_phase) + 1 else "⬜ Pending"
            )
            summary_table.add_row(str(i), phase_def.name, status)

        console.print(summary_table)

    async def _handle_phase(self, args: str) -> None:
        """Handle phase command."""
        if not args:
            # Show current phase details
            phase_def = self.ptes.get_phase_definition(self.current_phase)
            console.print(
                Panel(
                    f"[bold]{phase_def.name}[/bold]\n\n"
                    f"{phase_def.description}\n\n"
                    f"[cyan]Objectives:[/cyan]\n"
                    + "\n".join(f"  • {obj}" for obj in phase_def.objectives[:5])
                    + "\n\n"
                    f"[cyan]Tools:[/cyan] {', '.join(phase_def.tools) or 'N/A'}",
                    title=f"📍 Phase: {self.current_phase.value}",
                    border_style="blue",
                )
            )
        else:
            # Try to change phase
            phase_name = args.lower().replace(" ", "_")
            for phase in PTESPhase:
                if phase_name in phase.value.lower():
                    self.current_phase = phase
                    console.print(f"[green]Switched to phase: {phase.value}[/green]")
                    return
            console.print(f"[red]Unknown phase: {args}[/red]")

    async def _suggest_action(self, args: str) -> None:
        """Get AI suggestions for next action."""
        phase_def = self.ptes.get_phase_definition(self.current_phase)
        
        console.print(
            Panel(
                f"[bold]Suggested Actions for {phase_def.name}[/bold]\n\n"
                f"Based on the current phase, you should:\n\n"
                + "\n".join(f"[cyan]{i}.[/cyan] {activity}" for i, activity in enumerate(phase_def.activities[:5], 1))
                + "\n\n"
                f"[dim]Recommended tools: {', '.join(phase_def.tools) or 'None specific'}[/dim]",
                title="💡 AI Suggestions",
                border_style="yellow",
            )
        )

    async def _run_tool(self, args: str) -> None:
        """Run a security tool."""
        if not args:
            console.print("[yellow]Usage: tool <name> [arguments][/yellow]")
            console.print("[dim]Available tools: nmap, nuclei, ffuf, httpx, sqlmap, hydra[/dim]")
            return

        parts = args.split(maxsplit=1)
        tool_name = parts[0]
        tool_args = parts[1] if len(parts) > 1 else ""

        # Show approval prompt for non-low-risk tools
        if tool_name in ("sqlmap", "hydra"):
            if self.mode == ApprovalMode.SUPERVISED:
                console.print(
                    Panel(
                        f"[bold red]⚠️ High-Risk Tool: {tool_name}[/bold red]\n\n"
                        f"Arguments: {tool_args or 'none'}\n\n"
                        "This tool may cause significant impact on the target.",
                        title="🔐 Approval Required",
                        border_style="red",
                    )
                )
                if not Confirm.ask("[yellow]Approve execution?[/yellow]"):
                    console.print("[dim]Execution cancelled.[/dim]")
                    return

        console.print(f"[dim]Executing: {tool_name} {tool_args}[/dim]")
        console.print("[yellow]Tool execution is simulated in this demo.[/yellow]")

    async def _handle_finding(self, args: str) -> None:
        """Handle finding management."""
        if args.lower() == "add":
            console.print("[yellow]Interactive finding creation...[/yellow]")
            title = Prompt.ask("Finding title")
            severity = Prompt.ask(
                "Severity",
                choices=["critical", "high", "medium", "low", "info"],
                default="medium",
            )
            description = Prompt.ask("Description")
            console.print(f"[green]Finding created: {title} ({severity})[/green]")
        else:
            # List findings
            console.print("[dim]No findings recorded yet.[/dim]")

    async def _quick_scan(self, args: str) -> None:
        """Quick vulnerability scan."""
        if not args:
            console.print("[yellow]Usage: scan <target>[/yellow]")
            return

        console.print(f"[cyan]Scanning target: {args}[/cyan]")
        console.print("[yellow]Scan simulation...[/yellow]")


async def engage_session(
    engagement_id: str | None = None,
    mode: str | None = None,
) -> None:
    """Start an interactive engagement session."""
    # Initialize database
    await init_database()

    # Get active engagement or specific one
    async with get_session() as session:
        repo = EngagementRepository(session)

        if engagement_id:
            engagement = await repo.get_by_id(engagement_id)
        else:
            engagement = await repo.get_active()

        if not engagement:
            console.print(
                Panel(
                    "[red]No active engagement found.[/red]\n\n"
                    "Start a new engagement with:\n"
                    "  [cyan]numasec init --client 'Client Name' --scope 'target'[/cyan]",
                    title="❌ Error",
                    border_style="red",
                )
            )
            return

        # Parse mode
        approval_mode = ApprovalMode.SUPERVISED
        if mode:
            try:
                approval_mode = ApprovalMode(mode.lower())
            except ValueError:
                console.print(f"[yellow]Invalid mode: {mode}, using supervised[/yellow]")

        # Start session
        session_obj = EngageSession(
            engagement_id=engagement.id,
            mode=approval_mode,
        )
        await session_obj.run()
