"""
NumaSec - Interactive Chat Mode

Launch with just 'numasec' for an interactive AI pentesting assistant.
"""

from __future__ import annotations

import asyncio
import sys
import os
from pathlib import Path

# Rich for beautiful terminal UI
try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Import our premium UI
from numasec.cli.ui.theme import NumaSecUI, get_ui

console = Console() if RICH_AVAILABLE else None
ui = get_ui()


def print_banner():
    """Print the NumaSec banner."""
    ui.print_banner()


def print_help():
    """Print help message."""
    ui.print_help()


class InteractiveSession:
    """Interactive chat session with NumaSec."""
    
    def __init__(self):
        self.mcp_client = None
        self.llm_provider = None
        self.messages = []  # Simplified message history
        self.pending_action = None  # What AI wants to do next
        self.auto_mode = False
        self.agent = None # NumaSecAgent instance
        
        self.system_prompt = "You are NumaSec." # Placeholder for Agent logic
    
    async def start(self):
        """Start the interactive session."""
        
        # Enable logging (WARNING level to reduce noise)
        import logging
        logging.basicConfig(level=logging.WARNING, format='%(name)s: %(message)s')
        # Suppress httpx request logging
        logging.getLogger("httpx").setLevel(logging.ERROR)
        
        # Load .env
        env_file = self._find_env_file()
        if env_file:
            self._load_env(env_file)
        
        api_key = os.environ.get("DEEPSEEK_API_KEY", os.environ.get("ANTHROPIC_API_KEY", ""))
        
        # ═══════════════════════════════════════════════════════════════════════
        # MCP-First Architecture: Connect MCP Client
        # ═══════════════════════════════════════════════════════════════════════
        ui.status("Initializing...", style="dim")
        
        from numasec.client.transports.direct import DirectTransport
        from numasec.client.mcp_client import AsyncMCPClient
        from numasec.ai.router import LLMRouter, LLMProvider
        from numasec.agent import NumaSecAgent, AgentConfig
        from numasec.core.approval import ApprovalMode
        
        # 1. Connect MCP Client (Tool Layer)
        try:
            transport = DirectTransport()
            self.mcp_client = AsyncMCPClient(transport)
            await self.mcp_client.connect()
        except Exception as e:
            ui.error(f"MCP Connection Failed: {e}")
            return
        
        # 2. Initialize LLM Router (Brain Layer)
        try:
            router = LLMRouter(primary=LLMProvider.DEEPSEEK)
        except Exception as e:
            ui.error(f"Router Init Failed: {e}")
            await self.mcp_client.disconnect()
            return

        ui.print_ready(len(self.mcp_client.tools))
        
        # 3. Initialize Agent WITH mcp_client (Full Integration)
        self.agent = NumaSecAgent.create(
            router=router,
            mcp_client=self.mcp_client,
            target="interactive",
            approval_mode=ApprovalMode.SUPERVISED
        )
        
        # Run the agent loop
        try:
            await self._agent_loop()
        finally:
            # Cleanup
            await self.mcp_client.disconnect()
            await router.close()
            self._status("Session closed.")
        
    def _find_env_file(self):
        check = Path.cwd()
        for _ in range(5):
            f = check / ".env"
            if f.exists():
                return f
            check = check.parent
        return None
    
    def _load_env(self, path):
        for line in path.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())
    
    async def _agent_loop(self):
        """Main loop using the Agent."""
        while True:
            try:
                # Get input
                if RICH_AVAILABLE:
                    user_input = Prompt.ask("\n[bold green]You[/bold green]")
                else:
                    user_input = input("\nYou: ")
                
                if not user_input.strip():
                    continue

                # Commands
                if user_input.startswith("/"):
                    if not await self._command(user_input):
                        break
                    continue
                
                # Chat with Agent (Hybrid Mode)
                await self._run_chat(user_input)
                
            except KeyboardInterrupt:
                self._status("Goodbye!")
                break
            except EOFError:
                break
            except asyncio.CancelledError:
                 self._status("Operation Cancelled.")

    async def _run_chat(self, text: str):
         """Run a chat turn with the agent - autonomous loop like Claude Code."""
         from numasec.agent.events import EventType
         
         # Stream events from agent.chat() - shows autonomous progress
         async for event in self.agent.chat(text):
             if event.event_type == EventType.THINK:
                 reasoning = event.data.get("reasoning", "")
                 iteration = event.data.get("iteration", 0)
                 
                 # Show REAL agent reasoning with iteration counter
                 if reasoning:
                     if RICH_AVAILABLE:
                         title = f"🧠 Agent Reasoning (Step {iteration})" if iteration > 0 else "🧠 Agent Reasoning"
                         console.print(Panel(
                             Markdown(reasoning),
                             title=title,
                             border_style="blue"
                         ))
                     else:
                         print(f"\n🧠 Agent (Step {iteration}): {reasoning}")
                     
             elif event.event_type == EventType.ACTION_PROPOSED:
                 tool = event.data.get("tool")
                 params = event.data.get("params", {})
                 iteration = event.data.get("iteration", 0)
                 
                 # Show real tool execution with parameters
                 if RICH_AVAILABLE:
                     step_indicator = f"[dim]({iteration})[/dim] " if iteration > 0 else ""
                     console.print(f"{step_indicator}[cyan]⚡ {tool}[/cyan] [dim]{params}[/dim]")
                 else:
                     print(f"({iteration}) ⚡ {tool} {params}")
                 
             elif event.event_type == EventType.ACTION_COMPLETE:
                 tool = event.data.get("tool", "action")
                 result = event.data.get("result", "")
                 
                 # Show abbreviated result (not humanized, just truncated)
                 if len(result) > 300:
                     result_preview = result[:300] + "..."
                 else:
                     result_preview = result
                 
                 if RICH_AVAILABLE:
                     console.print(f"[dim]📤 Result: {result_preview}[/dim]")
                 else:
                     print(f"📤 {result_preview}")
                     
             elif event.event_type == EventType.FLAG:
                 finding_type = event.data.get("finding_type", "unknown")
                 
                 if finding_type == "vulnerability":
                     vuln_type = event.data.get("vulnerability", "unknown")
                     severity = event.data.get("severity", "UNKNOWN")
                     evidence = event.data.get("evidence", "")
                     
                     # Show real vulnerability with evidence
                     if RICH_AVAILABLE:
                         console.print(Panel(
                             f"[bold red]Type:[/bold red] {vuln_type}\n"
                             f"[bold yellow]Severity:[/bold yellow] {severity}\n"
                             f"[bold white]Evidence:[/bold white] {evidence[:200]}",
                             title="🎯 Vulnerability Detected",
                             border_style="red"
                         ))
                     else:
                         print(f"\n🎯 VULNERABILITY: {vuln_type} ({severity})")
                         print(f"   Evidence: {evidence[:200]}")
                 else:
                     # Legacy credential pattern
                     flag_data = event.data.get("flag")
                     ui.show_flag_found(flag_data)
                     
             elif event.event_type == EventType.COMPLETE:
                 # Agent finished autonomous work
                 findings_count = event.data.get("findings", 0)
                 iterations = event.data.get("iterations", 0)
                 reason = event.data.get("reason", "completed")
                 
                 if reason == "max_iterations":
                     self._status(f"⚠️ Reached iteration limit ({iterations}). Found {findings_count} issue(s).")
                 else:
                     self._status(f"✅ Task completed in {iterations} step(s). Found {findings_count} issue(s).")
             
             elif event.event_type == EventType.ERROR:
                 error_msg = event.data.get("error", "Unknown error")
                 ui.error(f"Error: {error_msg}")

    async def _command(self, cmd: str) -> bool:
        """Handle command. Returns False to quit."""
        parts = cmd.split(maxsplit=1)
        c = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        
        if c in ("/quit", "/exit", "/q"):
            self._status("Goodbye!")
            return False
        elif c == "/help":
            print_help()
        elif c == "/tools":
            ui.print_tools(self.mcp_client.tools)
        elif c == "/clear":
            if self.agent and self.agent.state:
                self.agent.state.context_messages.clear()
                self.agent._init_system_prompt()
            ui.success("Conversation cleared.")
        elif c in ("/assess", "/test", "/scan"):
            if arg:
                await self._assess(arg)
            else:
                ui.error("Usage: /assess <target>")
        else:
            ui.error(f"Unknown command: {c}")
        return True

    async def _assess(self, target: str):
        """Autonomous security assessment mode."""
        # Detect objective from input (Training mode if keywords present)
        objective = "Perform comprehensive vulnerability assessment" if any(kw in target.lower() for kw in ["training", "challenge", "vulnerable", "practice"]) else "Identify OWASP Top 10 vulnerabilities and security misconfigurations"
        
        ui.start_autonomous(target, objective)
        self.auto_mode = True
        
        from numasec.agent.events import EventType
        
        step_count = 0
        try:
            async for event in self.agent.run(target=target, objective=objective):
                if event.event_type == EventType.THINK:
                    step_count += 1
                    reasoning = event.data.get("reasoning", "")
                    
                    # Show step indicator
                    ui.show_step(step_count, self.agent.config.max_iterations, "Analyzing...")
                    
                    # Show thinking content (only if substantial)
                    if reasoning and len(reasoning) > 50:
                        ui.show_thinking(reasoning)
                        
                elif event.event_type == EventType.ACTION_COMPLETE:
                    tool = event.data.get("tool", "action")
                    result = event.data.get("result", "")
                    ui.show_action_result(tool, result)
                    
                elif event.event_type == EventType.FLAG:
                    flag_data = event.data.get("flag")
                    finding_type = event.data.get("finding_type", "unknown")
                    
                    if finding_type == "vulnerability":
                        vuln_type = event.data.get("vulnerability", "unknown")
                        severity = event.data.get("severity", "UNKNOWN")
                        evidence = event.data.get("evidence", "")
                        ui.success(f"🎯 VULNERABILITY DETECTED: {vuln_type}")
                        ui.status(f"   Severity: {severity}", style="yellow")
                        if evidence:
                            ui.status(f"   Evidence: {evidence[:200]}", style="dim")
                    else:
                        # Legacy credential pattern
                        ui.show_flag_found(flag_data)
                    
                elif event.event_type == EventType.COMPLETE:
                    ui.show_complete(findings=0)
                    
        except KeyboardInterrupt:
            ui.status("\n⏸️  Interrupted. You're back in control.", style="yellow")
        except asyncio.CancelledError:
            ui.status("⏸️  Paused.", style="yellow")
        except Exception as e:
            ui.error(f"Agent Error: {e}")
        finally:
             self.auto_mode = False

    def _status(self, msg):
        ui.status(msg)
    
    def _error(self, msg):
        ui.error(msg)


async def main():
    ui.print_banner()
    await InteractiveSession().start()


def run():
    # MANUAL LOOP MANAGEMENT TO CATCH CTRL+C
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(main())
        except KeyboardInterrupt:
            # Catch Ctrl+C at the top level
            print("\n[!] Force Exit via KeyboardInterrupt")
        finally:
            try:
                # Cancel all running tasks
                tasks = asyncio.all_tasks(loop)
                for task in tasks:
                    task.cancel()
                loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
                loop.close()
            except Exception:
                pass
    except Exception as e:
        print(f"Fatal error: {e}")


if __name__ == "__main__":
    run()
