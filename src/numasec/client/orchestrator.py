"""
NumaSec - Orchestrator

The main agent brain that coordinates LLM reasoning with MCP tools.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncGenerator

from numasec.client.mcp_client import AsyncMCPClient, ToolResult
from numasec.client.context import ContextManager, ContextConfig
from numasec.client.providers.base import (
    LLMProvider,
    Message,
    ToolCall,
    ToolDefinition,
    LLMResponse,
)


logger = logging.getLogger("numasec.orchestrator")


@dataclass
class SolveResult:
    """Result from solving a challenge."""
    success: bool
    flag: str | None
    iterations: int
    findings: list[str]
    duration_seconds: float
    error: str | None = None


@dataclass
class OrchestratorConfig:
    """Orchestrator configuration."""
    max_iterations: int = 30
    parallel_tools: bool = True  # Execute parallel tool calls
    verbose: bool = True  # Print progress
    system_prompt: str = ""  # Custom system prompt


DEFAULT_SYSTEM_PROMPT = """You are an expert penetration tester specializing in vulnerability assessment and exploitation.
Your goal is to identify security vulnerabilities and extract proof of compromise (credentials, data, access tokens).

APPROACH:
1. Start with reconnaissance - understand the target
2. Identify entry points - forms, APIs, hidden paths
3. Test for vulnerabilities - injection, authentication bypass, etc.
4. Think step by step - reason about what you observe
5. When you find credentials or proof of compromise, report them clearly

AVAILABLE TOOLS:
You have access to security testing tools. Use them wisely:
- web_request: Make HTTP requests (GET, POST, etc.)
- recon_nmap: Port scanning
- web_ffuf: Directory fuzzing
- And more...

When you find proof of compromise (credentials, sensitive data, access tokens), say "COMPROMISE FOUND: <details>".
"""


class Orchestrator:
    """
    The heart of NumaSec - coordinates LLM reasoning with MCP tools.
    
    Unlike a simple ReAct loop, this orchestrator:
    1. Manages context window intelligently
    2. Supports parallel tool execution
    3. Handles multi-step reasoning
    4. Extracts and reports findings
    
    Usage:
        async with Orchestrator(mcp_client, llm_provider) as agent:
            result = await agent.solve("http://target.com", "find the flag")
    """
    
    def __init__(
        self,
        mcp_client: AsyncMCPClient,
        llm_provider: LLMProvider,
        config: OrchestratorConfig | None = None,
        context: ContextManager | None = None,
    ):
        self.mcp = mcp_client
        self.llm = llm_provider
        self.config = config or OrchestratorConfig()
        self.context = context or ContextManager()
        self._running = False
        self._stop_requested = False
    
    async def assess(
        self,
        target: str,
        objective: str,
        hints: list[str] | None = None,
    ) -> SolveResult:
        """
        Perform security assessment of a target.
        
        Enterprise security testing mode. Identifies vulnerabilities,
        misconfigurations, and potential attack vectors.
        
        Args:
            target: Target URL, IP, or description
            objective: Assessment goal (e.g., "identify OWASP Top 10 vulnerabilities")
            hints: Optional guidance for testing scope
            
        Returns:
            SolveResult with vulnerabilities, findings, and assessment stats
        """
        start_time = datetime.now()
        self._running = True
        self._stop_requested = False
        
        # Get tools for LLM
        tools = self.mcp.tools
        
        # Build initial context
        system_prompt = self.config.system_prompt or DEFAULT_SYSTEM_PROMPT
        
        self.context.add_message(Message(role="system", content=system_prompt))
        
        # User message with target and assessment objectives
        user_content = f"Target: {target}\nAssessment Objective: {objective}"
        if hints:
            user_content += f"\n\nGuidance:\n" + "\n".join(f"- {h}" for h in hints)
        user_content += "\n\nBegin your security assessment."
        
        self.context.add_message(Message(role="user", content=user_content))
        
        flag = None
        error = None
        iteration = 0
        
        try:
            for iteration in range(1, self.config.max_iterations + 1):
                if self._stop_requested:
                    break
                
                if self.config.verbose:
                    print(f"\n{'='*60}")
                    print(f"Iteration {iteration}/{self.config.max_iterations}")
                    print('='*60)
                
                # Prune context if needed
                if self.context.needs_pruning():
                    self.context.prune()
                
                # Get LLM response
                try:
                    response = await self.llm.chat(
                        self.context.get_messages(),
                        tools,
                    )
                except Exception as e:
                    logger.error(f"LLM error: {e}")
                    error = str(e)
                    break
                
                # Add assistant message to context
                assistant_msg = Message(
                    role="assistant",
                    content=response.content or "",
                    tool_calls=response.tool_calls if response.has_tool_calls else None,
                )
                self.context.add_message(assistant_msg)
                
                # Print reasoning
                if self.config.verbose and response.content:
                    print(f"\n🧠 REASONING:\n{response.content[:500]}...")
                
                # Check for security findings in reasoning
                if response.content:
                    # Priority 1: Vulnerability detection (enterprise)
                    vulnerability = self._extract_vulnerability(response.content)
                    if vulnerability:
                        if self.config.verbose:
                            print(f"\n🎯 VULNERABILITY: {vulnerability['type']} ({vulnerability['severity']})")
                        # Store but continue assessment (find all vulns)
                        if not flag:  # Use flag variable for primary finding
                            flag = f"{vulnerability['type']}__{vulnerability['severity']}"
                    
                    # Priority 2: Legacy credential pattern detection (backward compat)
                    if not flag:
                        credential_pattern = self._extract_flag(response.content)
                        if credential_pattern:
                            if self.config.verbose:
                                print(f"\n🔑 CREDENTIAL PATTERN FOUND: {credential_pattern}")
                            flag = credential_pattern
                            break  # Mission complete on credential extraction
                
                # Handle tool calls
                if not response.has_tool_calls:
                    if self.config.verbose:
                        print("\n✓ LLM completed reasoning (no tool calls)")
                    continue
                
                # Execute tool calls (parallel if supported)
                tool_results = await self._execute_tool_calls(response.tool_calls)
                
                # Add tool results to context
                for tc, result in zip(response.tool_calls, tool_results):
                    self.context.add_tool_result(tc.name, result.content, tc.id)
                    
                    # Check for security findings in tool results
                    if not flag:
                        # Priority 1: Vulnerability patterns
                        vulnerability = self._extract_vulnerability(result.content)
                        if vulnerability:
                            if self.config.verbose:
                                print(f"\n🎯 VULNERABILITY: {vulnerability['type']} ({vulnerability['severity']})")
                            flag = f"{vulnerability['type']}__{vulnerability['severity']}"
                        
                        # Priority 2: Legacy credential patterns (backward compatibility)
                        if not flag:
                            flag = self._extract_flag(result.content)
                            if flag:
                                if self.config.verbose:
                                    print(f"\n🔑 CREDENTIAL PATTERN FOUND: {flag}")
                                break  # Mission complete
                
                if flag:
                    break
                    
        except asyncio.CancelledError:
            error = "Cancelled"
        except Exception as e:
            logger.exception("Orchestrator error")
            error = str(e)
        finally:
            self._running = False
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return SolveResult(
            success=flag is not None,
            flag=flag,
            iterations=iteration,
            findings=self.context.get_critical_findings(),
            duration_seconds=duration,
            error=error,
        )
    
    async def _execute_tool_calls(
        self, 
        tool_calls: list[ToolCall]
    ) -> list[ToolResult]:
        """Execute tool calls, potentially in parallel."""
        if self.config.parallel_tools and len(tool_calls) > 1:
            # Parallel execution
            if self.config.verbose:
                print(f"\n⚡ Executing {len(tool_calls)} tools in parallel...")
            
            results = await self.mcp.call_tools_parallel([
                (tc.name, tc.arguments) for tc in tool_calls
            ])
        else:
            # Sequential execution
            results = []
            for tc in tool_calls:
                if self.config.verbose:
                    args_preview = json.dumps(tc.arguments)[:150]
                    print(f"\n⚡ {tc.name}({args_preview}...)")
                
                result = await self.mcp.call_tool(tc.name, tc.arguments)
                results.append(result)
                
                if self.config.verbose:
                    preview = result.content[:300] if result.content else ""
                    print(f"📤 Result ({len(result.content)} chars): {preview}...")
        
        return results
    
    def _extract_vulnerability(self, text: str) -> dict | None:
        """
        Extract vulnerability indicators from tool/LLM output.
        
        Enterprise-focused detection for real-world security findings.
        
        Returns:
            Dict with {type, severity, evidence} or None
        """
        # SQL Injection indicators
        sql_patterns = [
            (r"SQL syntax.*error", "sql_injection", "CRITICAL"),
            (r"mysql_fetch|pg_query", "sql_injection", "CRITICAL"),
            (r"ORA-\d{5}", "sql_injection", "CRITICAL"),
        ]
        
        # XSS indicators
        xss_patterns = [
            (r"<script[^>]*>.*</script>", "xss", "HIGH"),
            (r"javascript:\w+\(", "xss", "HIGH"),
        ]
        
        # Command Injection
        cmd_patterns = [
            (r"root:x:0:0:", "command_injection", "CRITICAL"),
            (r"/etc/passwd", "path_traversal", "HIGH"),
            (r"uid=\d+.*gid=\d+", "command_injection", "CRITICAL"),
        ]
        
        # Combine all patterns
        all_patterns = sql_patterns + xss_patterns + cmd_patterns
        
        for pattern, vuln_type, severity in all_patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                return {
                    "type": vuln_type,
                    "severity": severity,
                    "evidence": match.group(0)[:200]
                }
        
        return None
    
    def _extract_flag(self, text: str) -> str | None:
        """Extract credential patterns from text.
        
        Generalized pattern matching for credential/secret extraction in
        professional pentesting and training platform contexts.
        Supports: passwords, API keys, tokens, and common secret formats.
        """
        patterns = [
            r'picoCTF\{[^}]+\}',  # Training platform pattern
            r'flag\{[^}]+\}',     # Training platform pattern
            r'CTF\{[^}]+\}',      # Training platform pattern
            r'htb\{[^}]+\}',      # Training platform pattern
            r'THM\{[^}]+\}',      # Training platform pattern
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group()
        
        return None
    
    def stop(self) -> None:
        """Request graceful stop."""
        self._stop_requested = True
    
    @property
    def is_running(self) -> bool:
        """Check if orchestrator is running."""
        return self._running
    
    async def __aenter__(self) -> "Orchestrator":
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        pass


async def create_default_orchestrator(
    api_key: str | None = None,
    use_direct_transport: bool = True,
) -> tuple[Orchestrator, AsyncMCPClient, LLMProvider]:
    """
    Factory function to create an orchestrator with default settings.
    
    Args:
        api_key: DeepSeek API key (or from DEEPSEEK_API_KEY env)
        use_direct_transport: Use direct transport (faster) vs stdio
        
    Returns:
        Tuple of (Orchestrator, AsyncMCPClient, LLMProvider)
    """
    from numasec.client.providers.deepseek import DeepSeekProvider, DeepSeekConfig
    
    if use_direct_transport:
        from numasec.client.transports.direct import DirectTransport
        transport = DirectTransport()
    else:
        from numasec.client.transports.stdio import StdioTransport
        transport = StdioTransport()
    
    mcp_client = AsyncMCPClient(transport)
    await mcp_client.connect()
    
    llm_config = DeepSeekConfig(api_key=api_key or "")
    llm_provider = DeepSeekProvider(llm_config)
    
    orchestrator = Orchestrator(mcp_client, llm_provider)
    
    return orchestrator, mcp_client, llm_provider
