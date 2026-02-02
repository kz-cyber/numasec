"""
NumaSec - New CLI Entry Point

Uses the new MCP client architecture.
"""

from __future__ import annotations

import asyncio
import argparse
import logging
import os
import sys
from pathlib import Path


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quiet noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


async def assess_command(args: argparse.Namespace) -> int:
    """Perform security assessment using the orchestrator."""
    from numasec.client import create_default_orchestrator
    
    target_display = args.target[:45] + "..." if len(args.target) > 48 else args.target
    print(f"""
╭──────────────────────────────────────────────────────────╮
│  ⚡ NumaSec - AI Security Copilot v2.0            │
├──────────────────────────────────────────────────────────┤
│  Target:      {target_display:<42} │
│  Model:       {args.model:<42} │
│  Iterations:  {args.iterations:<42} │
╰──────────────────────────────────────────────────────────╯
""")
    
    orchestrator, mcp_client, llm_provider = await create_default_orchestrator(
        api_key=args.api_key,
        use_direct_transport=not args.use_stdio,
    )
    
    try:
        # Parse guidance
        hints = args.hints.split(",") if args.hints else None
        
        result = await orchestrator.assess(
            target=args.target,
            objective=args.objective,
            hints=hints,
        )
        
        print(f"\n{'='*60}")
        print("ASSESSMENT RESULTS")
        print('='*60)
        
        if result.success:
            print(f"\n🎯 FINDINGS IDENTIFIED!")
            if "__" in (result.flag or ""):  # Vulnerability format
                vuln_parts = result.flag.split("__")
                print(f"🔴 Vulnerability: {vuln_parts[0]}")
                print(f"   Severity: {vuln_parts[1]}")
            else:
                print(f"🚩 Flag: {result.flag}")  # Training mode
        else:
            print(f"\n⚠️ Assessment incomplete after {result.iterations} iterations")
        
        print(f"\n📊 Assessment Metrics:")
        print(f"   Iterations: {result.iterations}")
        print(f"   Duration: {result.duration_seconds:.1f}s")
        if result.findings:
            print(f"   Findings: {result.findings}")
        if result.error:
            print(f"   Error: {result.error}")
        
        return 0 if result.success else 1
        
    finally:
        await mcp_client.disconnect()
        await llm_provider.close()


async def list_tools_command(args: argparse.Namespace) -> int:
    """List available MCP tools."""
    from numasec.client.mcp_client import AsyncMCPClient
    from numasec.client.transports import DirectTransport
    
    async with AsyncMCPClient(DirectTransport()) as client:
        print(f"\n📦 Available Tools ({len(client.tools)}):\n")
        
        for tool in client.tools:
            print(f"  • {tool.name}")
            print(f"    {tool.description[:80]}...")
            print()
    
    return 0


def main() -> int:
    """Main CLI entry point."""
    # Load .env file if exists
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())
    
    parser = argparse.ArgumentParser(
        description="NumaSec - AI Security Copilot for Enterprise Pentesting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Assess web application security
  numasec assess https://target.com --objective "identify OWASP Top 10 vulnerabilities"
  
  # Test specific attack vectors
  numasec assess https://api.target.com -o "test for SQL injection" --hints "focus on login endpoints"
  
  # Training mode (for practice labs)
  numasec assess http://training.example.com -o "identify vulnerabilities"
  
  # List available tools
  numasec tools
"""
    )
    
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # Assess command (enterprise security testing)
    assess_parser = subparsers.add_parser(
        "assess", 
        help="Perform security assessment of target",
        aliases=["test", "scan"]  # User-friendly aliases
    )
    assess_parser.add_argument("target", help="Target URL, IP, or domain")
    assess_parser.add_argument(
        "-o", "--objective", 
        default="Identify security vulnerabilities and misconfigurations",
        help="Assessment objective (e.g., 'test for SQL injection')"
    )
    assess_parser.add_argument(
        "-i", "--iterations", 
        type=int, 
        default=30,
        help="Maximum assessment iterations"
    )
    assess_parser.add_argument(
        "--hints",
        help="Comma-separated testing guidance (e.g., 'focus on API endpoints')"
    )
    assess_parser.add_argument(
        "--api-key",
        default=os.environ.get("DEEPSEEK_API_KEY", ""),
        help="DeepSeek API key (or set DEEPSEEK_API_KEY env variable)"
    )
    assess_parser.add_argument(
        "--model",
        default="deepseek-chat",
        help="LLM model to use (default: deepseek-chat)"
    )
    assess_parser.add_argument(
        "--use-stdio",
        action="store_true",
        help="Use stdio transport (spawns MCP server subprocess)"
    )
    
    # Tools command
    tools_parser = subparsers.add_parser("tools", help="List available tools")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    setup_logging(args.verbose)
    
    # Run command
    if args.command in ["assess", "test", "scan"]:
        if not args.api_key:
            print("Error: Set DEEPSEEK_API_KEY environment variable or use --api-key")
            return 1
        return asyncio.run(assess_command(args))
    elif args.command == "tools":
        return asyncio.run(list_tools_command(args))
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
