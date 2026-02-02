"""
NumaSec - CLI Application

Typer-based command-line interface with Rich UI.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from numasec import __version__

# Create the main Typer app
app = typer.Typer(
    name="numasec",
    help="🛡️ NumaSec - The MCP-Native Pentesting Copilot",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


# ══════════════════════════════════════════════════════════════════════════════
# Callbacks and Global Options
# ══════════════════════════════════════════════════════════════════════════════


def version_callback(value: bool) -> None:
    """Display version and exit."""
    if value:
        console.print(
            Panel(
                f"[bold blue]NumaSec[/bold blue] v{__version__}\n"
                f"[dim]The MCP-Native Pentesting Copilot[/dim]",
                border_style="blue",
            )
        )
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-V",
        help="Enable verbose output.",
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file.",
        envvar="NUMASEC_CONFIG",
    ),
) -> None:
    """
    🛡️ NumaSec - The MCP-Native Pentesting Copilot

    AI-powered penetration testing assistant following industry compliance
    standards (ISO 27001, PTES, OWASP, NIST) with human-in-the-loop safety.

    Get started:

        numasec init --client "ACME Corp" --scope "192.168.1.0/24"
        numasec engage --mode supervised
    """
    # Store global options in context
    pass


# ══════════════════════════════════════════════════════════════════════════════
# Commands
# ══════════════════════════════════════════════════════════════════════════════


@app.command()
def version() -> None:
    """Show version information."""
    console.print(
        Panel(
            f"[bold blue]NumaSec[/bold blue] v{__version__}\n\n"
            f"[dim]The MCP-Native Pentesting Copilot[/dim]\n\n"
            f"• Python 3.11+\n"
            f"• MCP Protocol\n"
            f"• PTES Methodology\n"
            f"• CVSS 3.1 Scoring",
            title="Version Info",
            border_style="blue",
        )
    )


@app.command()
def init(
    client: str = typer.Option(
        ...,
        "--client",
        "-c",
        help="Client name for the engagement.",
    ),
    project: str = typer.Option(
        None,
        "--project",
        "-p",
        help="Project name (defaults to 'Penetration Test').",
    ),
    scope: list[str] = typer.Option(
        None,
        "--scope",
        "-s",
        help="Target scope (IP, CIDR, domain, or URL). Can be repeated.",
    ),
    scope_file: Optional[Path] = typer.Option(
        None,
        "--scope-file",
        "-f",
        help="File containing scope targets (one per line).",
    ),
    methodology: str = typer.Option(
        "PTES",
        "--methodology",
        "-m",
        help="Testing methodology (PTES, OWASP, NIST).",
    ),
    mode: str = typer.Option(
        "supervised",
        "--mode",
        help="Approval mode: supervised, semi_auto, or autonomous.",
    ),
) -> None:
    """
    Initialize a new penetration testing engagement.

    Example:
        numasec init --client "ACME Corp" --scope "10.0.0.0/24"
    """
    from numasec.cli.commands.init import init_engagement

    asyncio.run(
        init_engagement(
            client=client,
            project=project or "Penetration Test",
            scope=list(scope) if scope else [],
            scope_file=scope_file,
            methodology=methodology,
            mode=mode,
        )
    )


@app.command()
def engage(
    mode: str = typer.Option(
        None,
        "--mode",
        "-m",
        help="Override approval mode for this session.",
    ),
    engagement_id: Optional[str] = typer.Option(
        None,
        "--engagement",
        "-e",
        help="Engagement ID to continue (uses active if not specified).",
    ),
) -> None:
    """
    Start interactive pentesting session with AI assistance.

    Example:
        numasec engage --mode supervised
    """
    from numasec.cli.commands.engage import engage_session

    asyncio.run(engage_session(engagement_id=engagement_id, mode=mode))


@app.command()
def agent(
    target: str = typer.Argument(
        ...,
        help="Target URL, IP, or challenge description.",
    ),
    objective: str = typer.Option(
        "",
        "--objective",
        "-o",
        help="What to achieve (e.g., 'find the flag', 'enumerate vulnerabilities').",
    ),
    mode: str = typer.Option(
        "supervised",
        "--mode",
        "-m",
        help="Approval mode: supervised, semi_auto, autonomous.",
    ),
    max_iterations: int = typer.Option(
        100,  # Increased from 50 for blind injection attacks
        "--max-iterations",
        "-i",
        help="Maximum agent iterations.",
    ),
    verbose: bool = typer.Option(
        True,
        "--verbose/--quiet",
        "-v/-q",
        help="Show verbose output.",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        "-d",
        help="Show full debug output (code, responses, reasoning).",
    ),
) -> None:
    """
    🧠 Run NumaSec Ultimate AI Agent.

    This launches the autonomous pentesting agent that will:
    - Analyze the target using cognitive reasoning
    - Suggest and execute security tools
    - Learn patterns using KnowledgeStore with vector search
    - Explore actions using UCB1 algorithm
    - Report findings with CVSS scores

    Examples:
        numasec agent http://target.com
        numasec agent "http://localhost:3000" --objective "test SQL injection"
        numasec agent 192.168.1.1 --mode autonomous -i 100
        numasec agent http://target.com --debug  # Show all details
    """
    from numasec.core.approval import ApprovalMode
    from numasec.cli.commands.engage import run_agent

    # Parse mode
    try:
        approval_mode = ApprovalMode(mode.lower())
    except ValueError:
        console.print(f"[yellow]Invalid mode: {mode}, using supervised[/yellow]")
        approval_mode = ApprovalMode.SUPERVISED

    result = asyncio.run(
        run_agent(
            target=target,
            objective=objective,
            mode=approval_mode,
            max_iterations=max_iterations,
            verbose=verbose,
            debug=debug,
        )
    )

    # Exit code based on result
    if result.get("success"):
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


@app.command()
def status() -> None:
    """Show current engagement status."""
    console.print(
        Panel(
            "[dim]No active engagement found.[/dim]\n\n"
            "Start a new engagement with:\n"
            "  [cyan]numasec init --client 'Client Name' --scope 'target'[/cyan]",
            title="📊 Engagement Status",
            border_style="dim",
        )
    )


@app.command("mcp-server")
def mcp_server(
    stdio: bool = typer.Option(
        True,
        "--stdio/--no-stdio",
        help="Use stdio transport (default for Claude Desktop).",
    ),
    port: Optional[int] = typer.Option(
        None,
        "--port",
        "-p",
        help="Port for SSE transport (alternative to stdio).",
    ),
) -> None:
    """
    Start the MCP server for AI integration.

    This server implements the Model Context Protocol (MCP),
    allowing integration with Claude Desktop, Claude Code, and other MCP clients.

    Example:
        numasec mcp-server --stdio
    """
    from numasec.mcp.server import run_server

    asyncio.run(run_server(stdio=stdio, port=port))


@app.command()
def report(
    format: str = typer.Option(
        "pdf",
        "--format",
        "-f",
        help="Output format: pdf, docx, md, html.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path.",
    ),
    template: str = typer.Option(
        "ptes",
        "--template",
        "-t",
        help="Report template: ptes, owasp, executive, technical.",
    ),
    engagement_id: Optional[str] = typer.Option(
        None,
        "--engagement",
        "-e",
        help="Engagement ID (uses active if not specified).",
    ),
) -> None:
    """
    Generate penetration test report.

    Example:
        numasec report --format pdf --output report.pdf
    """
    from numasec.cli.commands.report import generate_report

    asyncio.run(generate_report(format=format, output=output, template=template, engagement_id=engagement_id))


@app.command()
def finding(
    action: str = typer.Argument(
        "list",
        help="Action: list, add, show, edit, delete.",
    ),
    finding_id: Optional[str] = typer.Option(
        None,
        "--id",
        "-i",
        help="Finding ID for show/edit/delete actions.",
    ),
) -> None:
    """
    Manage security findings.

    Example:
        numasec finding list
        numasec finding add --interactive
    """
    from numasec.cli.commands.finding import handle_finding

    asyncio.run(handle_finding(action=action, finding_id=finding_id))


@app.command()
def knowledge(
    action: str = typer.Argument(
        "search",
        help="Action: search, add, import, list.",
    ),
    query: Optional[str] = typer.Option(
        None,
        "--query",
        "-q",
        help="Search query.",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        "-C",
        help="Payload category.",
    ),
    payload: Optional[str] = typer.Option(
        None,
        "--payload",
        "-p",
        help="Payload to add.",
    ),
) -> None:
    """
    Manage knowledge base (payloads, techniques, writeups).

    Example:
        numasec knowledge search --query "sql injection bypass"
        numasec knowledge list
    """
    from numasec.cli.commands.knowledge import handle_knowledge

    asyncio.run(handle_knowledge(action=action, query=query, category=category, payload=payload))


@app.command()
def config(
    action: str = typer.Argument(
        "show",
        help="Action: show, set, init.",
    ),
    key: Optional[str] = typer.Option(
        None,
        "--key",
        "-k",
        help="Configuration key for get/set.",
    ),
    value: Optional[str] = typer.Option(
        None,
        "--value",
        "-V",
        help="Configuration value for set.",
    ),
) -> None:
    """
    Manage configuration.

    Example:
        numasec config show
        numasec config set --key llm.primary_provider --value claude
    """
    if action == "show":
        from numasec.config.settings import get_settings

        settings = get_settings()

        table = Table(title="Current Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")

        # Display key settings
        table.add_row("LLM Provider", settings.llm.primary_provider.value)
        table.add_row("Approval Mode", settings.approval.default_mode.value)
        table.add_row("Database", str(settings.database.path))
        table.add_row("Cache Enabled", str(settings.cache.enabled))
        table.add_row("Report Template", settings.reporting.default_template.value)

        console.print(table)
    elif action == "init":
        from numasec.config.settings import create_default_config

        path = create_default_config()
        console.print(f"[green]Created default config at:[/green] {path}")
    else:
        console.print(f"[yellow]Config action '{action}' not yet implemented.[/yellow]")


# ══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════════════════


def main_cli() -> None:
    """Main entry point for the CLI."""
    app()


if __name__ == "__main__":
    main_cli()
