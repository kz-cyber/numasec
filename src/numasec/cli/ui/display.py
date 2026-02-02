"""
NumaSec - CLI UI Display Components

Rich-based display components for consistent UI.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

console = Console()


# ══════════════════════════════════════════════════════════════════════════════
# Severity Styles
# ══════════════════════════════════════════════════════════════════════════════


SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "informational": "blue",
    "info": "blue",
}


def get_severity_style(severity: str) -> str:
    """Get Rich style for severity."""
    return SEVERITY_STYLES.get(severity.lower(), "white")


def severity_badge(severity: str) -> str:
    """Create severity badge text."""
    style = get_severity_style(severity)
    return f"[{style}]● {severity.upper()}[/{style}]"


# ══════════════════════════════════════════════════════════════════════════════
# Finding Display
# ══════════════════════════════════════════════════════════════════════════════


def finding_card(
    title: str,
    severity: str,
    cvss_score: float,
    cwe_id: str,
    description: str,
    finding_id: str | None = None,
) -> Panel:
    """Create a finding card panel."""
    style = get_severity_style(severity)
    
    header = f"[bold]{title}[/bold]\n\n"
    header += f"{severity_badge(severity)} | CVSS: {cvss_score} | {cwe_id}\n\n"
    
    content = header + description[:200]
    if len(description) > 200:
        content += "..."
    
    return Panel(
        content,
        title=f"Finding: {finding_id[:8] if finding_id else 'New'}",
        border_style=style,
    )


def finding_table(findings: list[dict[str, Any]]) -> Table:
    """Create a findings summary table."""
    table = Table(title=f"Findings ({len(findings)})")
    table.add_column("#", style="dim", width=3)
    table.add_column("Title", style="cyan", max_width=40)
    table.add_column("Severity")
    table.add_column("CVSS", justify="right")
    table.add_column("CWE", style="dim")

    for i, f in enumerate(findings, 1):
        severity = f.get("severity", "unknown")
        style = get_severity_style(severity)
        
        title = f.get("title", "Untitled")
        if len(title) > 37:
            title = title[:34] + "..."
        
        table.add_row(
            str(i),
            title,
            f"[{style}]{severity}[/{style}]",
            str(f.get("cvss_score", 0.0)),
            f.get("cwe_id", ""),
        )

    return table


# ══════════════════════════════════════════════════════════════════════════════
# Phase Display
# ══════════════════════════════════════════════════════════════════════════════


def phase_indicator(
    current_phase: str,
    all_phases: list[str],
    completed_phases: list[str] | None = None,
) -> Panel:
    """Create a phase progress indicator."""
    completed = completed_phases or []
    
    lines = []
    for i, phase in enumerate(all_phases, 1):
        if phase == current_phase:
            status = "🔵"
            style = "bold cyan"
        elif phase in completed:
            status = "✅"
            style = "green"
        else:
            status = "⬜"
            style = "dim"
        
        lines.append(f"[{style}]{status} {i}. {phase}[/{style}]")
    
    return Panel(
        "\n".join(lines),
        title="📍 PTES Phases",
        border_style="blue",
    )


def phase_details(
    name: str,
    description: str,
    objectives: list[str],
    tools: list[str],
    progress: float = 0.0,
) -> Panel:
    """Create detailed phase panel."""
    content = f"[bold]{name}[/bold]\n\n"
    content += f"{description}\n\n"
    content += "[cyan]Objectives:[/cyan]\n"
    content += "\n".join(f"  • {obj}" for obj in objectives[:5])
    
    if tools:
        content += f"\n\n[cyan]Tools:[/cyan] {', '.join(tools)}"
    
    content += f"\n\n[dim]Progress: {progress:.1f}%[/dim]"
    
    return Panel(content, title="Phase Details", border_style="blue")


# ══════════════════════════════════════════════════════════════════════════════
# Scope Display
# ══════════════════════════════════════════════════════════════════════════════


def scope_tree(
    scope_entries: list[dict[str, Any]],
    title: str = "Scope",
) -> Tree:
    """Create a scope tree display."""
    tree = Tree(f"[bold cyan]📋 {title}[/bold cyan]")
    
    # Group by type
    by_type: dict[str, list[str]] = {}
    for entry in scope_entries:
        entry_type = entry.get("type", "other")
        target = entry.get("target", "")
        if entry_type not in by_type:
            by_type[entry_type] = []
        by_type[entry_type].append(target)
    
    type_icons = {
        "ip": "💻",
        "cidr": "🌐",
        "domain": "🔗",
        "url": "📎",
        "wildcard": "✱",
    }
    
    for entry_type, targets in by_type.items():
        icon = type_icons.get(entry_type, "📌")
        type_branch = tree.add(f"{icon} {entry_type.upper()} ({len(targets)})")
        for target in targets[:10]:
            type_branch.add(f"[cyan]{target}[/cyan]")
        if len(targets) > 10:
            type_branch.add(f"[dim]... and {len(targets) - 10} more[/dim]")
    
    return tree


def scope_table(scope_entries: list[dict[str, Any]]) -> Table:
    """Create a scope table."""
    table = Table(title="Scope Entries")
    table.add_column("Type", style="dim")
    table.add_column("Target", style="cyan")
    table.add_column("Status")

    for entry in scope_entries:
        table.add_row(
            entry.get("type", "").upper(),
            entry.get("target", ""),
            "[green]Active[/green]",
        )

    return table


# ══════════════════════════════════════════════════════════════════════════════
# Status Display
# ══════════════════════════════════════════════════════════════════════════════


def engagement_status(
    client: str,
    project: str,
    status: str,
    phase: str,
    findings_count: int,
    scope_count: int,
    start_date: datetime | None = None,
) -> Panel:
    """Create engagement status panel."""
    status_icon = {
        "active": "🟢",
        "paused": "🟡",
        "complete": "✅",
        "draft": "⬜",
    }.get(status.lower(), "⬜")
    
    content = f"[bold]{project}[/bold]\n"
    content += f"Client: {client}\n\n"
    content += f"Status: {status_icon} {status}\n"
    content += f"Phase: {phase}\n"
    content += f"Findings: {findings_count}\n"
    content += f"Scope Targets: {scope_count}\n"
    
    if start_date:
        content += f"\nStarted: {start_date.strftime('%Y-%m-%d')}"
    
    return Panel(content, title="📊 Engagement Status", border_style="blue")


# ══════════════════════════════════════════════════════════════════════════════
# Tool Display
# ══════════════════════════════════════════════════════════════════════════════


def tool_output(
    tool_name: str,
    command: str,
    output: str,
    success: bool = True,
    duration: float = 0.0,
) -> Panel:
    """Create tool output panel."""
    status = "[green]Success[/green]" if success else "[red]Failed[/red]"
    
    header = f"[dim]$ {command}[/dim]\n\n"
    
    # Truncate long output
    if len(output) > 1000:
        display_output = output[:500] + "\n\n[dim]... output truncated ...[/dim]\n\n" + output[-500:]
    else:
        display_output = output
    
    footer = f"\n\n[dim]{status} in {duration:.2f}s[/dim]"
    
    return Panel(
        header + display_output + footer,
        title=f"🔧 {tool_name}",
        border_style="green" if success else "red",
    )


def tool_approval(
    tool_name: str,
    risk_level: str,
    command: str,
    target: str,
) -> Panel:
    """Create tool approval request panel."""
    risk_style = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red",
    }.get(risk_level.lower(), "white")
    
    content = f"[bold]Tool:[/bold] {tool_name}\n"
    content += f"[bold]Risk:[/bold] [{risk_style}]{risk_level.upper()}[/{risk_style}]\n"
    content += f"[bold]Target:[/bold] {target}\n"
    content += f"[bold]Command:[/bold] [dim]{command}[/dim]\n\n"
    content += "[yellow]Do you want to proceed?[/yellow]"
    
    return Panel(
        content,
        title="🔐 Approval Required",
        border_style=risk_style,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Progress Display
# ══════════════════════════════════════════════════════════════════════════════


def progress_bar(
    current: int,
    total: int,
    width: int = 30,
    label: str = "",
) -> str:
    """Create a simple progress bar string."""
    if total == 0:
        percentage = 100
    else:
        percentage = int((current / total) * 100)
    
    filled = int((percentage / 100) * width)
    empty = width - filled
    
    bar = "█" * filled + "░" * empty
    
    if label:
        return f"{label}: [{bar}] {percentage}%"
    return f"[{bar}] {percentage}%"


# ══════════════════════════════════════════════════════════════════════════════
# Message Display
# ══════════════════════════════════════════════════════════════════════════════


def success_message(message: str, title: str = "Success") -> Panel:
    """Create success message panel."""
    return Panel(
        f"[green]{message}[/green]",
        title=f"✅ {title}",
        border_style="green",
    )


def error_message(message: str, title: str = "Error") -> Panel:
    """Create error message panel."""
    return Panel(
        f"[red]{message}[/red]",
        title=f"❌ {title}",
        border_style="red",
    )


def warning_message(message: str, title: str = "Warning") -> Panel:
    """Create warning message panel."""
    return Panel(
        f"[yellow]{message}[/yellow]",
        title=f"⚠️ {title}",
        border_style="yellow",
    )


def info_message(message: str, title: str = "Info") -> Panel:
    """Create info message panel."""
    return Panel(
        f"[blue]{message}[/blue]",
        title=f"ℹ️ {title}",
        border_style="blue",
    )
