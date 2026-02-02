"""
Init Command - Create new penetration testing engagement.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from numasec.data.database import get_session, init_database
from numasec.data.models import EngagementStatus, ScopeType
from numasec.data.repositories.engagement import EngagementRepository

console = Console()


def detect_scope_type(target: str) -> ScopeType:
    """Detect the type of scope entry from the target string."""
    import ipaddress
    import re

    target = target.strip()

    # Check for URL
    if target.startswith(("http://", "https://")):
        return ScopeType.URL

    # Check for wildcard domain
    if target.startswith("*."):
        return ScopeType.WILDCARD

    # Check for CIDR
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return ScopeType.CIDR
        except ValueError:
            pass

    # Check for IP address
    try:
        ipaddress.ip_address(target)
        return ScopeType.IP
    except ValueError:
        pass

    # Default to domain
    return ScopeType.DOMAIN


async def init_engagement(
    client: str,
    project: str,
    scope: list[str],
    scope_file: Path | None,
    methodology: str,
    mode: str,
) -> None:
    """Initialize a new penetration testing engagement."""
    # Initialize database
    await init_database()

    # Collect all scope entries
    all_scope = list(scope)

    if scope_file and scope_file.exists():
        with open(scope_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    all_scope.append(line)

    if not all_scope:
        console.print(
            "[yellow]Warning:[/yellow] No scope entries provided. "
            "Add scope with --scope or --scope-file."
        )

    async with get_session() as session:
        repo = EngagementRepository(session)

        # Create engagement
        engagement = await repo.create(
            client_name=client,
            project_name=project,
            methodology=methodology.upper(),
            approval_mode=mode,
            metadata={"scope_count": len(all_scope)},
        )

        # Add scope entries
        for target in all_scope:
            scope_type = detect_scope_type(target)
            await repo.add_scope_entry(
                engagement_id=engagement.id,
                target=target,
                scope_type=scope_type.value,
            )

        # Activate the engagement
        await repo.update_status(engagement.id, EngagementStatus.ACTIVE)

    # Display result
    console.print()
    console.print(
        Panel(
            f"[bold green]Engagement Created Successfully![/bold green]\n\n"
            f"[cyan]ID:[/cyan] {engagement.id}\n"
            f"[cyan]Client:[/cyan] {client}\n"
            f"[cyan]Project:[/cyan] {project}\n"
            f"[cyan]Methodology:[/cyan] {methodology}\n"
            f"[cyan]Approval Mode:[/cyan] {mode}\n"
            f"[cyan]Scope Entries:[/cyan] {len(all_scope)}",
            title="🛡️ New Engagement",
            border_style="green",
        )
    )

    if all_scope:
        table = Table(title="Scope")
        table.add_column("Target", style="cyan")
        table.add_column("Type", style="dim")

        for target in all_scope[:10]:  # Show first 10
            scope_type = detect_scope_type(target)
            table.add_row(target, scope_type.value)

        if len(all_scope) > 10:
            table.add_row(f"... and {len(all_scope) - 10} more", "")

        console.print(table)

    console.print()
    console.print("[dim]Start testing with:[/dim] [cyan]numasec engage[/cyan]")
