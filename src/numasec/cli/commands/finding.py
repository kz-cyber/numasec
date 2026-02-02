"""
Finding Command - Manage security findings.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Optional
from uuid import uuid4

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from numasec.compliance import CVSSCalculator, AttackVector, AttackComplexity
from numasec.compliance import PrivilegesRequired, UserInteraction, Scope, Impact
from numasec.compliance import get_cwe_mapper
from numasec.data.database import get_session, init_database
from numasec.data.models import Severity

console = Console()


class FindingManager:
    """Manage security findings."""

    def __init__(self) -> None:
        self.cvss_calc = CVSSCalculator()
        self.cwe_mapper = get_cwe_mapper()

    async def list_findings(self, engagement_id: str | None = None) -> None:
        """List all findings."""
        from numasec.data.repositories.finding import FindingRepository

        async with get_session() as session:
            repo = FindingRepository(session)
            findings = await repo.list_all(engagement_id=engagement_id)

            if not findings:
                console.print("[dim]No findings recorded yet.[/dim]")
                return

            table = Table(title=f"Findings ({len(findings)})")
            table.add_column("ID", style="dim", max_width=8)
            table.add_column("Title", style="cyan")
            table.add_column("Severity")
            table.add_column("CVSS", justify="right")
            table.add_column("CWE", style="dim")
            table.add_column("Status")

            for finding in findings:
                severity_style = self._get_severity_style(finding.severity)
                table.add_row(
                    finding.id[:8],
                    finding.title[:40] + ("..." if len(finding.title) > 40 else ""),
                    f"[{severity_style}]{finding.severity.value}[/{severity_style}]",
                    str(finding.cvss_score),
                    finding.cwe_id,
                    "Open",
                )

            console.print(table)

    async def show_finding(self, finding_id: str) -> None:
        """Show detailed finding information."""
        from numasec.data.repositories.finding import FindingRepository

        async with get_session() as session:
            repo = FindingRepository(session)
            finding = await repo.get_by_id(finding_id)

            if not finding:
                console.print(f"[red]Finding not found: {finding_id}[/red]")
                return

            severity_style = self._get_severity_style(finding.severity)
            
            console.print(
                Panel(
                    f"[bold]{finding.title}[/bold]\n\n"
                    f"[{severity_style}]● {finding.severity.value.upper()}[/{severity_style}] | "
                    f"CVSS: {finding.cvss_score} | {finding.cwe_id}\n\n"
                    f"[cyan]Description:[/cyan]\n{finding.description}\n\n"
                    f"[cyan]Impact:[/cyan]\n{finding.impact}\n\n"
                    f"[cyan]Remediation:[/cyan]\n{finding.remediation}\n\n"
                    f"[dim]Vector: {finding.cvss_vector}[/dim]",
                    title=f"Finding: {finding.id[:8]}",
                    border_style=severity_style,
                )
            )

    async def add_finding_interactive(self, engagement_id: str | None = None) -> None:
        """Add a finding interactively."""
        from numasec.data.repositories.finding import FindingRepository
        from numasec.data.repositories.engagement import EngagementRepository

        # Get active engagement if not specified
        if not engagement_id:
            async with get_session() as session:
                repo = EngagementRepository(session)
                engagement = await repo.get_active()
                if not engagement:
                    console.print("[red]No active engagement. Run 'numasec init' first.[/red]")
                    return
                engagement_id = engagement.id

        console.print(
            Panel(
                "[bold]Add New Security Finding[/bold]\n\n"
                "Enter the finding details below.",
                title="🔍 New Finding",
                border_style="cyan",
            )
        )

        # Collect information
        title = Prompt.ask("[cyan]Title[/cyan]")

        # Suggest CWE
        console.print("\n[dim]Searching for related CWE...[/dim]")
        cwe_suggestions = self.cwe_mapper.suggest(title)
        if cwe_suggestions:
            console.print("Suggested CWE IDs:")
            for i, cwe in enumerate(cwe_suggestions[:5], 1):
                console.print(f"  {i}. {cwe.id}: {cwe.name}")
            cwe_choice = Prompt.ask(
                "[cyan]CWE ID[/cyan]",
                default=cwe_suggestions[0].id,
            )
        else:
            cwe_choice = Prompt.ask("[cyan]CWE ID[/cyan]", default="CWE-Unknown")

        description = Prompt.ask("[cyan]Description[/cyan]")
        impact = Prompt.ask("[cyan]Impact[/cyan]")
        remediation = Prompt.ask("[cyan]Remediation[/cyan]")

        # CVSS calculation
        console.print("\n[bold]CVSS 3.1 Scoring[/bold]")
        
        av = Prompt.ask(
            "Attack Vector",
            choices=["N", "A", "L", "P"],
            default="N",
        )
        ac = Prompt.ask(
            "Attack Complexity",
            choices=["L", "H"],
            default="L",
        )
        pr = Prompt.ask(
            "Privileges Required",
            choices=["N", "L", "H"],
            default="N",
        )
        ui = Prompt.ask(
            "User Interaction",
            choices=["N", "R"],
            default="N",
        )
        s = Prompt.ask(
            "Scope",
            choices=["U", "C"],
            default="U",
        )
        c = Prompt.ask(
            "Confidentiality Impact",
            choices=["N", "L", "H"],
            default="H",
        )
        i_val = Prompt.ask(
            "Integrity Impact",
            choices=["N", "L", "H"],
            default="H",
        )
        a = Prompt.ask(
            "Availability Impact",
            choices=["N", "L", "H"],
            default="N",
        )

        # Calculate CVSS
        av_map = {"N": AttackVector.NETWORK, "A": AttackVector.ADJACENT, "L": AttackVector.LOCAL, "P": AttackVector.PHYSICAL}
        ac_map = {"L": AttackComplexity.LOW, "H": AttackComplexity.HIGH}
        pr_map = {"N": PrivilegesRequired.NONE, "L": PrivilegesRequired.LOW, "H": PrivilegesRequired.HIGH}
        ui_map = {"N": UserInteraction.NONE, "R": UserInteraction.REQUIRED}
        s_map = {"U": Scope.UNCHANGED, "C": Scope.CHANGED}
        i_map = {"N": Impact.NONE, "L": Impact.LOW, "H": Impact.HIGH}

        result = self.cvss_calc.calculate(
            attack_vector=av_map[av],
            attack_complexity=ac_map[ac],
            privileges_required=pr_map[pr],
            user_interaction=ui_map[ui],
            scope=s_map[s],
            confidentiality=i_map[c],
            integrity=i_map[i_val],
            availability=i_map[a],
        )

        console.print(f"\n[green]CVSS Score: {result.base_score} ({result.severity})[/green]")
        console.print(f"[dim]Vector: {result.vector_string}[/dim]")

        # Confirm save
        if not Confirm.ask("\n[cyan]Save finding?[/cyan]"):
            console.print("[dim]Finding not saved.[/dim]")
            return

        # Save to database
        async with get_session() as session:
            repo = FindingRepository(session)
            
            # Map severity
            severity_map = {
                "Critical": Severity.CRITICAL,
                "High": Severity.HIGH,
                "Medium": Severity.MEDIUM,
                "Low": Severity.LOW,
                "None": Severity.INFORMATIONAL,
            }
            
            finding = await repo.create(
                engagement_id=engagement_id,
                title=title,
                severity=severity_map.get(result.severity, Severity.MEDIUM),
                cvss_score=result.base_score,
                cvss_vector=result.vector_string,
                cwe_id=cwe_choice,
                description=description,
                impact=impact,
                remediation=remediation,
            )

            console.print(
                Panel(
                    f"[green]Finding saved successfully![/green]\n\n"
                    f"ID: {finding.id[:8]}\n"
                    f"Title: {title}\n"
                    f"CVSS: {result.base_score} ({result.severity})",
                    title="✅ Finding Created",
                    border_style="green",
                )
            )

    async def delete_finding(self, finding_id: str) -> None:
        """Delete a finding."""
        from numasec.data.repositories.finding import FindingRepository

        if not Confirm.ask(f"[red]Delete finding {finding_id}?[/red]"):
            console.print("[dim]Deletion cancelled.[/dim]")
            return

        async with get_session() as session:
            repo = FindingRepository(session)
            success = await repo.delete(finding_id)

            if success:
                console.print(f"[green]Finding {finding_id} deleted.[/green]")
            else:
                console.print(f"[red]Finding not found: {finding_id}[/red]")

    def _get_severity_style(self, severity: Severity) -> str:
        """Get Rich style for severity."""
        styles = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "green",
            Severity.INFORMATIONAL: "blue",
        }
        return styles.get(severity, "white")


async def handle_finding(
    action: str,
    finding_id: str | None = None,
    engagement_id: str | None = None,
) -> None:
    """Handle finding command."""
    await init_database()
    manager = FindingManager()

    if action == "list":
        await manager.list_findings(engagement_id)
    elif action == "add":
        await manager.add_finding_interactive(engagement_id)
    elif action == "show" and finding_id:
        await manager.show_finding(finding_id)
    elif action == "delete" and finding_id:
        await manager.delete_finding(finding_id)
    else:
        console.print(
            Panel(
                "[cyan]Available actions:[/cyan]\n\n"
                "  list          - List all findings\n"
                "  add           - Add new finding interactively\n"
                "  show --id X   - Show finding details\n"
                "  delete --id X - Delete a finding",
                title="🔍 Finding Command",
                border_style="cyan",
            )
        )
