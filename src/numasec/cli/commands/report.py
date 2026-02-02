"""
Report Command - Generate penetration test reports.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from numasec.reporting import (
    ReportGenerator,
    ReportConfig,
    ReportFormat,
    ReportTemplate,
    Classification,
    FindingData,
    EvidenceItem,
    VersionEntry,
    ToolUsed,
    is_typst_available,
)
from numasec.data.database import get_session, init_database
from numasec.data.repositories.engagement import EngagementRepository
from numasec.data.repositories.finding import FindingRepository

console = Console()


async def generate_report(
    format: str,
    output: Path | None,
    template: str,
    engagement_id: str | None = None,
) -> None:
    """Generate penetration test report."""
    await init_database()

    # Map format string to enum
    format_map = {
        "pdf": ReportFormat.PDF,
        "docx": ReportFormat.DOCX,
        "md": ReportFormat.MARKDOWN,
        "markdown": ReportFormat.MARKDOWN,
        "html": ReportFormat.HTML,
        "json": ReportFormat.JSON,
    }

    report_format = format_map.get(format.lower(), ReportFormat.PDF)

    # Map template string to enum
    template_map = {
        "ptes": ReportTemplate.PTES,
        "executive": ReportTemplate.EXECUTIVE,
        "technical": ReportTemplate.TECHNICAL,
        "compliance": ReportTemplate.COMPLIANCE,
    }

    report_template = template_map.get(template.lower(), ReportTemplate.PTES)

    # Check Typst for PDF
    if report_format == ReportFormat.PDF and not is_typst_available():
        console.print(
            Panel(
                "[yellow]Typst is not installed.[/yellow]\n\n"
                "PDF generation requires Typst. Install with:\n"
                "  [cyan]brew install typst[/cyan] (macOS)\n"
                "  [cyan]cargo install typst-cli[/cyan] (Rust)\n\n"
                "Or use a different format:\n"
                "  [cyan]numasec report --format md[/cyan]",
                title="⚠️ Typst Not Found",
                border_style="yellow",
            )
        )
        return

    # Get engagement and findings
    async with get_session() as session:
        eng_repo = EngagementRepository(session)
        finding_repo = FindingRepository(session)

        # Get engagement
        if engagement_id:
            engagement = await eng_repo.get_by_id(engagement_id)
        else:
            engagement = await eng_repo.get_active()

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

        # Get findings
        findings = await finding_repo.list_all(engagement_id=engagement.id)

        # Convert to report format
        finding_data = []
        for f in findings:
            finding_data.append(
                FindingData(
                    id=f.id,
                    title=f.title,
                    severity=f.severity.value.capitalize(),
                    cvss_score=f.cvss_score,
                    cvss_vector=f.cvss_vector,
                    cwe_id=f.cwe_id,
                    description=f.description,
                    affected_assets=[],  # Would need to load from evidence
                    evidence=[],
                    impact=f.impact,
                    remediation=f.remediation,
                    references=[],
                )
            )

        # Generate output path if not specified
        if not output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = {
                ReportFormat.PDF: "pdf",
                ReportFormat.DOCX: "docx",
                ReportFormat.MARKDOWN: "md",
                ReportFormat.HTML: "html",
                ReportFormat.JSON: "json",
            }.get(report_format, "pdf")
            output = Path(f"report_{engagement.project_name.lower().replace(' ', '_')}_{timestamp}.{ext}")

        # Create report config
        config = ReportConfig(
            title=f"Penetration Test Report - {engagement.project_name}",
            client_name=engagement.client_name,
            project_name=engagement.project_name,
            version="1.0",
            classification=Classification.CONFIDENTIAL,
            author="NumaSec",
            start_date=engagement.start_date.strftime("%Y-%m-%d") if engagement.start_date else "",
            end_date=engagement.end_date.strftime("%Y-%m-%d") if engagement.end_date else datetime.now().strftime("%Y-%m-%d"),
            format=report_format,
            template=report_template,
            findings=finding_data,
            executive_summary=f"This report presents the findings from the penetration test conducted for {engagement.client_name}.",
            testing_approach="Comprehensive penetration testing following the PTES methodology.",
            version_history=[
                VersionEntry(
                    version="1.0",
                    date=datetime.now().strftime("%Y-%m-%d"),
                    changes="Initial release",
                    author="NumaSec",
                )
            ],
            tools_used=[
                ToolUsed("NumaSec", "AI-powered penetration testing orchestration"),
                ToolUsed("Nmap", "Network discovery and port scanning"),
                ToolUsed("Nuclei", "Vulnerability scanning"),
            ],
        )

        # Generate report
        console.print(
            Panel(
                f"[bold]Generating Report[/bold]\n\n"
                f"📋 Client: {engagement.client_name}\n"
                f"📝 Project: {engagement.project_name}\n"
                f"🔍 Findings: {len(finding_data)}\n"
                f"📄 Format: {report_format.value.upper()}\n"
                f"📁 Output: {output}",
                title="📊 Report Generation",
                border_style="cyan",
            )
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Generating report...", total=None)

            generator = ReportGenerator(config)
            result = generator.generate(output)

            progress.update(task, completed=True)

        if result.success:
            console.print(
                Panel(
                    f"[green]Report generated successfully![/green]\n\n"
                    f"📁 File: {result.output_path}\n"
                    f"⏱️ Time: {result.generation_time:.2f}s",
                    title="✅ Complete",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    f"[red]Report generation failed![/red]\n\n"
                    f"Errors:\n" + "\n".join(f"  • {e}" for e in result.errors),
                    title="❌ Error",
                    border_style="red",
                )
            )


async def list_reports() -> None:
    """List generated reports."""
    # Look for report files in current directory
    report_files = list(Path.cwd().glob("report_*.pdf")) + \
                   list(Path.cwd().glob("report_*.docx")) + \
                   list(Path.cwd().glob("report_*.md")) + \
                   list(Path.cwd().glob("report_*.html")) + \
                   list(Path.cwd().glob("report_*.json"))

    if not report_files:
        console.print("[dim]No reports found in current directory.[/dim]")
        return

    table = Table(title="Generated Reports")
    table.add_column("File", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Modified")

    for f in sorted(report_files, key=lambda x: x.stat().st_mtime, reverse=True):
        size = f.stat().st_size
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.1f} MB"

        modified = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        table.add_row(f.name, size_str, modified)

    console.print(table)
