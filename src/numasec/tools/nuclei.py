"""
NumaSec - Nuclei Tool Wrapper

ProjectDiscovery Nuclei vulnerability scanner with JSON output parsing.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from numasec.tools.base import (
    BaseTool,
    ToolCategory,
    ToolResult,
    ToolRisk,
    ToolStatus,
    Vulnerability,
)
from numasec.tools.executor import get_executor
from numasec.tools.registry import register_tool


# ══════════════════════════════════════════════════════════════════════════════
# Output Models
# ══════════════════════════════════════════════════════════════════════════════


class NucleiMatch(BaseModel):
    """Single nuclei template match."""

    template_id: str
    template_name: str = ""
    severity: str = "info"
    type: str = ""
    host: str = ""
    matched_at: str = ""
    extracted_results: list[str] = Field(default_factory=list)
    ip: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    matcher_name: str = ""
    curl_command: str = ""
    description: str = ""
    tags: list[str] = Field(default_factory=list)

    def to_vulnerability(self) -> Vulnerability:
        """Convert to generic Vulnerability."""
        return Vulnerability(
            id=self.template_id,
            name=self.template_name or self.template_id,
            severity=self.severity,
            description=self.description,
            url=self.matched_at,
            template=self.template_id,
            matched=self.matched_at,
        )


class NucleiResult(BaseModel):
    """Complete nuclei scan result."""

    matches: list[NucleiMatch] = Field(default_factory=list)
    targets_scanned: int = 0
    templates_used: int = 0
    duration_seconds: float = 0

    @property
    def total_matches(self) -> int:
        return len(self.matches)

    @property
    def by_severity(self) -> dict[str, int]:
        """Count matches by severity."""
        counts: dict[str, int] = {}
        for match in self.matches:
            counts[match.severity] = counts.get(match.severity, 0) + 1
        return counts

    @property
    def critical_count(self) -> int:
        return sum(1 for m in self.matches if m.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for m in self.matches if m.severity == "high")


# ══════════════════════════════════════════════════════════════════════════════
# Nuclei Tool
# ══════════════════════════════════════════════════════════════════════════════


@register_tool
class NucleiTool(BaseTool[NucleiResult]):
    """
    Nuclei vulnerability scanner wrapper.

    Supports:
    - Template-based scanning
    - Severity filtering
    - Tag-based filtering
    - JSON output parsing
    """

    name = "nuclei"
    description = "Fast template-based vulnerability scanner"
    category = ToolCategory.WEB_APPLICATION
    risk = ToolRisk.MEDIUM
    command = "nuclei"

    async def execute(
        self,
        targets: list[str],
        templates: list[str] | None = None,
        severity: list[str] | None = None,
        tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        rate_limit: int = 150,
        timeout: int = 600,
        extra_args: list[str] | None = None,
    ) -> ToolResult[NucleiResult]:
        """
        Execute nuclei scan.

        Args:
            targets: Target URLs or hosts
            templates: Specific templates to run
            severity: Filter by severity (critical, high, medium, low, info)
            tags: Filter by tags
            exclude_tags: Tags to exclude
            rate_limit: Requests per second
            timeout: Scan timeout
            extra_args: Additional nuclei arguments

        Returns:
            ToolResult with NucleiResult data
        """
        start_time = datetime.now(timezone.utc)

        # Build command
        cmd = ["nuclei", "-json", "-silent"]

        # Add targets
        for target in targets:
            cmd.extend(["-u", target])

        # Add templates
        if templates:
            for t in templates:
                cmd.extend(["-t", t])

        # Add severity filter
        if severity:
            cmd.extend(["-s", ",".join(severity)])

        # Add tags
        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        if exclude_tags:
            cmd.extend(["-etags", ",".join(exclude_tags)])

        # Rate limit
        cmd.extend(["-rl", str(rate_limit)])

        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        # Execute
        executor = get_executor()
        result = await executor.execute(cmd, timeout=timeout)

        completed_at = datetime.now(timezone.utc)
        duration_ms = (completed_at - start_time).total_seconds() * 1000

        if result.exit_code not in [0, 1]:  # nuclei returns 1 when findings exist
            return ToolResult[NucleiResult](
                tool_name=self.name,
                status=result.status,
                data=None,
                raw_output=result.stderr or result.stdout,
                error=result.stderr,
                command=" ".join(cmd),
                exit_code=result.exit_code,
                started_at=start_time,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

        # Parse JSON output
        try:
            nuclei_result = self.parse_output(result.stdout)
            nuclei_result.targets_scanned = len(targets)
            nuclei_result.duration_seconds = duration_ms / 1000
        except Exception as e:
            return ToolResult[NucleiResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                raw_output=result.stdout,
                error=f"Failed to parse nuclei output: {e}",
                command=" ".join(cmd),
                exit_code=result.exit_code,
                started_at=start_time,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

        return ToolResult[NucleiResult](
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            data=nuclei_result,
            raw_output=result.stdout,
            command=" ".join(cmd),
            exit_code=result.exit_code,
            started_at=start_time,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )

    def parse_output(self, raw_output: str) -> NucleiResult:
        """Parse nuclei JSONL output."""
        result = NucleiResult()

        for line in raw_output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)
                match = NucleiMatch(
                    template_id=data.get("template-id", data.get("templateID", "")),
                    template_name=data.get("info", {}).get("name", ""),
                    severity=data.get("info", {}).get("severity", "info"),
                    type=data.get("type", ""),
                    host=data.get("host", ""),
                    matched_at=data.get("matched-at", data.get("matched", "")),
                    extracted_results=data.get("extracted-results", []),
                    ip=data.get("ip", ""),
                    matcher_name=data.get("matcher-name", ""),
                    curl_command=data.get("curl-command", ""),
                    description=data.get("info", {}).get("description", ""),
                    tags=data.get("info", {}).get("tags", []),
                )
                result.matches.append(match)
            except json.JSONDecodeError:
                continue

        return result

    @classmethod
    def get_schema(cls) -> dict[str, Any]:
        """Get JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Target URLs or hosts",
                },
                "templates": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific template paths or IDs",
                },
                "severity": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "description": "Filter by severity levels",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by template tags",
                },
                "rate_limit": {
                    "type": "integer",
                    "default": 150,
                    "description": "Requests per second",
                },
            },
            "required": ["targets"],
        }
