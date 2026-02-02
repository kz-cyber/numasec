"""
NumaSec - Subfinder Tool Wrapper

Subdomain discovery with JSON output parsing.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from numasec.tools.base import (
    BaseTool,
    Host,
    ToolCategory,
    ToolResult,
    ToolRisk,
    ToolStatus,
)
from numasec.tools.executor import get_executor
from numasec.tools.registry import register_tool


# ══════════════════════════════════════════════════════════════════════════════
# Output Models
# ══════════════════════════════════════════════════════════════════════════════


class Subdomain(BaseModel):
    """Discovered subdomain."""

    host: str
    source: str = ""
    ip: str = ""

    def to_host(self) -> Host:
        """Convert to generic Host."""
        return Host(
            ip=self.ip,
            hostname=self.host,
            state="up",
        )


class SubfinderResult(BaseModel):
    """Complete Subfinder scan result."""

    domain: str = ""
    subdomains: list[Subdomain] = Field(default_factory=list)
    sources_used: list[str] = Field(default_factory=list)
    duration_seconds: float = 0

    @property
    def total_subdomains(self) -> int:
        return len(self.subdomains)

    @property
    def unique_hosts(self) -> list[str]:
        """Get unique subdomain hostnames."""
        return list(set(s.host for s in self.subdomains))

    @property
    def by_source(self) -> dict[str, list[str]]:
        """Group subdomains by source."""
        result: dict[str, list[str]] = {}
        for sub in self.subdomains:
            if sub.source not in result:
                result[sub.source] = []
            result[sub.source].append(sub.host)
        return result


# ══════════════════════════════════════════════════════════════════════════════
# Subfinder Tool
# ══════════════════════════════════════════════════════════════════════════════


@register_tool
class SubfinderTool(BaseTool[SubfinderResult]):
    """
    Subfinder subdomain discovery wrapper.

    Supports:
    - Multiple data sources
    - Rate limiting
    - Recursive enumeration
    """

    name = "subfinder"
    description = "Fast passive subdomain enumeration"
    category = ToolCategory.RECONNAISSANCE
    risk = ToolRisk.LOW  # Passive reconnaissance
    command = "subfinder"

    async def execute(
        self,
        domain: str,
        recursive: bool = False,
        sources: list[str] | None = None,
        exclude_sources: list[str] | None = None,
        all_sources: bool = False,
        rate_limit: int = 0,
        timeout: int = 300,
        extra_args: list[str] | None = None,
    ) -> ToolResult[SubfinderResult]:
        """
        Execute Subfinder subdomain discovery.

        Args:
            domain: Target domain
            recursive: Enable recursive enumeration
            sources: Specific sources to use
            exclude_sources: Sources to exclude
            all_sources: Use all available sources
            rate_limit: Rate limit per source
            timeout: Scan timeout
            extra_args: Additional Subfinder arguments

        Returns:
            ToolResult with SubfinderResult data
        """
        start_time = datetime.now(timezone.utc)

        # Build command
        cmd = ["subfinder", "-d", domain, "-json", "-silent"]

        if recursive:
            cmd.append("-recursive")

        if sources:
            cmd.extend(["-sources", ",".join(sources)])

        if exclude_sources:
            cmd.extend(["-exclude-sources", ",".join(exclude_sources)])

        if all_sources:
            cmd.append("-all")

        if rate_limit > 0:
            cmd.extend(["-rate-limit", str(rate_limit)])

        if extra_args:
            cmd.extend(extra_args)

        # Execute
        executor = get_executor()
        result = await executor.execute(cmd, timeout=timeout)

        completed_at = datetime.now(timezone.utc)
        duration_ms = (completed_at - start_time).total_seconds() * 1000

        if result.exit_code != 0 and not result.stdout:
            return ToolResult[SubfinderResult](
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

        # Parse output
        try:
            subfinder_result = self.parse_output(result.stdout, domain)
            subfinder_result.duration_seconds = duration_ms / 1000
        except Exception as e:
            return ToolResult[SubfinderResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                raw_output=result.stdout,
                error=f"Failed to parse Subfinder output: {e}",
                command=" ".join(cmd),
                exit_code=result.exit_code,
                started_at=start_time,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

        return ToolResult[SubfinderResult](
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            data=subfinder_result,
            raw_output=result.stdout,
            command=" ".join(cmd),
            exit_code=result.exit_code,
            started_at=start_time,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )

    def parse_output(self, raw_output: str, domain: str) -> SubfinderResult:
        """Parse Subfinder JSONL output."""
        result = SubfinderResult(domain=domain)
        sources_set: set[str] = set()

        for line in raw_output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)
                subdomain = Subdomain(
                    host=data.get("host", ""),
                    source=data.get("source", ""),
                    ip=data.get("ip", ""),
                )
                result.subdomains.append(subdomain)
                
                if subdomain.source:
                    sources_set.add(subdomain.source)

            except json.JSONDecodeError:
                # Plain text output (one subdomain per line)
                subdomain = Subdomain(host=line.strip())
                result.subdomains.append(subdomain)

        result.sources_used = list(sources_set)
        return result

    @classmethod
    def get_schema(cls) -> dict[str, Any]:
        """Get JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain",
                },
                "recursive": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable recursive enumeration",
                },
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific sources to use",
                },
                "all_sources": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use all available sources",
                },
            },
            "required": ["domain"],
        }
