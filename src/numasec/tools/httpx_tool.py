"""
NumaSec - httpx Tool Wrapper

ProjectDiscovery httpx HTTP probe with JSON output parsing.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from numasec.tools.base import (
    BaseTool,
    HTTPResponse,
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


class HttpxProbe(BaseModel):
    """Single httpx probe result."""

    url: str
    input: str = ""
    scheme: str = ""
    host: str = ""
    port: str = ""
    path: str = ""
    status_code: int = 0
    content_length: int = 0
    content_type: str = ""
    title: str = ""
    webserver: str = ""
    tech: list[str] = Field(default_factory=list)
    method: str = "GET"
    final_url: str = ""
    chain_status_codes: list[int] = Field(default_factory=list)
    a: list[str] = Field(default_factory=list)  # A records
    cname: list[str] = Field(default_factory=list)  # CNAME records
    cdn: bool = False
    cdn_name: str = ""
    tls_host: str = ""
    tls_version: str = ""
    response_time: str = ""
    failed: bool = False
    error: str = ""

    def to_http_response(self) -> HTTPResponse:
        """Convert to generic HTTPResponse."""
        return HTTPResponse(
            url=self.url,
            status_code=self.status_code,
            content_length=self.content_length,
            content_type=self.content_type,
            headers={},
            body="",
        )


class HttpxResult(BaseModel):
    """Complete httpx scan result."""

    probes: list[HttpxProbe] = Field(default_factory=list)
    total_probed: int = 0
    alive_count: int = 0
    failed_count: int = 0
    duration_seconds: float = 0

    @property
    def alive_hosts(self) -> list[HttpxProbe]:
        """Get only alive probes."""
        return [p for p in self.probes if not p.failed]

    @property
    def by_status_code(self) -> dict[int, list[HttpxProbe]]:
        """Group probes by status code."""
        result: dict[int, list[HttpxProbe]] = {}
        for probe in self.probes:
            if probe.status_code not in result:
                result[probe.status_code] = []
            result[probe.status_code].append(probe)
        return result

    @property
    def technologies(self) -> set[str]:
        """Get all detected technologies."""
        techs: set[str] = set()
        for probe in self.probes:
            techs.update(probe.tech)
        return techs


# ══════════════════════════════════════════════════════════════════════════════
# httpx Tool
# ══════════════════════════════════════════════════════════════════════════════


@register_tool
class HttpxTool(BaseTool[HttpxResult]):
    """
    httpx HTTP probe wrapper.

    Supports:
    - HTTP probing with technology detection
    - Title extraction
    - Status code filtering
    - TLS information
    """

    name = "httpx"
    description = "Fast HTTP probe and technology fingerprinting"
    category = ToolCategory.RECONNAISSANCE
    risk = ToolRisk.LOW
    command = "httpx"

    async def execute(
        self,
        targets: list[str],
        follow_redirects: bool = True,
        tech_detect: bool = True,
        title: bool = True,
        status_code: bool = True,
        content_length: bool = True,
        web_server: bool = True,
        threads: int = 50,
        timeout: int = 300,
        match_codes: list[int] | None = None,
        filter_codes: list[int] | None = None,
        extra_args: list[str] | None = None,
    ) -> ToolResult[HttpxResult]:
        """
        Execute httpx probe.

        Args:
            targets: Target URLs or hosts
            follow_redirects: Follow HTTP redirects
            tech_detect: Detect technologies
            title: Extract page titles
            status_code: Include status codes
            content_length: Include content length
            web_server: Detect web server
            threads: Concurrent threads
            timeout: Probe timeout
            match_codes: Only show these status codes
            filter_codes: Filter out these status codes
            extra_args: Additional httpx arguments

        Returns:
            ToolResult with HttpxResult data
        """
        start_time = datetime.now(timezone.utc)

        # Build command
        cmd = ["httpx", "-json", "-silent"]

        # Options
        if follow_redirects:
            cmd.append("-follow-redirects")

        if tech_detect:
            cmd.append("-tech-detect")

        if title:
            cmd.append("-title")

        if status_code:
            cmd.append("-status-code")

        if content_length:
            cmd.append("-content-length")

        if web_server:
            cmd.append("-web-server")

        # Threads
        cmd.extend(["-threads", str(threads)])

        # Match/filter codes
        if match_codes:
            cmd.extend(["-mc", ",".join(str(c) for c in match_codes)])

        if filter_codes:
            cmd.extend(["-fc", ",".join(str(c) for c in filter_codes)])

        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        # Validate targets
        if not targets:
            return ToolResult[HttpxResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                error="No targets provided",
                command=" ".join(cmd),
                exit_code=-1,
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
                duration_ms=0,
            )

        # Execute with targets as stdin (httpx expects one target per line)
        executor = get_executor()
        stdin_input = "\n".join(targets)
        result = await executor.execute(cmd, timeout=timeout, input_data=stdin_input)

        completed_at = datetime.now(timezone.utc)
        duration_ms = (completed_at - start_time).total_seconds() * 1000

        if result.exit_code != 0:
            return ToolResult[HttpxResult](
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
            httpx_result = self.parse_output(result.stdout)
            httpx_result.total_probed = len(targets)
            httpx_result.duration_seconds = duration_ms / 1000
        except Exception as e:
            return ToolResult[HttpxResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                raw_output=result.stdout,
                error=f"Failed to parse httpx output: {e}",
                command=" ".join(cmd),
                exit_code=result.exit_code,
                started_at=start_time,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

        return ToolResult[HttpxResult](
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            data=httpx_result,
            raw_output=result.stdout,
            command=" ".join(cmd),
            exit_code=result.exit_code,
            started_at=start_time,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )

    def parse_output(self, raw_output: str) -> HttpxResult:
        """Parse httpx JSONL output."""
        result = HttpxResult()

        for line in raw_output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)
                probe = HttpxProbe(
                    url=data.get("url", ""),
                    input=data.get("input", ""),
                    scheme=data.get("scheme", ""),
                    host=data.get("host", ""),
                    port=str(data.get("port", "")),
                    path=data.get("path", ""),
                    status_code=data.get("status_code", data.get("status-code", 0)),
                    content_length=data.get("content_length", data.get("content-length", 0)),
                    content_type=data.get("content_type", data.get("content-type", "")),
                    title=data.get("title", ""),
                    webserver=data.get("webserver", ""),
                    tech=data.get("tech", []),
                    method=data.get("method", "GET"),
                    final_url=data.get("final_url", data.get("final-url", "")),
                    chain_status_codes=data.get("chain_status_codes", []),
                    a=data.get("a", []),
                    cname=data.get("cname", []),
                    cdn=data.get("cdn", False),
                    cdn_name=data.get("cdn_name", data.get("cdn-name", "")),
                    tls_host=data.get("tls", {}).get("host", "") if isinstance(data.get("tls"), dict) else "",
                    tls_version=data.get("tls", {}).get("version", "") if isinstance(data.get("tls"), dict) else "",
                    response_time=data.get("response_time", data.get("response-time", "")),
                    failed=data.get("failed", False),
                    error=data.get("error", ""),
                )
                result.probes.append(probe)

                if probe.failed:
                    result.failed_count += 1
                else:
                    result.alive_count += 1

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
                "follow_redirects": {
                    "type": "boolean",
                    "default": True,
                    "description": "Follow HTTP redirects",
                },
                "tech_detect": {
                    "type": "boolean",
                    "default": True,
                    "description": "Detect web technologies",
                },
                "threads": {
                    "type": "integer",
                    "default": 50,
                    "description": "Number of concurrent threads",
                },
                "match_codes": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Only show these HTTP status codes",
                },
            },
            "required": ["targets"],
        }
