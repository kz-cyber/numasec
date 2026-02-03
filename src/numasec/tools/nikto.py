"""
NumaSec - Nikto Tool Wrapper

Web server scanner with output parsing.
"""

from __future__ import annotations

import re
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


class NiktoFinding(BaseModel):
    """Single Nikto finding."""

    id: str = ""
    osvdb: str = ""
    method: str = ""
    uri: str = ""
    message: str = ""
    
    def to_vulnerability(self) -> Vulnerability:
        """Convert to generic Vulnerability."""
        severity = "low"
        if any(word in self.message.lower() for word in ["critical", "dangerous", "backdoor"]):
            severity = "critical"
        elif any(word in self.message.lower() for word in ["vulnerable", "injection", "xss"]):
            severity = "high"
        elif any(word in self.message.lower() for word in ["outdated", "exposure", "disclosure"]):
            severity = "medium"
            
        return Vulnerability(
            id=self.id or self.osvdb,
            name=self.message[:100] if self.message else "Nikto Finding",
            severity=severity,
            description=self.message,
            url=self.uri,
        )


class NiktoResult(BaseModel):
    """Complete Nikto scan result."""

    target: str = ""
    ip: str = ""
    port: int | None = None  # Allow None for dynamic port detection
    banner: str = ""
    findings: list[NiktoFinding] = Field(default_factory=list)
    duration_seconds: float = 0

    @property
    def total_findings(self) -> int:
        return len(self.findings)


# ══════════════════════════════════════════════════════════════════════════════
# Nikto Tool
# ══════════════════════════════════════════════════════════════════════════════


@register_tool
class NiktoTool(BaseTool[NiktoResult]):
    """
    Nikto web server scanner wrapper.

    Supports:
    - Server misconfiguration detection
    - Outdated software identification
    - Known vulnerability checks
    """

    name = "nikto"
    description = "Web server scanner for misconfigurations and vulnerabilities"
    category = ToolCategory.WEB_APPLICATION
    risk = ToolRisk.LOW  # Mostly passive checks
    command = "nikto"

    async def execute(
        self,
        target: str,
        port: int | None = None,
        ssl: bool = False,
        tuning: str | None = None,
        plugins: str | None = None,
        timeout: int = 600,
        extra_args: list[str] | None = None,
    ) -> ToolResult[NiktoResult]:
        """
        Execute Nikto scan.

        Args:
            target: Target host or URL
            port: Target port
            ssl: Use SSL/TLS
            tuning: Scan tuning options (0-9, a-c, x)
            plugins: Specific plugins to run
            timeout: Scan timeout
            extra_args: Additional Nikto arguments

        Returns:
            ToolResult with NiktoResult data
        """
        start_time = datetime.now(timezone.utc)

        # Build command
        cmd = ["nikto", "-h", target]
        
        # Add port only if explicitly provided
        if port is not None:
            cmd.extend(["-p", str(port)])
        # Otherwise nikto will auto-detect from URL

        if ssl:
            cmd.append("-ssl")

        if tuning:
            cmd.extend(["-Tuning", tuning])

        if plugins:
            cmd.extend(["-Plugins", plugins])

        # Output format
        cmd.extend(["-Format", "txt"])

        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        # Execute
        executor = get_executor()
        result = await executor.execute(cmd, timeout=timeout)

        completed_at = datetime.now(timezone.utc)
        duration_ms = (completed_at - start_time).total_seconds() * 1000

        if result.exit_code != 0 and not result.stdout:
            return ToolResult[NiktoResult](
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
        nikto_result = self.parse_output(result.stdout, target, port)
        nikto_result.duration_seconds = duration_ms / 1000

        return ToolResult[NiktoResult](
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            data=nikto_result,
            raw_output=result.stdout,
            command=" ".join(cmd),
            exit_code=result.exit_code,
            started_at=start_time,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )

    def parse_output(self, raw_output: str, target: str, port: int | None) -> NiktoResult:
        """Parse Nikto text output."""
        result = NiktoResult(target=target, port=port)

        lines = raw_output.split("\n")

        for line in lines:
            line = line.strip()

            # Target IP
            if "+ Target IP:" in line:
                result.ip = line.split(":", 1)[1].strip()

            # Server banner
            if "+ Server:" in line:
                result.banner = line.split(":", 1)[1].strip()

            # Finding lines start with + and often contain OSVDB
            if line.startswith("+"):
                # OSVDB pattern
                osvdb_match = re.search(r"OSVDB-(\d+)", line)
                
                # URI pattern
                uri_match = re.search(r"(/[^\s:]+)", line)
                
                # Skip info lines
                if any(x in line for x in ["Target IP:", "Target Hostname:", "Target Port:", 
                                            "Start Time:", "End Time:", "Server:", "retrieved",
                                            "allowed HTTP Methods"]):
                    continue

                finding = NiktoFinding(
                    osvdb=f"OSVDB-{osvdb_match.group(1)}" if osvdb_match else "",
                    uri=uri_match.group(1) if uri_match else "",
                    message=line[1:].strip(),  # Remove leading +
                )
                
                if finding.message:
                    result.findings.append(finding)

        return result

    @classmethod
    def get_schema(cls) -> dict[str, Any]:
        """Get JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host or URL",
                },
                "port": {
                    "type": "integer",
                    "default": 80,
                    "description": "Target port",
                },
                "ssl": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use SSL/TLS",
                },
                "tuning": {
                    "type": "string",
                    "description": "Scan tuning (0-9, a-c, x)",
                },
            },
            "required": ["target"],
        }
