"""
NumaSec - WhatWeb Tool Wrapper

Web technology fingerprinting with JSON output.
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
)
from numasec.tools.executor import get_executor
from numasec.tools.registry import register_tool


# ══════════════════════════════════════════════════════════════════════════════
# Output Models
# ══════════════════════════════════════════════════════════════════════════════


class WhatWebPlugin(BaseModel):
    """Single WhatWeb plugin result."""

    name: str
    version: list[str] = Field(default_factory=list)
    string: list[str] = Field(default_factory=list)
    certainty: int = 100


class WhatWebTarget(BaseModel):
    """WhatWeb result for a single target."""

    target: str
    http_status: int = 0
    request_config: dict[str, Any] = Field(default_factory=dict)
    plugins: list[WhatWebPlugin] = Field(default_factory=list)

    @property
    def technologies(self) -> list[str]:
        """Get list of detected technologies."""
        return [p.name for p in self.plugins]

    @property
    def technologies_with_versions(self) -> dict[str, str]:
        """Get technologies with their versions."""
        result = {}
        for p in self.plugins:
            version = p.version[0] if p.version else ""
            result[p.name] = version
        return result


class WhatWebResult(BaseModel):
    """Complete WhatWeb scan result."""

    targets: list[WhatWebTarget] = Field(default_factory=list)
    duration_seconds: float = 0

    @property
    def all_technologies(self) -> set[str]:
        """Get all unique technologies across all targets."""
        techs = set()
        for target in self.targets:
            techs.update(target.technologies)
        return techs


# ══════════════════════════════════════════════════════════════════════════════
# WhatWeb Tool
# ══════════════════════════════════════════════════════════════════════════════


@register_tool
class WhatWebTool(BaseTool[WhatWebResult]):
    """
    WhatWeb web fingerprinting wrapper.

    Supports:
    - Technology detection
    - Version identification
    - Multiple aggression levels
    """

    name = "whatweb"
    description = "Web technology fingerprinting"
    category = ToolCategory.RECONNAISSANCE
    risk = ToolRisk.LOW  # Passive fingerprinting
    command = "whatweb"

    async def execute(
        self,
        targets: list[str],
        aggression: int = 1,  # 1=stealthy, 3=aggressive, 4=heavy
        follow_redirect: bool = True,
        max_redirects: int = 4,
        timeout: int = 300,
        extra_args: list[str] | None = None,
    ) -> ToolResult[WhatWebResult]:
        """
        Execute WhatWeb scan.

        Args:
            targets: Target URLs or hosts
            aggression: Aggression level (1-4)
            follow_redirect: Follow HTTP redirects
            max_redirects: Maximum redirects to follow
            timeout: Scan timeout
            extra_args: Additional WhatWeb arguments

        Returns:
            ToolResult with WhatWebResult data
        """
        start_time = datetime.now(timezone.utc)

        # Build command
        cmd = ["whatweb", "--log-json=-"]  # JSON output to stdout

        # Aggression level
        cmd.extend(["-a", str(aggression)])

        # Redirects
        if follow_redirect:
            cmd.append("--follow-redirect=always")
            cmd.extend(["--max-redirects", str(max_redirects)])

        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        # Add targets
        cmd.extend(targets)

        # Execute
        executor = get_executor()
        result = await executor.execute(cmd, timeout=timeout)

        completed_at = datetime.now(timezone.utc)
        duration_ms = (completed_at - start_time).total_seconds() * 1000

        if result.exit_code != 0 and not result.stdout:
            return ToolResult[WhatWebResult](
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
            whatweb_result = self.parse_output(result.stdout)
            whatweb_result.duration_seconds = duration_ms / 1000
        except Exception as e:
            return ToolResult[WhatWebResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                raw_output=result.stdout,
                error=f"Failed to parse WhatWeb output: {e}",
                command=" ".join(cmd),
                exit_code=result.exit_code,
                started_at=start_time,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

        return ToolResult[WhatWebResult](
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            data=whatweb_result,
            raw_output=result.stdout,
            command=" ".join(cmd),
            exit_code=result.exit_code,
            started_at=start_time,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )

    def parse_output(self, raw_output: str) -> WhatWebResult:
        """Parse WhatWeb JSON output."""
        result = WhatWebResult()

        for line in raw_output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)
                
                # Each line is a target result
                target = WhatWebTarget(
                    target=data.get("target", ""),
                    http_status=data.get("http_status", 0),
                    request_config=data.get("request_config", {}),
                )

                # Parse plugins
                plugins_data = data.get("plugins", {})
                for plugin_name, plugin_info in plugins_data.items():
                    if isinstance(plugin_info, dict):
                        plugin = WhatWebPlugin(
                            name=plugin_name,
                            version=plugin_info.get("version", []),
                            string=plugin_info.get("string", []),
                            certainty=plugin_info.get("certainty", 100),
                        )
                    else:
                        plugin = WhatWebPlugin(name=plugin_name)
                    target.plugins.append(plugin)

                result.targets.append(target)

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
                "aggression": {
                    "type": "integer",
                    "default": 1,
                    "minimum": 1,
                    "maximum": 4,
                    "description": "Aggression level (1=stealthy, 4=aggressive)",
                },
                "follow_redirect": {
                    "type": "boolean",
                    "default": True,
                    "description": "Follow HTTP redirects",
                },
            },
            "required": ["targets"],
        }
