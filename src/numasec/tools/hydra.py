"""
NumaSec - Hydra Tool Wrapper

Password brute-force with structured output parsing.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from numasec.tools.base import (
    BaseTool,
    Credential,
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


class HydraCredential(BaseModel):
    """Found credential from Hydra."""

    host: str
    port: int
    service: str
    login: str
    password: str

    def to_credential(self) -> Credential:
        """Convert to generic Credential."""
        return Credential(
            username=self.login,
            password=self.password,
            service=self.service,
            host=self.host,
        )


class HydraResult(BaseModel):
    """Complete Hydra attack result."""

    target: str = ""
    service: str = ""
    port: int = 0
    credentials: list[HydraCredential] = Field(default_factory=list)
    attempts: int = 0
    success: bool = False
    duration_seconds: float = 0

    @property
    def credentials_found(self) -> int:
        return len(self.credentials)


# ══════════════════════════════════════════════════════════════════════════════
# Hydra Tool
# ══════════════════════════════════════════════════════════════════════════════


@register_tool
class HydraTool(BaseTool[HydraResult]):
    """
    Hydra password cracker wrapper.

    Supports:
    - Multiple protocols (SSH, FTP, HTTP, etc.)
    - Wordlist-based attacks
    - Single credentials testing
    
    WARNING: This is a CRITICAL risk tool for exploitation.
    Requires explicit human approval.
    """

    name = "hydra"
    description = "Fast network logon cracker"
    category = ToolCategory.EXPLOITATION
    risk = ToolRisk.CRITICAL  # Active exploitation!
    command = "hydra"

    # Supported services
    SERVICES = [
        "ssh", "ftp", "http-get", "http-post", "http-post-form",
        "https-get", "https-post", "https-post-form",
        "mysql", "postgres", "mssql", "oracle", "mongodb",
        "smb", "rdp", "vnc", "telnet", "smtp", "pop3", "imap",
        "ldap", "snmp", "redis", "memcached",
    ]

    async def execute(
        self,
        target: str,
        service: str,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        user_list: str | None = None,
        pass_list: str | None = None,
        http_path: str | None = None,
        http_form: str | None = None,
        threads: int = 16,
        timeout: int = 600,
        exit_on_first: bool = True,
        extra_args: list[str] | None = None,
    ) -> ToolResult[HydraResult]:
        """
        Execute Hydra brute-force attack.

        Args:
            target: Target host
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            port: Service port (default based on service)
            username: Single username
            password: Single password
            user_list: Path to username wordlist
            pass_list: Path to password wordlist
            http_path: HTTP path for web attacks
            http_form: HTTP form data (for http-*-form)
            threads: Concurrent threads
            timeout: Attack timeout
            exit_on_first: Stop on first valid credential
            extra_args: Additional Hydra arguments

        Returns:
            ToolResult with HydraResult data
        """
        start_time = datetime.now(timezone.utc)

        if service not in self.SERVICES:
            return ToolResult[HydraResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                raw_output="",
                error=f"Unsupported service: {service}. Supported: {', '.join(self.SERVICES)}",
                command="",
                exit_code=-1,
                started_at=start_time,
                completed_at=start_time,
                duration_ms=0,
            )

        if not username and not user_list:
            return ToolResult[HydraResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                raw_output="",
                error="Either username or user_list is required",
                command="",
                exit_code=-1,
                started_at=start_time,
                completed_at=start_time,
                duration_ms=0,
            )

        if not password and not pass_list:
            return ToolResult[HydraResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                raw_output="",
                error="Either password or pass_list is required",
                command="",
                exit_code=-1,
                started_at=start_time,
                completed_at=start_time,
                duration_ms=0,
            )

        # Build command
        cmd = ["hydra"]

        # Credentials
        if username:
            cmd.extend(["-l", username])
        elif user_list:
            cmd.extend(["-L", user_list])

        if password:
            cmd.extend(["-p", password])
        elif pass_list:
            cmd.extend(["-P", pass_list])

        # Threads
        cmd.extend(["-t", str(threads)])

        # Exit on first
        if exit_on_first:
            cmd.append("-f")

        # Verbose for parsing
        cmd.append("-V")

        # Port
        if port:
            cmd.extend(["-s", str(port)])

        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        # Target and service
        cmd.append(target)
        
        # Service with optional path
        if http_form:
            cmd.append(f"{service}")
            cmd.append(http_form)
        elif http_path:
            cmd.append(f"{service}")
            cmd.append(http_path)
        else:
            cmd.append(service)

        # Execute
        executor = get_executor()
        result = await executor.execute(cmd, timeout=timeout)

        completed_at = datetime.now(timezone.utc)
        duration_ms = (completed_at - start_time).total_seconds() * 1000

        # Parse output
        hydra_result = self.parse_output(result.stdout, target, service, port or 0)
        hydra_result.duration_seconds = duration_ms / 1000

        status = ToolStatus.SUCCESS if hydra_result.credentials_found > 0 else ToolStatus.SUCCESS

        return ToolResult[HydraResult](
            tool_name=self.name,
            status=status,
            data=hydra_result,
            raw_output=result.stdout,
            command=" ".join(cmd),
            exit_code=result.exit_code,
            started_at=start_time,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )

    def parse_output(self, raw_output: str, target: str, service: str, port: int) -> HydraResult:
        """Parse Hydra text output."""
        result = HydraResult(
            target=target,
            service=service,
            port=port,
        )

        # Pattern for found credentials
        # [22][ssh] host: 192.168.1.1   login: admin   password: admin123
        cred_pattern = re.compile(
            r"\[(\d+)\]\[([^\]]+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(.+)"
        )

        # Alternative pattern
        # [ssh] host: 192.168.1.1 login: admin password: admin123
        alt_pattern = re.compile(
            r"\[([^\]]+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(.+)"
        )

        lines = raw_output.split("\n")

        for line in lines:
            line = line.strip()

            # Try main pattern
            match = cred_pattern.search(line)
            if match:
                cred = HydraCredential(
                    port=int(match.group(1)),
                    service=match.group(2),
                    host=match.group(3),
                    login=match.group(4),
                    password=match.group(5).strip(),
                )
                result.credentials.append(cred)
                result.success = True
                continue

            # Try alternative pattern
            match = alt_pattern.search(line)
            if match:
                cred = HydraCredential(
                    port=port,
                    service=match.group(1),
                    host=match.group(2),
                    login=match.group(3),
                    password=match.group(4).strip(),
                )
                result.credentials.append(cred)
                result.success = True
                continue

            # Count attempts
            if "login:" in line.lower() and "password:" in line.lower():
                result.attempts += 1

        return result

    @classmethod
    def get_schema(cls) -> dict[str, Any]:
        """Get JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host or IP",
                },
                "service": {
                    "type": "string",
                    "enum": cls.SERVICES,
                    "description": "Service to attack",
                },
                "port": {
                    "type": "integer",
                    "description": "Service port",
                },
                "username": {
                    "type": "string",
                    "description": "Single username to try",
                },
                "password": {
                    "type": "string",
                    "description": "Single password to try",
                },
                "user_list": {
                    "type": "string",
                    "description": "Path to username wordlist",
                },
                "pass_list": {
                    "type": "string",
                    "description": "Path to password wordlist",
                },
                "http_form": {
                    "type": "string",
                    "description": "HTTP form string for http-*-form services",
                },
                "threads": {
                    "type": "integer",
                    "default": 16,
                    "description": "Concurrent threads",
                },
                "exit_on_first": {
                    "type": "boolean",
                    "default": True,
                    "description": "Stop on first valid credential",
                },
            },
            "required": ["target", "service"],
        }
