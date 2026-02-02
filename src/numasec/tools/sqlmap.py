"""
NumaSec - SQLMap Tool Wrapper

SQL injection detection and exploitation with JSON output.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
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


class SQLiInjection(BaseModel):
    """SQL injection finding."""

    parameter: str
    place: str  # GET, POST, COOKIE, HEADER
    injection_type: str  # boolean-based, error-based, time-based, UNION
    title: str
    payload: str
    vector: str = ""
    backend: str = ""


class SQLiDatabase(BaseModel):
    """Extracted database information."""

    name: str
    tables: list[str] = Field(default_factory=list)


class SQLMapResult(BaseModel):
    """Complete SQLMap scan result."""

    target: str = ""
    vulnerable: bool = False
    injections: list[SQLiInjection] = Field(default_factory=list)
    backend_dbms: str = ""
    web_server: str = ""
    web_application: str = ""
    databases: list[SQLiDatabase] = Field(default_factory=list)
    current_user: str = ""
    current_db: str = ""
    is_dba: bool = False
    hostname: str = ""
    duration_seconds: float = 0

    @property
    def injection_count(self) -> int:
        return len(self.injections)

    @property
    def has_critical(self) -> bool:
        """Check if any critical injection types found."""
        critical_types = ["stacked", "UNION", "error-based"]
        return any(
            any(t in inj.injection_type for t in critical_types)
            for inj in self.injections
        )

    def to_vulnerability(self) -> Vulnerability | None:
        """Convert to generic Vulnerability if vulnerable."""
        if not self.vulnerable:
            return None
        return Vulnerability(
            id="SQL_INJECTION",
            name=f"SQL Injection in {self.target}",
            severity="critical" if self.has_critical else "high",
            description=f"SQL injection found. DBMS: {self.backend_dbms}. "
            f"Injection types: {', '.join(i.injection_type for i in self.injections)}",
            url=self.target,
        )


# ══════════════════════════════════════════════════════════════════════════════
# SQLMap Tool
# ══════════════════════════════════════════════════════════════════════════════


@register_tool
class SQLMapTool(BaseTool[SQLMapResult]):
    """
    SQLMap SQL injection wrapper.

    Supports:
    - Automatic SQL injection detection
    - Database enumeration
    - Data extraction
    - Various techniques and tampers
    
    WARNING: This is a HIGH risk tool that can modify databases.
    Always use with explicit human approval.
    """

    name = "sqlmap"
    description = "Automatic SQL injection detection and exploitation"
    category = ToolCategory.WEB_APPLICATION
    risk = ToolRisk.HIGH  # Can modify data!
    command = "sqlmap"

    async def execute(
        self,
        url: str | None = None,
        request_file: str | None = None,
        data: str | None = None,
        param: str | None = None,
        cookie: str | None = None,
        headers: dict[str, str] | None = None,
        technique: str = "BEUSTQ",  # All techniques
        level: int = 1,  # 1-5
        risk: int = 1,  # 1-3
        dbs: bool = False,
        tables: bool = False,
        dump: bool = False,
        batch: bool = True,  # Non-interactive
        threads: int = 1,
        timeout: int = 600,
        tamper: str | None = None,
        extra_args: list[str] | None = None,
    ) -> ToolResult[SQLMapResult]:
        """
        Execute SQLMap scan.

        Args:
            url: Target URL with injectable parameter
            request_file: HTTP request file
            data: POST data
            param: Specific parameter to test
            cookie: HTTP cookie
            headers: Custom headers
            technique: Injection techniques (B=boolean, E=error, U=union, S=stacked, T=time, Q=inline)
            level: Level of tests (1-5)
            risk: Risk of tests (1-3)
            dbs: Enumerate databases
            tables: Enumerate tables
            dump: Dump data
            batch: Non-interactive mode
            threads: Concurrent threads
            timeout: Scan timeout
            tamper: Tamper script(s)
            extra_args: Additional SQLMap arguments

        Returns:
            ToolResult with SQLMapResult data
        """
        start_time = datetime.now(timezone.utc)

        if not url and not request_file:
            return ToolResult[SQLMapResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                raw_output="",
                error="Either url or request_file is required",
                command="",
                exit_code=-1,
                started_at=start_time,
                completed_at=start_time,
                duration_ms=0,
            )

        # Build command
        cmd = ["sqlmap"]

        # Target
        if url:
            cmd.extend(["-u", url])
        if request_file:
            cmd.extend(["-r", request_file])

        # Data
        if data:
            cmd.extend(["--data", data])

        # Parameter
        if param:
            cmd.extend(["-p", param])

        # Cookie
        if cookie:
            cmd.extend(["--cookie", cookie])

        # Headers
        if headers:
            for key, value in headers.items():
                cmd.extend(["--header", f"{key}: {value}"])

        # Technique settings
        cmd.extend(["--technique", technique])
        cmd.extend(["--level", str(level)])
        cmd.extend(["--risk", str(risk)])

        # Enumeration flags
        if dbs:
            cmd.append("--dbs")
        if tables:
            cmd.append("--tables")
        if dump:
            cmd.append("--dump")

        # Tamper
        if tamper:
            cmd.extend(["--tamper", tamper])

        # Threads
        cmd.extend(["--threads", str(threads)])

        # Batch mode
        if batch:
            cmd.append("--batch")

        # Output format
        cmd.append("--forms")  # Check forms
        cmd.append("--smart")  # Smart mode

        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        # Execute
        executor = get_executor()
        result = await executor.execute(cmd, timeout=timeout)

        completed_at = datetime.now(timezone.utc)
        duration_ms = (completed_at - start_time).total_seconds() * 1000

        # SQLMap has complex exit codes, parse output instead
        sqlmap_result = self.parse_output(result.stdout, url or "")
        sqlmap_result.target = url or request_file or ""
        sqlmap_result.duration_seconds = duration_ms / 1000

        status = ToolStatus.SUCCESS if sqlmap_result.vulnerable else ToolStatus.SUCCESS

        return ToolResult[SQLMapResult](
            tool_name=self.name,
            status=status,
            data=sqlmap_result,
            raw_output=result.stdout,
            command=" ".join(cmd),
            exit_code=result.exit_code,
            started_at=start_time,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )

    def parse_output(self, raw_output: str, target: str) -> SQLMapResult:
        """Parse SQLMap text output."""
        result = SQLMapResult(target=target)

        lines = raw_output.split("\n")

        for line in lines:
            line = line.strip()

            # Check for vulnerability confirmation
            if "is vulnerable" in line.lower():
                result.vulnerable = True

            # Backend DBMS
            if "back-end DBMS:" in line:
                result.backend_dbms = line.split(":", 1)[1].strip()

            # Web server
            if "web server operating system:" in line:
                result.web_server = line.split(":", 1)[1].strip()

            if "web application technology:" in line:
                result.web_application = line.split(":", 1)[1].strip()

            # Current user
            if "current user:" in line:
                result.current_user = line.split(":", 1)[1].strip()

            # Current database
            if "current database:" in line:
                result.current_db = line.split(":", 1)[1].strip()

            # DBA check
            if "current user is DBA:" in line:
                result.is_dba = "True" in line

            # Hostname
            if "hostname:" in line:
                result.hostname = line.split(":", 1)[1].strip()

            # Injection type detection
            if "Type:" in line and "Payload:" in line.lower():
                # This is an injection finding
                injection = SQLiInjection(
                    parameter="",
                    place="",
                    injection_type=line.split("Type:", 1)[1].split()[0] if "Type:" in line else "",
                    title=line,
                    payload="",
                )
                result.injections.append(injection)

            # Parameter is injectable
            if "Parameter:" in line and "is vulnerable" in raw_output:
                parts = line.replace("Parameter:", "").strip().split()
                if parts:
                    param = parts[0].strip("'").strip('"')
                    place = parts[1].strip("()") if len(parts) > 1 else ""
                    injection = SQLiInjection(
                        parameter=param,
                        place=place,
                        injection_type="detected",
                        title=line,
                        payload="",
                    )
                    if not any(i.parameter == param for i in result.injections):
                        result.injections.append(injection)

        # If we found backend DBMS, it's likely vulnerable
        if result.backend_dbms and not result.vulnerable:
            result.vulnerable = True

        return result

    @classmethod
    def get_schema(cls) -> dict[str, Any]:
        """Get JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with injectable parameter",
                },
                "request_file": {
                    "type": "string",
                    "description": "Path to HTTP request file",
                },
                "data": {
                    "type": "string",
                    "description": "POST data",
                },
                "param": {
                    "type": "string",
                    "description": "Specific parameter to test",
                },
                "technique": {
                    "type": "string",
                    "default": "BEUSTQ",
                    "description": "Injection techniques",
                },
                "level": {
                    "type": "integer",
                    "default": 1,
                    "minimum": 1,
                    "maximum": 5,
                    "description": "Level of tests",
                },
                "risk": {
                    "type": "integer",
                    "default": 1,
                    "minimum": 1,
                    "maximum": 3,
                    "description": "Risk of tests",
                },
                "dbs": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enumerate databases",
                },
                "batch": {
                    "type": "boolean",
                    "default": True,
                    "description": "Non-interactive mode",
                },
            },
            "required": [],
        }
