"""
NumaSec - Ffuf Tool Wrapper

Fast web fuzzer with JSON output parsing.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from numasec.tools.base import (
    BaseTool,
    FuzzResult,
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


class FfufMatch(BaseModel):
    """Single ffuf match result."""

    input_data: dict[str, str] = Field(default_factory=dict)
    position: int = 0
    status: int = 0
    length: int = 0
    words: int = 0
    lines: int = 0
    content_type: str = ""
    redirect_location: str = ""
    duration: int = 0  # nanoseconds
    url: str = ""
    result_file: str = ""

    @property
    def fuzz_word(self) -> str:
        """Get the FUZZ keyword value."""
        return self.input_data.get("FUZZ", "")

    def to_fuzz_result(self) -> FuzzResult:
        """Convert to generic FuzzResult."""
        return FuzzResult(
            url=self.url,
            status_code=self.status,
            content_length=self.length,
            words=self.words,
            lines=self.lines,
            payload=self.fuzz_word,
        )


class FfufConfig(BaseModel):
    """Ffuf scan configuration from output."""

    url: str = ""
    wordlist: str = ""
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    data: str = ""
    extensions: list[str] = Field(default_factory=list)
    matchers: dict[str, Any] = Field(default_factory=dict)
    filters: dict[str, Any] = Field(default_factory=dict)


class FfufResult(BaseModel):
    """Complete ffuf scan result."""

    results: list[FfufMatch] = Field(default_factory=list)
    config: FfufConfig = Field(default_factory=FfufConfig)
    command_line: str = ""
    time_taken: str = ""
    total_requests: int = 0
    requests_per_second: float = 0
    duration_seconds: float = 0

    @property
    def total_matches(self) -> int:
        return len(self.results)

    @property
    def by_status_code(self) -> dict[int, list[FfufMatch]]:
        """Group matches by status code."""
        result: dict[int, list[FfufMatch]] = {}
        for match in self.results:
            if match.status not in result:
                result[match.status] = []
            result[match.status].append(match)
        return result

    @property
    def directories_found(self) -> list[str]:
        """Get found directories (200, 301, 302, 403)."""
        return [m.fuzz_word for m in self.results if m.status in [200, 301, 302, 403]]


# ══════════════════════════════════════════════════════════════════════════════
# Ffuf Tool
# ══════════════════════════════════════════════════════════════════════════════


@register_tool
class FfufTool(BaseTool[FfufResult]):
    """
    Ffuf web fuzzer wrapper.

    Supports:
    - Directory and file fuzzing
    - Parameter fuzzing
    - Virtual host discovery
    - Custom wordlists
    - Match/filter by status, size, words
    """

    name = "ffuf"
    description = "Fast web fuzzer for directory and parameter discovery"
    category = ToolCategory.WEB_APPLICATION
    risk = ToolRisk.MEDIUM
    command = "ffuf"

    async def execute(
        self,
        url: str,
        wordlist: str,
        method: str = "GET",
        data: str | None = None,
        headers: dict[str, str] | None = None,
        extensions: list[str] | None = None,
        match_codes: list[int] | None = None,
        filter_codes: list[int] | None = None,
        filter_size: int | None = None,
        filter_words: int | None = None,
        filter_lines: int | None = None,
        threads: int = 40,
        rate: int = 0,
        timeout: int = 600,
        extra_args: list[str] | None = None,
    ) -> ToolResult[FfufResult]:
        """
        Execute ffuf fuzzing.

        Args:
            url: Target URL with FUZZ keyword
            wordlist: Path to wordlist
            method: HTTP method
            data: POST data
            headers: Custom headers
            extensions: File extensions to append
            match_codes: Match these status codes
            filter_codes: Filter these status codes
            filter_size: Filter by response size
            filter_words: Filter by word count
            filter_lines: Filter by line count
            threads: Concurrent threads
            rate: Requests per second (0 = unlimited)
            timeout: Scan timeout
            extra_args: Additional ffuf arguments

        Returns:
            ToolResult with FfufResult data
        """
        start_time = datetime.now(timezone.utc)

        # Build command
        cmd = ["ffuf", "-json", "-s"]  # -s for silent mode

        # Target and wordlist
        cmd.extend(["-u", url])
        cmd.extend(["-w", wordlist])

        # Method
        cmd.extend(["-X", method])

        # POST data
        if data:
            cmd.extend(["-d", data])

        # Headers
        if headers:
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])

        # Extensions
        if extensions:
            cmd.extend(["-e", ",".join(extensions)])

        # Match codes
        if match_codes:
            cmd.extend(["-mc", ",".join(str(c) for c in match_codes)])
        else:
            cmd.extend(["-mc", "all"])  # Default to all

        # Filter codes
        if filter_codes:
            cmd.extend(["-fc", ",".join(str(c) for c in filter_codes)])

        # Filter size
        if filter_size is not None:
            cmd.extend(["-fs", str(filter_size)])

        # Filter words
        if filter_words is not None:
            cmd.extend(["-fw", str(filter_words)])

        # Filter lines
        if filter_lines is not None:
            cmd.extend(["-fl", str(filter_lines)])

        # Threads and rate
        cmd.extend(["-t", str(threads)])
        if rate > 0:
            cmd.extend(["-rate", str(rate)])

        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        # Execute
        executor = get_executor()
        result = await executor.execute(cmd, timeout=timeout)

        completed_at = datetime.now(timezone.utc)
        duration_ms = (completed_at - start_time).total_seconds() * 1000

        if result.exit_code != 0:
            return ToolResult[FfufResult](
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
            ffuf_result = self.parse_output(result.stdout)
            ffuf_result.duration_seconds = duration_ms / 1000
        except Exception as e:
            return ToolResult[FfufResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                raw_output=result.stdout,
                error=f"Failed to parse ffuf output: {e}",
                command=" ".join(cmd),
                exit_code=result.exit_code,
                started_at=start_time,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

        return ToolResult[FfufResult](
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            data=ffuf_result,
            raw_output=result.stdout,
            command=" ".join(cmd),
            exit_code=result.exit_code,
            started_at=start_time,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )

    def parse_output(self, raw_output: str) -> FfufResult:
        """Parse ffuf JSON output."""
        result = FfufResult()

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return result

        # Parse config
        config_data = data.get("config", {})
        result.config = FfufConfig(
            url=config_data.get("url", ""),
            wordlist=config_data.get("wordlist", ""),
            method=config_data.get("method", "GET"),
            headers=config_data.get("headers", {}),
            data=config_data.get("data", ""),
        )

        result.command_line = data.get("commandline", "")
        result.time_taken = data.get("time", "")

        # Parse results
        for item in data.get("results", []):
            match = FfufMatch(
                input_data=item.get("input", {}),
                position=item.get("position", 0),
                status=item.get("status", 0),
                length=item.get("length", 0),
                words=item.get("words", 0),
                lines=item.get("lines", 0),
                content_type=item.get("content-type", ""),
                redirect_location=item.get("redirectlocation", ""),
                duration=item.get("duration", 0),
                url=item.get("url", ""),
                result_file=item.get("resultfile", ""),
            )
            result.results.append(match)

        return result

    @classmethod
    def get_schema(cls) -> dict[str, Any]:
        """Get JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with FUZZ keyword",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist file",
                },
                "method": {
                    "type": "string",
                    "default": "GET",
                    "description": "HTTP method",
                },
                "data": {
                    "type": "string",
                    "description": "POST data (use FUZZ keyword)",
                },
                "extensions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "File extensions to append",
                },
                "match_codes": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Match these status codes",
                },
                "filter_codes": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Filter these status codes",
                },
                "filter_size": {
                    "type": "integer",
                    "description": "Filter responses with this size",
                },
                "threads": {
                    "type": "integer",
                    "default": 40,
                    "description": "Concurrent threads",
                },
            },
            "required": ["url", "wordlist"],
        }
