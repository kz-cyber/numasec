"""
NumaSec - Tool Executor

Subprocess execution with timeout, output capture, and error handling.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import signal
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from numasec.tools.base import (
    BaseTool,
    ToolError,
    ToolResult,
    ToolStatus,
)


# ══════════════════════════════════════════════════════════════════════════════
# Execution Configuration
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class ExecutionConfig:
    """Configuration for tool execution."""

    timeout: int = 300  # 5 minutes default
    max_output_size: int = 10 * 1024 * 1024  # 10MB
    working_dir: str | None = None
    env: dict[str, str] | None = None
    capture_stderr: bool = True
    save_output: bool = True
    output_dir: str = "{NUMASEC_DATA_DIR}/outputs"  # Will be expanded at runtime


# ══════════════════════════════════════════════════════════════════════════════
# Tool Executor
# ══════════════════════════════════════════════════════════════════════════════


class ToolExecutor:
    """
    Execute security tools as subprocesses.

    Features:
    - Timeout handling
    - Output capture (stdout/stderr)
    - JSON output parsing
    - Evidence storage
    - Error handling and recovery
    """

    def __init__(self, config: ExecutionConfig | None = None) -> None:
        """Initialize executor."""
        self.config = config or ExecutionConfig()
        self._running_processes: dict[str, asyncio.subprocess.Process] = {}

    async def execute(
        self,
        command: list[str] | str,
        timeout: int | None = None,
        working_dir: str | None = None,
        env: dict[str, str] | None = None,
        input_data: str | None = None,
    ) -> ExecutionResult:
        """
        Execute a command and capture output.

        Args:
            command: Command to execute (list or string)
            timeout: Execution timeout in seconds
            working_dir: Working directory
            env: Environment variables
            input_data: Data to pass to stdin

        Returns:
            ExecutionResult with output and status
        """
        start_time = datetime.now(timezone.utc)
        timeout = timeout or self.config.timeout

        # Parse command
        if isinstance(command, str):
            cmd_list = shlex.split(command)
        else:
            cmd_list = command

        cmd_str = " ".join(cmd_list)

        # Prepare environment
        process_env = os.environ.copy()
        if self.config.env:
            process_env.update(self.config.env)
        if env:
            process_env.update(env)

        # Prepare working directory
        cwd = working_dir or self.config.working_dir
        if cwd:
            cwd = os.path.expanduser(cwd)

        try:
            # Create process
            process = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE if self.config.capture_stderr else None,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                cwd=cwd,
                env=process_env,
            )

            # Track process
            process_id = f"{cmd_list[0]}_{id(process)}"
            self._running_processes[process_id] = process

            try:
                # Execute with timeout
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=input_data.encode() if input_data else None),
                    timeout=timeout,
                )

                # Truncate if too large
                if len(stdout) > self.config.max_output_size:
                    stdout = stdout[:self.config.max_output_size] + b"\n... (truncated)"

                return ExecutionResult(
                    command=cmd_str,
                    status=ToolStatus.SUCCESS if process.returncode == 0 else ToolStatus.FAILED,
                    exit_code=process.returncode or 0,
                    stdout=stdout.decode("utf-8", errors="replace"),
                    stderr=stderr.decode("utf-8", errors="replace") if stderr else "",
                    started_at=start_time,
                    completed_at=datetime.now(timezone.utc),
                )

            except asyncio.TimeoutError:
                # Kill process on timeout
                process.kill()
                await process.wait()

                return ExecutionResult(
                    command=cmd_str,
                    status=ToolStatus.TIMEOUT,
                    exit_code=-1,
                    stdout="",
                    stderr=f"Process timed out after {timeout} seconds",
                    started_at=start_time,
                    completed_at=datetime.now(timezone.utc),
                )

            finally:
                # Remove from tracking
                self._running_processes.pop(process_id, None)

        except FileNotFoundError:
            return ExecutionResult(
                command=cmd_str,
                status=ToolStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr=f"Command not found: {cmd_list[0]}",
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
            )

        except PermissionError:
            return ExecutionResult(
                command=cmd_str,
                status=ToolStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr=f"Permission denied: {cmd_list[0]}",
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
            )

        except Exception as e:
            return ExecutionResult(
                command=cmd_str,
                status=ToolStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
            )

    async def execute_tool(
        self,
        tool: BaseTool,
        **kwargs: Any,
    ) -> ToolResult:
        """
        Execute a tool instance.

        Args:
            tool: Tool to execute
            **kwargs: Tool parameters

        Returns:
            ToolResult from tool execution
        """
        return await tool.execute(**kwargs)

    async def cancel_all(self) -> int:
        """
        Cancel all running processes.

        Returns:
            Number of processes cancelled
        """
        cancelled = 0

        for process_id, process in list(self._running_processes.items()):
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()
            except Exception:
                pass
            finally:
                cancelled += 1
                self._running_processes.pop(process_id, None)

        return cancelled

    def get_running_count(self) -> int:
        """Get number of running processes."""
        return len(self._running_processes)

    async def save_output(
        self,
        result: "ExecutionResult",
        name: str | None = None,
    ) -> Path | None:
        """
        Save execution output to file.

        Args:
            result: Execution result
            name: Optional name for output file

        Returns:
            Path to saved file or None
        """
        if not self.config.save_output:
            return None

        # Expand {NUMASEC_DATA_DIR} placeholder
        dir_path = self.config.output_dir.replace(
            "{NUMASEC_DATA_DIR}",
            os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec"))
        )
        output_dir = Path(os.path.expanduser(dir_path))
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = result.started_at.strftime("%Y%m%d_%H%M%S")
        name = name or result.command.split()[0]
        filename = f"{name}_{timestamp}.txt"

        output_path = output_dir / filename

        content = f"""Command: {result.command}
Status: {result.status.value}
Exit Code: {result.exit_code}
Started: {result.started_at.isoformat()}
Completed: {result.completed_at.isoformat() if result.completed_at else 'N/A'}
Duration: {result.duration_ms:.1f}ms

=== STDOUT ===
{result.stdout}

=== STDERR ===
{result.stderr}
"""

        output_path.write_text(content)
        return output_path


@dataclass
class ExecutionResult:
    """Result from command execution."""

    command: str
    status: ToolStatus
    exit_code: int
    stdout: str
    stderr: str
    started_at: datetime
    completed_at: datetime | None = None

    @property
    def success(self) -> bool:
        """Check if execution was successful."""
        return self.status == ToolStatus.SUCCESS and self.exit_code == 0

    @property
    def duration_ms(self) -> float:
        """Get execution duration in milliseconds."""
        if self.completed_at is None:
            return 0
        delta = self.completed_at - self.started_at
        return delta.total_seconds() * 1000

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "command": self.command,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "stdout_lines": len(self.stdout.split("\n")),
            "stderr_lines": len(self.stderr.split("\n")),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Global Executor
# ══════════════════════════════════════════════════════════════════════════════

_executor: ToolExecutor | None = None


def get_executor() -> ToolExecutor:
    """Get the global tool executor."""
    global _executor
    if _executor is None:
        _executor = ToolExecutor()
    return _executor


async def execute_command(
    command: list[str] | str,
    timeout: int | None = None,
    **kwargs: Any,
) -> ExecutionResult:
    """Execute a command using the global executor."""
    return await get_executor().execute(command, timeout=timeout, **kwargs)
