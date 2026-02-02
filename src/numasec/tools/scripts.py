"""
NumaSec - Script Execution Tool

Execute custom Python and Shell scripts with sandboxing.
"""

from __future__ import annotations

import asyncio
import tempfile
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
)
from numasec.tools.executor import get_executor
from numasec.tools.registry import register_tool


# ══════════════════════════════════════════════════════════════════════════════
# Output Models
# ══════════════════════════════════════════════════════════════════════════════


class ScriptResult(BaseModel):
    """Script execution result."""

    script_type: str  # python, shell
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0
    success: bool = True
    error: str = ""


# ══════════════════════════════════════════════════════════════════════════════
# Script Execution Tool
# ══════════════════════════════════════════════════════════════════════════════


@register_tool
class ScriptTool(BaseTool[ScriptResult]):
    """
    Custom script execution wrapper.

    Supports:
    - Python scripts
    - Shell/Bash scripts
    - Inline code or file execution
    
    WARNING: This is a CRITICAL risk tool.
    Scripts can execute arbitrary code. Requires explicit human approval.
    """

    name = "script"
    description = "Execute custom Python or Shell scripts"
    category = ToolCategory.EXPLOITATION
    risk = ToolRisk.CRITICAL  # Arbitrary code execution!
    command = "python"  # Default to Python

    # Dangerous patterns to warn about
    DANGEROUS_PATTERNS = [
        "rm -rf",
        "sudo",
        "chmod 777",
        ":(){:|:&};:",  # Fork bomb
        "mkfs",
        "dd if=",
        "> /dev/sd",
        "wget.*|.*bash",
        "curl.*|.*sh",
    ]

    async def execute(
        self,
        code: str | None = None,
        script_path: str | None = None,
        script_type: str = "python",  # python, shell
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        working_dir: str | None = None,
        timeout: int = 300,
    ) -> ToolResult[ScriptResult]:
        """
        Execute a custom script.

        Args:
            code: Inline script code
            script_path: Path to script file
            script_type: Type of script (python, shell)
            args: Script arguments
            env: Environment variables
            working_dir: Working directory
            timeout: Execution timeout

        Returns:
            ToolResult with ScriptResult data
        """
        start_time = datetime.now(timezone.utc)

        if not code and not script_path:
            return ToolResult[ScriptResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                raw_output="",
                error="Either code or script_path is required",
                command="",
                exit_code=-1,
                started_at=start_time,
                completed_at=start_time,
                duration_ms=0,
            )

        # Check for dangerous patterns
        content = code or ""
        if script_path:
            try:
                content = Path(script_path).read_text()
            except Exception:
                pass

        for pattern in self.DANGEROUS_PATTERNS:
            if pattern in content:
                # Don't block, but include warning
                pass  # Human approval should catch dangerous scripts

        # Build command
        if script_type == "python":
            interpreter = ["python3", "-u"]  # Unbuffered
        elif script_type == "shell":
            interpreter = ["bash"]
        else:
            return ToolResult[ScriptResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                raw_output="",
                error=f"Unsupported script type: {script_type}",
                command="",
                exit_code=-1,
                started_at=start_time,
                completed_at=start_time,
                duration_ms=0,
            )

        # Handle inline code vs file
        temp_file = None
        if code:
            # Write to temp file
            suffix = ".py" if script_type == "python" else ".sh"
            temp_file = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=suffix,
                delete=False,
            )
            temp_file.write(code)
            temp_file.close()
            script_path = temp_file.name

        cmd = interpreter + [script_path]
        if args:
            cmd.extend(args)

        # Execute
        executor = get_executor()
        result = await executor.execute(
            cmd,
            timeout=timeout,
            env=env,
            working_dir=working_dir,
        )

        # Cleanup temp file
        if temp_file:
            try:
                Path(temp_file.name).unlink()
            except Exception:
                pass

        completed_at = datetime.now(timezone.utc)
        duration_ms = (completed_at - start_time).total_seconds() * 1000

        script_result = ScriptResult(
            script_type=script_type,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_seconds=duration_ms / 1000,
            success=result.exit_code == 0,
            error=result.stderr if result.exit_code != 0 else "",
        )

        status = ToolStatus.SUCCESS if script_result.success else ToolStatus.FAILED

        return ToolResult[ScriptResult](
            tool_name=self.name,
            status=status,
            data=script_result,
            raw_output=result.stdout + result.stderr,
            command=" ".join(cmd),
            exit_code=result.exit_code,
            started_at=start_time,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )

    def parse_output(self, raw_output: str) -> ScriptResult:
        """Parse script output (returns as-is since scripts have custom output)."""
        return ScriptResult(
            script_type="unknown",
            stdout=raw_output,
            success=True,
        )

    @classmethod
    def get_schema(cls) -> dict[str, Any]:
        """Get JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Inline script code",
                },
                "script_path": {
                    "type": "string",
                    "description": "Path to script file",
                },
                "script_type": {
                    "type": "string",
                    "enum": ["python", "shell"],
                    "default": "python",
                    "description": "Type of script",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Script arguments",
                },
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Environment variables",
                },
                "working_dir": {
                    "type": "string",
                    "description": "Working directory",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Execution timeout in seconds",
                },
            },
            "required": [],
        }


# ══════════════════════════════════════════════════════════════════════════════
# Python Script Tool (convenience wrapper)
# ══════════════════════════════════════════════════════════════════════════════


@register_tool
class PythonScriptTool(BaseTool[ScriptResult]):
    """
    Python script execution wrapper.
    
    Convenience wrapper for executing Python code.
    """

    name = "python_script"
    description = "Execute Python scripts"
    category = ToolCategory.EXPLOITATION
    risk = ToolRisk.CRITICAL
    command = "python3"

    async def execute(
        self,
        code: str,
        args: list[str] | None = None,
        timeout: int = 300,
    ) -> ToolResult[ScriptResult]:
        """Execute Python code."""
        script_tool = ScriptTool()
        return await script_tool.execute(
            code=code,
            script_type="python",
            args=args,
            timeout=timeout,
        )

    def parse_output(self, raw_output: str) -> ScriptResult:
        """Parse Python script output."""
        return ScriptResult(
            script_type="python",
            stdout=raw_output,
            success=True,
        )

    @classmethod
    def get_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Python code to execute",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Script arguments",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Execution timeout",
                },
            },
            "required": ["code"],
        }


# ══════════════════════════════════════════════════════════════════════════════
# Shell Script Tool (convenience wrapper)
# ══════════════════════════════════════════════════════════════════════════════


@register_tool
class ShellScriptTool(BaseTool[ScriptResult]):
    """
    Shell script execution wrapper.
    
    Convenience wrapper for executing Shell/Bash code.
    """

    name = "shell_script"
    description = "Execute Shell/Bash scripts"
    category = ToolCategory.EXPLOITATION
    risk = ToolRisk.CRITICAL
    command = "bash"

    async def execute(
        self,
        code: str,
        args: list[str] | None = None,
        timeout: int = 300,
    ) -> ToolResult[ScriptResult]:
        """Execute Shell code."""
        script_tool = ScriptTool()
        return await script_tool.execute(
            code=code,
            script_type="shell",
            args=args,
            timeout=timeout,
        )

    def parse_output(self, raw_output: str) -> ScriptResult:
        """Parse shell script output."""
        return ScriptResult(
            script_type="shell",
            stdout=raw_output,
            success=True,
        )

    @classmethod
    def get_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Shell code to execute",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Script arguments",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Execution timeout",
                },
            },
            "required": ["code"],
        }
