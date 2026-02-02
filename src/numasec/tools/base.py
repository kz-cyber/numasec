"""
NumaSec - Tool Base Classes

Abstract base classes and types for security tool wrappers.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field


# ══════════════════════════════════════════════════════════════════════════════
# Enums
# ══════════════════════════════════════════════════════════════════════════════


class ToolRisk(str, Enum):
    """Risk level for security tools."""

    LOW = "low"  # Read-only, passive (nmap, httpx)
    MEDIUM = "medium"  # Active scanning (nuclei, ffuf)
    HIGH = "high"  # Intrusive testing (sqlmap)
    CRITICAL = "critical"  # Exploitation (hydra, scripts)


class ToolCategory(str, Enum):
    """Tool categories."""

    RECONNAISSANCE = "reconnaissance"
    WEB_APPLICATION = "web_application"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    UTILITY = "utility"


class ToolStatus(str, Enum):
    """Tool execution status."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


# ══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class ToolMetadata:
    """Metadata for a security tool."""

    name: str
    description: str
    category: ToolCategory
    risk: ToolRisk
    command: str  # Base command (e.g., "nmap", "nuclei")
    version: str | None = None
    installed: bool = True
    requires_root: bool = False
    output_format: str = "json"  # json, xml, text
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "risk": self.risk.value,
            "command": self.command,
            "version": self.version,
            "installed": self.installed,
            "requires_root": self.requires_root,
            "output_format": self.output_format,
            "tags": self.tags,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Result Models
# ══════════════════════════════════════════════════════════════════════════════

T = TypeVar("T")


class ToolResult(BaseModel, Generic[T]):
    """Result from a tool execution."""
    
    model_config = ConfigDict(arbitrary_types_allowed=True)

    tool_name: str
    status: ToolStatus
    data: T | None = None
    raw_output: str = ""
    error: str | None = None
    command: str = ""
    exit_code: int = 0
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    duration_ms: float = 0

    @property
    def success(self) -> bool:
        """Check if execution was successful."""
        return self.status == ToolStatus.SUCCESS

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool_name": self.tool_name,
            "status": self.status.value,
            "data": self.data.model_dump() if hasattr(self.data, "model_dump") else self.data,
            "error": self.error,
            "command": self.command,
            "exit_code": self.exit_code,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


class ToolError(BaseModel):
    """Error from tool execution."""

    tool_name: str
    error_type: str
    message: str
    command: str = ""
    exit_code: int = 1
    stderr: str = ""
    suggestion: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool_name": self.tool_name,
            "error_type": self.error_type,
            "message": self.message,
            "command": self.command,
            "exit_code": self.exit_code,
            "stderr": self.stderr,
            "suggestion": self.suggestion,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Base Tool Class
# ══════════════════════════════════════════════════════════════════════════════


class BaseTool(ABC, Generic[T]):
    """
    Abstract base class for security tool wrappers.

    All tool wrappers should inherit from this class and implement:
    - execute(): Run the tool and return structured result
    - parse_output(): Parse raw output into structured data
    - get_schema(): Return JSON schema for tool parameters
    """

    # Tool metadata (override in subclasses)
    name: str = "base_tool"
    description: str = "Base tool"
    category: ToolCategory = ToolCategory.UTILITY
    risk: ToolRisk = ToolRisk.LOW
    command: str = ""

    def __init__(self) -> None:
        """Initialize the tool."""
        self._metadata: ToolMetadata | None = None

    @property
    def metadata(self) -> ToolMetadata:
        """Get tool metadata."""
        if self._metadata is None:
            self._metadata = ToolMetadata(
                name=self.name,
                description=self.description,
                category=self.category,
                risk=self.risk,
                command=self.command,
            )
        return self._metadata

    @abstractmethod
    async def execute(self, **kwargs: Any) -> ToolResult[T]:
        """
        Execute the tool with given parameters.

        Args:
            **kwargs: Tool-specific parameters

        Returns:
            ToolResult with structured data
        """
        pass

    @abstractmethod
    def parse_output(self, raw_output: str) -> T:
        """
        Parse raw tool output into structured data.

        Args:
            raw_output: Raw stdout from tool

        Returns:
            Parsed structured data
        """
        pass

    @classmethod
    def get_schema(cls) -> dict[str, Any]:
        """
        Get JSON schema for tool parameters.

        Override in subclasses to define parameters.
        """
        return {
            "type": "object",
            "properties": {},
            "required": [],
        }

    @classmethod
    def get_mcp_tool_definition(cls) -> dict[str, Any]:
        """Get MCP tool definition."""
        return {
            "name": cls.name,
            "description": cls.description,
            "inputSchema": cls.get_schema(),
        }

    def validate_params(self, **kwargs: Any) -> tuple[bool, str | None]:
        """
        Validate tool parameters.

        Returns:
            (valid, error_message)
        """
        # Default: accept all params
        return True, None

    async def check_installed(self) -> bool:
        """Check if the tool is installed."""
        import shutil
        return shutil.which(self.command) is not None

    def build_command(self, **kwargs: Any) -> list[str]:
        """
        Build command line arguments.

        Override in subclasses for tool-specific logic.
        """
        return [self.command]

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name}, risk={self.risk.value})>"


# ══════════════════════════════════════════════════════════════════════════════
# Common Output Models
# ══════════════════════════════════════════════════════════════════════════════


class Port(BaseModel):
    """Port information."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""


class Host(BaseModel):
    """Host information."""

    ip: str
    hostname: str = ""
    state: str = "up"
    os: str = ""
    ports: list[Port] = Field(default_factory=list)


class Vulnerability(BaseModel):
    """Vulnerability found by scanner."""

    id: str
    name: str
    severity: str
    description: str = ""
    url: str = ""
    template: str = ""
    matched: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HTTPResponse(BaseModel):
    """HTTP response data."""

    url: str
    status_code: int
    content_type: str = ""
    content_length: int = 0
    title: str = ""
    server: str = ""
    technologies: list[str] = Field(default_factory=list)
    body: str = ""


class FuzzResult(BaseModel):
    """Fuzzing result."""

    url: str
    status_code: int
    content_length: int
    words: int = 0
    lines: int = 0
    input_value: str = ""
    position: str = ""


class Credential(BaseModel):
    """Credential from brute force."""

    host: str
    port: int
    service: str
    username: str
    password: str
    valid: bool = True
