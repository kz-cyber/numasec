"""
NumaSec - Audit Logger

Immutable hash-chain audit log for all actions.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
# Enums
# ══════════════════════════════════════════════════════════════════════════════


class AuditAction(str, Enum):
    """Types of auditable actions."""

    # Engagement
    ENGAGEMENT_CREATED = "engagement_created"
    ENGAGEMENT_ACTIVATED = "engagement_activated"
    ENGAGEMENT_COMPLETED = "engagement_completed"
    PHASE_ADVANCED = "phase_advanced"

    # Scope
    SCOPE_ADDED = "scope_added"
    SCOPE_REMOVED = "scope_removed"
    SCOPE_CHECK = "scope_check"

    # Tools
    TOOL_EXECUTED = "tool_executed"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"

    # Approval
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_AUTO = "approval_auto"

    # Findings
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    FINDING_DELETED = "finding_deleted"

    # Reports
    REPORT_GENERATED = "report_generated"
    REPORT_EXPORTED = "report_exported"

    # Safety
    EMERGENCY_STOP = "emergency_stop"
    SAFETY_VIOLATION = "safety_violation"

    # General
    SYSTEM_START = "system_start"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIG_CHANGED = "config_changed"
    ERROR = "error"


# ══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class AuditEntry:
    """A single audit log entry with hash chain."""

    timestamp: datetime
    action: AuditAction
    engagement_id: str | None
    tool: str | None
    target: str | None
    result: str
    user_approved: bool
    data: dict[str, Any]
    previous_hash: str
    hash: str = ""

    def __post_init__(self) -> None:
        """Calculate hash after initialization."""
        if not self.hash:
            self.hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        """Calculate SHA-256 hash for this entry."""
        content = json.dumps(
            {
                "timestamp": self.timestamp.isoformat(),
                "action": self.action.value,
                "engagement_id": self.engagement_id,
                "tool": self.tool,
                "target": self.target,
                "result": self.result,
                "user_approved": self.user_approved,
                "data": self.data,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def verify(self) -> bool:
        """Verify this entry's hash is valid."""
        return self.hash == self._calculate_hash()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action.value,
            "engagement_id": self.engagement_id,
            "tool": self.tool,
            "target": self.target,
            "result": self.result,
            "user_approved": self.user_approved,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEntry":
        """Create from dictionary."""
        entry = cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            action=AuditAction(data["action"]),
            engagement_id=data.get("engagement_id"),
            tool=data.get("tool"),
            target=data.get("target"),
            result=data["result"],
            user_approved=data.get("user_approved", False),
            data=data.get("data", {}),
            previous_hash=data["previous_hash"],
            hash=data["hash"],
        )
        return entry


# ══════════════════════════════════════════════════════════════════════════════
# Audit Logger
# ══════════════════════════════════════════════════════════════════════════════


class AuditLogger:
    """
    Immutable hash-chain audit logger.

    Every action is logged with:
    - Timestamp
    - Action type
    - Engagement context
    - Tool used (if applicable)
    - Target (if applicable)
    - Result
    - Approval status
    - SHA-256 hash linking to previous entry
    """

    # Genesis hash for first entry
    GENESIS_HASH = "0" * 64

    def __init__(self, log_path: Path | None = None) -> None:
        """
        Initialize logger.

        Args:
            log_path: Path to persist audit log
        """
        self._entries: list[AuditEntry] = []
        self._log_path = log_path
        self._last_hash = self.GENESIS_HASH
        self._current_engagement_id: str | None = None

    @property
    def last_hash(self) -> str:
        """Get the hash of the last entry."""
        return self._last_hash

    @property
    def entry_count(self) -> int:
        """Get number of entries."""
        return len(self._entries)

    def set_engagement(self, engagement_id: str | None) -> None:
        """Set the current engagement context."""
        self._current_engagement_id = engagement_id

    def log(
        self,
        action: AuditAction,
        result: str,
        tool: str | None = None,
        target: str | None = None,
        user_approved: bool = False,
        data: dict[str, Any] | None = None,
        engagement_id: str | None = None,
    ) -> AuditEntry:
        """
        Log an action.

        Args:
            action: Type of action
            result: Result description
            tool: Tool name if applicable
            target: Target if applicable
            user_approved: Whether user approved this action
            data: Additional data
            engagement_id: Override engagement ID

        Returns:
            The created AuditEntry
        """
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            action=action,
            engagement_id=engagement_id or self._current_engagement_id,
            tool=tool,
            target=target,
            result=result,
            user_approved=user_approved,
            data=data or {},
            previous_hash=self._last_hash,
        )

        self._entries.append(entry)
        self._last_hash = entry.hash

        # Persist if path configured
        if self._log_path:
            self._persist_entry(entry)

        return entry

    def log_tool_execution(
        self,
        tool_name: str,
        target: str,
        command: str,
        approved: bool,
        params: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Log a tool execution."""
        return self.log(
            action=AuditAction.TOOL_EXECUTED,
            result=f"Executed {tool_name} on {target}",
            tool=tool_name,
            target=target,
            user_approved=approved,
            data={
                "command": command,
                "parameters": params or {},
            },
        )

    def log_tool_completion(
        self,
        tool_name: str,
        target: str,
        exit_code: int,
        duration_ms: float,
        summary: str = "",
    ) -> AuditEntry:
        """Log tool completion."""
        action = AuditAction.TOOL_COMPLETED if exit_code == 0 else AuditAction.TOOL_FAILED
        return self.log(
            action=action,
            result=summary or f"Completed with exit code {exit_code}",
            tool=tool_name,
            target=target,
            data={
                "exit_code": exit_code,
                "duration_ms": duration_ms,
            },
        )

    def log_finding(
        self,
        finding_id: str,
        title: str,
        severity: str,
        action: AuditAction = AuditAction.FINDING_CREATED,
    ) -> AuditEntry:
        """Log a finding action."""
        return self.log(
            action=action,
            result=f"Finding: {title} ({severity})",
            data={
                "finding_id": finding_id,
                "title": title,
                "severity": severity,
            },
        )

    def log_approval(
        self,
        request_id: str,
        tool_name: str,
        target: str,
        decision: str,
        auto: bool = False,
    ) -> AuditEntry:
        """Log an approval decision."""
        if auto:
            action = AuditAction.APPROVAL_AUTO
        elif decision.lower() in ["approved", "modified"]:
            action = AuditAction.APPROVAL_GRANTED
        else:
            action = AuditAction.APPROVAL_DENIED

        return self.log(
            action=action,
            result=f"Approval {decision} for {tool_name}",
            tool=tool_name,
            target=target,
            user_approved=decision.lower() in ["approved", "modified"],
            data={
                "request_id": request_id,
                "decision": decision,
                "auto_approved": auto,
            },
        )

    def log_error(
        self,
        error: str,
        tool: str | None = None,
        target: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Log an error."""
        return self.log(
            action=AuditAction.ERROR,
            result=error,
            tool=tool,
            target=target,
            data=data or {},
        )

    def verify_chain(self) -> tuple[bool, int]:
        """
        Verify the entire hash chain.

        Returns:
            (valid, first_invalid_index)
            If valid, first_invalid_index is -1
        """
        if not self._entries:
            return True, -1

        # First entry should have genesis hash
        if self._entries[0].previous_hash != self.GENESIS_HASH:
            return False, 0

        # Verify each entry
        for i, entry in enumerate(self._entries):
            if not entry.verify():
                return False, i

            # Check chain linkage (except for first)
            if i > 0:
                if entry.previous_hash != self._entries[i - 1].hash:
                    return False, i

        return True, -1

    def get_entries(
        self,
        action: AuditAction | None = None,
        tool: str | None = None,
        engagement_id: str | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """
        Get audit entries with optional filters.

        Args:
            action: Filter by action type
            tool: Filter by tool
            engagement_id: Filter by engagement
            limit: Maximum entries to return

        Returns:
            Filtered list of entries (newest first)
        """
        entries = self._entries.copy()

        if action:
            entries = [e for e in entries if e.action == action]

        if tool:
            entries = [e for e in entries if e.tool == tool]

        if engagement_id:
            entries = [e for e in entries if e.engagement_id == engagement_id]

        return list(reversed(entries[-limit:]))

    def _persist_entry(self, entry: AuditEntry) -> None:
        """Persist entry to log file."""
        if not self._log_path:
            return

        self._log_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self._log_path, "a") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")

    def load(self) -> None:
        """Load entries from log file."""
        if not self._log_path or not self._log_path.exists():
            return

        self._entries.clear()

        with open(self._log_path) as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    entry = AuditEntry.from_dict(data)
                    self._entries.append(entry)

        if self._entries:
            self._last_hash = self._entries[-1].hash

    def export(self, output_path: Path, format: str = "json") -> None:
        """Export audit log."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            with open(output_path, "w") as f:
                json.dump([e.to_dict() for e in self._entries], f, indent=2)


# Global instance
_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger."""
    global _logger
    if _logger is None:
        _logger = AuditLogger()
    return _logger


def configure_audit_logger(log_path: Path) -> AuditLogger:
    """Configure the global audit logger with a log path."""
    global _logger
    _logger = AuditLogger(log_path)
    _logger.load()  # Load existing entries
    return _logger
