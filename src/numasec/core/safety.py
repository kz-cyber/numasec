"""
NumaSec - Safety Controller

Emergency stop and safety controls for penetration testing.
"""

from __future__ import annotations

import signal
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


# ══════════════════════════════════════════════════════════════════════════════
# Enums
# ══════════════════════════════════════════════════════════════════════════════


class SafetyState(str, Enum):
    """Safety system state."""

    ACTIVE = "active"  # Normal operation
    PAUSED = "paused"  # Temporarily paused
    EMERGENCY_STOP = "emergency_stop"  # All operations halted
    SHUTDOWN = "shutdown"  # System shutting down


class SafetyViolationType(str, Enum):
    """Types of safety violations."""

    SCOPE_VIOLATION = "scope_violation"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    DANGEROUS_COMMAND = "dangerous_command"
    UNAUTHORIZED_TARGET = "unauthorized_target"
    SYSTEM_RESOURCE = "system_resource"
    NETWORK_ERROR = "network_error"
    TOOL_CRASH = "tool_crash"


# ══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class SafetyViolation:
    """A recorded safety violation."""

    timestamp: datetime
    violation_type: SafetyViolationType
    severity: str  # low, medium, high, critical
    description: str
    tool: str | None = None
    target: str | None = None
    action_taken: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class SafetyConfig:
    """Safety system configuration."""

    # Rate limits
    max_requests_per_minute: int = 60
    max_concurrent_tools: int = 5

    # Automatic triggers
    auto_pause_on_error_count: int = 5
    auto_stop_on_scope_violation: bool = True

    # Dangerous patterns to block
    blocked_patterns: list[str] = field(default_factory=lambda: [
        "rm -rf /",
        ":(){ :|:& };:",  # Fork bomb
        "> /dev/sd",  # Disk write
        "dd if=/dev/zero",
        "mkfs.",
    ])

    # Protected networks
    protected_networks: list[str] = field(default_factory=lambda: [
        "127.0.0.0/8",  # Localhost
        "10.0.0.0/8",  # Private (unless explicitly scoped)
        "172.16.0.0/12",  # Private
        "192.168.0.0/16",  # Private
    ])


# ══════════════════════════════════════════════════════════════════════════════
# Safety Controller
# ══════════════════════════════════════════════════════════════════════════════


# Callback type for safety events
SafetyCallback = Callable[[str, dict[str, Any]], None]


class SafetyController:
    """
    Emergency stop and safety controls.

    Responsibilities:
    - Emergency stop functionality
    - Rate limiting
    - Dangerous command detection
    - Safety violation tracking
    - System pause/resume
    """

    def __init__(self, config: SafetyConfig | None = None) -> None:
        """Initialize controller."""
        self._config = config or SafetyConfig()
        self._state = SafetyState.ACTIVE
        self._violations: list[SafetyViolation] = []
        self._error_count = 0
        self._request_count = 0
        self._last_request_window = datetime.now(timezone.utc)
        self._active_tools: set[str] = set()
        self._callbacks: list[SafetyCallback] = []
        self._shutdown_handlers: list[Callable[[], None]] = []

        # Register signal handlers
        self._setup_signal_handlers()

    @property
    def state(self) -> SafetyState:
        """Get current safety state."""
        return self._state

    @property
    def is_operational(self) -> bool:
        """Check if system is operational."""
        return self._state == SafetyState.ACTIVE

    @property
    def is_paused(self) -> bool:
        """Check if system is paused."""
        return self._state == SafetyState.PAUSED

    @property
    def is_stopped(self) -> bool:
        """Check if emergency stop is active."""
        return self._state == SafetyState.EMERGENCY_STOP

    def add_callback(self, callback: SafetyCallback) -> None:
        """Add a callback for safety events."""
        self._callbacks.append(callback)

    def add_shutdown_handler(self, handler: Callable[[], None]) -> None:
        """Add a shutdown handler."""
        self._shutdown_handlers.append(handler)

    def _notify(self, event: str, data: dict[str, Any]) -> None:
        """Notify all callbacks of an event."""
        for callback in self._callbacks:
            try:
                callback(event, data)
            except Exception:
                pass  # Don't let callbacks break safety system

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for emergency stop."""
        def handle_sigint(signum: int, frame: Any) -> None:
            self.emergency_stop("SIGINT received")

        def handle_sigterm(signum: int, frame: Any) -> None:
            self.emergency_stop("SIGTERM received")

        try:
            signal.signal(signal.SIGINT, handle_sigint)
            signal.signal(signal.SIGTERM, handle_sigterm)
        except (ValueError, OSError):
            # Can't set signal handlers in some contexts
            pass

    def emergency_stop(self, reason: str = "Manual trigger") -> None:
        """
        Trigger emergency stop.

        Halts all operations immediately.
        """
        self._state = SafetyState.EMERGENCY_STOP

        violation = SafetyViolation(
            timestamp=datetime.now(timezone.utc),
            violation_type=SafetyViolationType.SCOPE_VIOLATION,
            severity="critical",
            description=f"Emergency stop triggered: {reason}",
            action_taken="All operations halted",
        )
        self._violations.append(violation)

        self._notify("emergency_stop", {"reason": reason})

        # Clear active tools
        self._active_tools.clear()

    def pause(self, reason: str = "") -> None:
        """Pause all operations."""
        if self._state == SafetyState.ACTIVE:
            self._state = SafetyState.PAUSED
            self._notify("paused", {"reason": reason})

    def resume(self) -> bool:
        """Resume operations from pause."""
        if self._state == SafetyState.PAUSED:
            self._state = SafetyState.ACTIVE
            self._notify("resumed", {})
            return True
        return False

    def reset(self) -> None:
        """Reset from emergency stop (requires explicit action)."""
        self._state = SafetyState.ACTIVE
        self._error_count = 0
        self._request_count = 0
        self._notify("reset", {})

    def check_rate_limit(self) -> tuple[bool, str]:
        """
        Check if rate limit allows another request.

        Returns:
            (allowed, reason)
        """
        now = datetime.now(timezone.utc)

        # Reset window if needed
        elapsed = (now - self._last_request_window).total_seconds()
        if elapsed >= 60:
            self._request_count = 0
            self._last_request_window = now

        if self._request_count >= self._config.max_requests_per_minute:
            self._record_violation(
                SafetyViolationType.RATE_LIMIT_EXCEEDED,
                "medium",
                f"Rate limit exceeded: {self._request_count}/min",
            )
            return False, f"Rate limit exceeded ({self._config.max_requests_per_minute}/min)"

        self._request_count += 1
        return True, "OK"

    def check_concurrent_limit(self, tool_name: str) -> tuple[bool, str]:
        """
        Check if concurrent tool limit allows another tool.

        Args:
            tool_name: Name of tool to start

        Returns:
            (allowed, reason)
        """
        if len(self._active_tools) >= self._config.max_concurrent_tools:
            return False, f"Concurrent limit exceeded ({self._config.max_concurrent_tools})"

        self._active_tools.add(tool_name)
        return True, "OK"

    def release_tool(self, tool_name: str) -> None:
        """Release a tool from active set."""
        self._active_tools.discard(tool_name)

    def check_command(self, command: str) -> tuple[bool, str]:
        """
        Check if a command is safe to execute.

        Args:
            command: The command to check

        Returns:
            (safe, reason)
        """
        command_lower = command.lower()

        for pattern in self._config.blocked_patterns:
            if pattern.lower() in command_lower:
                self._record_violation(
                    SafetyViolationType.DANGEROUS_COMMAND,
                    "critical",
                    f"Blocked dangerous pattern: {pattern}",
                    action_taken="Command blocked",
                    data={"command": command[:200]},
                )
                return False, f"Dangerous pattern detected: {pattern}"

        return True, "OK"

    def record_error(self, error: str, tool: str | None = None) -> None:
        """Record an error and check thresholds."""
        self._error_count += 1

        if self._error_count >= self._config.auto_pause_on_error_count:
            self.pause(f"Error threshold reached: {self._error_count} errors")

    def record_scope_violation(
        self,
        target: str,
        tool: str | None = None,
    ) -> None:
        """Record a scope violation."""
        self._record_violation(
            SafetyViolationType.SCOPE_VIOLATION,
            "high",
            f"Scope violation for target: {target}",
            tool=tool,
            target=target,
            action_taken="Action blocked",
        )

        if self._config.auto_stop_on_scope_violation:
            self.emergency_stop(f"Scope violation: {target}")

    def _record_violation(
        self,
        violation_type: SafetyViolationType,
        severity: str,
        description: str,
        tool: str | None = None,
        target: str | None = None,
        action_taken: str = "",
        data: dict[str, Any] | None = None,
    ) -> SafetyViolation:
        """Record a safety violation."""
        violation = SafetyViolation(
            timestamp=datetime.now(timezone.utc),
            violation_type=violation_type,
            severity=severity,
            description=description,
            tool=tool,
            target=target,
            action_taken=action_taken,
            data=data or {},
        )
        self._violations.append(violation)
        self._notify("violation", {"violation": violation})
        return violation

    def get_violations(
        self,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[SafetyViolation]:
        """Get recorded violations."""
        violations = self._violations.copy()

        if severity:
            violations = [v for v in violations if v.severity == severity]

        return list(reversed(violations[-limit:]))

    def get_status(self) -> dict[str, Any]:
        """Get safety system status."""
        return {
            "state": self._state.value,
            "is_operational": self.is_operational,
            "error_count": self._error_count,
            "request_count": self._request_count,
            "active_tools": list(self._active_tools),
            "violation_count": len(self._violations),
            "recent_violations": [
                {
                    "type": v.violation_type.value,
                    "severity": v.severity,
                    "description": v.description,
                }
                for v in self._violations[-5:]
            ],
        }

    def shutdown(self) -> None:
        """Graceful shutdown."""
        self._state = SafetyState.SHUTDOWN

        # Call shutdown handlers
        for handler in self._shutdown_handlers:
            try:
                handler()
            except Exception:
                pass

        self._notify("shutdown", {})


# Global instance
_controller: SafetyController | None = None


def get_safety_controller() -> SafetyController:
    """Get the global safety controller."""
    global _controller
    if _controller is None:
        _controller = SafetyController()
    return _controller


def emergency_stop(reason: str = "Manual trigger") -> None:
    """Trigger emergency stop on global controller."""
    get_safety_controller().emergency_stop(reason)
