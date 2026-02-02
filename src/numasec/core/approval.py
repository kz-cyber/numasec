"""
NumaSec - Approval Gateway

Human-in-the-loop approval system for tool execution.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable
from uuid import uuid4


# ══════════════════════════════════════════════════════════════════════════════
# Enums
# ══════════════════════════════════════════════════════════════════════════════


class ApprovalMode(str, Enum):
    """Approval mode for tool execution."""

    SUPERVISED = "supervised"  # Approve everything
    SEMI_AUTO = "semi_auto"  # Auto-approve LOW risk, prompt for others
    AUTONOMOUS = "autonomous"  # No approval needed (training/lab mode only!)


class ApprovalDecision(str, Enum):
    """User's decision on approval request."""

    APPROVED = "approved"
    DENIED = "denied"
    SKIPPED = "skipped"
    MODIFIED = "modified"  # Approved with modifications
    TIMEOUT = "timeout"


# ══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class ApprovalRequest:
    """A request for human approval."""

    id: str
    tool_name: str
    action_description: str
    targets: list[str]
    risk_level: str
    parameters: dict[str, Any]
    reasoning: str
    created_at: datetime = field(default_factory=datetime.utcnow)

    # Set when processed
    decision: ApprovalDecision | None = None
    decided_at: datetime | None = None
    modified_params: dict[str, Any] | None = None
    denial_reason: str | None = None


@dataclass
class ApprovalStats:
    """Statistics for approvals."""

    total_requests: int = 0
    approved: int = 0
    denied: int = 0
    auto_approved: int = 0
    avg_response_time_ms: float = 0


# ══════════════════════════════════════════════════════════════════════════════
# Approval Gateway
# ══════════════════════════════════════════════════════════════════════════════


# Callback type for approval prompts
ApprovalCallback = Callable[[ApprovalRequest], ApprovalDecision]


class ApprovalGateway:
    """
    Human-in-the-loop approval system.

    Controls which tool executions require human approval based on:
    - Risk level (LOW, MEDIUM, HIGH, CRITICAL)
    - Approval mode (SUPERVISED, SEMI_AUTO, AUTONOMOUS)
    - Tool type
    """

    def __init__(
        self,
        mode: ApprovalMode = ApprovalMode.SEMI_AUTO,
        callback: ApprovalCallback | None = None,
    ) -> None:
        """
        Initialize gateway.

        Args:
            mode: Approval mode
            callback: Function to call for approval prompts
        """
        self._mode = mode
        self._callback = callback
        self._pending: dict[str, ApprovalRequest] = {}
        self._history: list[ApprovalRequest] = []
        self._timeout_seconds = 300  # 5 minute default timeout
        self._auto_deny_high_risk = False

    @property
    def mode(self) -> ApprovalMode:
        """Get current approval mode."""
        return self._mode

    @mode.setter
    def mode(self, value: ApprovalMode) -> None:
        """Set approval mode."""
        self._mode = value

    @property
    def timeout(self) -> int:
        """Get timeout in seconds."""
        return self._timeout_seconds

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Set timeout."""
        self._timeout_seconds = value

    def set_callback(self, callback: ApprovalCallback) -> None:
        """Set the approval callback function."""
        self._callback = callback

    def requires_approval(self, tool_name: str, risk_level: str) -> bool:
        """
        Check if a tool execution requires approval.

        Args:
            tool_name: Name of the tool
            risk_level: Risk level (low, medium, high, critical)

        Returns:
            True if approval is required
        """
        if self._mode == ApprovalMode.AUTONOMOUS:
            return False

        if self._mode == ApprovalMode.SUPERVISED:
            return True

        # SEMI_AUTO mode: approve LOW risk automatically
        if self._mode == ApprovalMode.SEMI_AUTO:
            return risk_level.lower() not in ["low"]

        return True

    async def request_approval(
        self,
        tool_name: str,
        action_description: str,
        targets: list[str],
        risk_level: str,
        parameters: dict[str, Any],
        reasoning: str = "",
    ) -> ApprovalRequest:
        """
        Request human approval for an action.

        Args:
            tool_name: Name of the tool
            action_description: What the tool will do
            targets: Target hosts/URLs
            risk_level: Risk level
            parameters: Tool parameters
            reasoning: AI's reasoning for this action

        Returns:
            ApprovalRequest with decision
        """
        request = ApprovalRequest(
            id=str(uuid4()),
            tool_name=tool_name,
            action_description=action_description,
            targets=targets,
            risk_level=risk_level,
            parameters=parameters,
            reasoning=reasoning,
        )

        # Auto-approve in autonomous mode
        if self._mode == ApprovalMode.AUTONOMOUS:
            request.decision = ApprovalDecision.APPROVED
            request.decided_at = datetime.now(timezone.utc)
            self._history.append(request)
            return request

        # Auto-approve low risk in semi-auto
        if self._mode == ApprovalMode.SEMI_AUTO and risk_level.lower() == "low":
            request.decision = ApprovalDecision.APPROVED
            request.decided_at = datetime.now(timezone.utc)
            self._history.append(request)
            return request

        # Add to pending
        self._pending[request.id] = request

        # Call callback if available
        if self._callback:
            try:
                decision = self._callback(request)
                request.decision = decision
            except Exception:
                request.decision = ApprovalDecision.DENIED
                request.denial_reason = "Callback error"
        else:
            # No callback, wait for manual decision
            # In real implementation, this would wait for UI input
            request.decision = ApprovalDecision.TIMEOUT

        request.decided_at = datetime.now(timezone.utc)
        del self._pending[request.id]
        self._history.append(request)

        return request

    def approve(
        self,
        request_id: str,
        modified_params: dict[str, Any] | None = None,
    ) -> bool:
        """
        Approve a pending request.

        Args:
            request_id: Request ID to approve
            modified_params: Optional modified parameters

        Returns:
            True if request was found and approved
        """
        request = self._pending.get(request_id)
        if not request:
            return False

        if modified_params:
            request.decision = ApprovalDecision.MODIFIED
            request.modified_params = modified_params
        else:
            request.decision = ApprovalDecision.APPROVED

        request.decided_at = datetime.now(timezone.utc)
        return True

    def deny(self, request_id: str, reason: str = "") -> bool:
        """
        Deny a pending request.

        Args:
            request_id: Request ID to deny
            reason: Reason for denial

        Returns:
            True if request was found and denied
        """
        request = self._pending.get(request_id)
        if not request:
            return False

        request.decision = ApprovalDecision.DENIED
        request.denial_reason = reason
        request.decided_at = datetime.now(timezone.utc)
        return True

    def get_pending(self) -> list[ApprovalRequest]:
        """Get all pending approval requests."""
        return list(self._pending.values())

    def get_history(self, limit: int = 100) -> list[ApprovalRequest]:
        """Get approval history."""
        return self._history[-limit:]

    def get_stats(self) -> ApprovalStats:
        """Get approval statistics."""
        total = len(self._history)
        approved = sum(
            1 for r in self._history
            if r.decision in [ApprovalDecision.APPROVED, ApprovalDecision.MODIFIED]
        )
        denied = sum(
            1 for r in self._history
            if r.decision == ApprovalDecision.DENIED
        )
        auto_approved = sum(
            1 for r in self._history
            if r.decision == ApprovalDecision.APPROVED and r.risk_level.lower() == "low"
        )

        # Calculate average response time
        response_times = []
        for r in self._history:
            if r.decided_at and r.created_at:
                delta = (r.decided_at - r.created_at).total_seconds() * 1000
                response_times.append(delta)

        avg_time = sum(response_times) / len(response_times) if response_times else 0

        return ApprovalStats(
            total_requests=total,
            approved=approved,
            denied=denied,
            auto_approved=auto_approved,
            avg_response_time_ms=avg_time,
        )

    def clear_history(self) -> None:
        """Clear approval history."""
        self._history.clear()


# Global instance
_gateway: ApprovalGateway | None = None


def get_approval_gateway() -> ApprovalGateway:
    """Get the global approval gateway."""
    global _gateway
    if _gateway is None:
        _gateway = ApprovalGateway()
    return _gateway


# ══════════════════════════════════════════════════════════════════════════════
# CLI Approval Callback
# ══════════════════════════════════════════════════════════════════════════════


def cli_approval_callback(request: ApprovalRequest) -> ApprovalDecision:
    """
    Simple CLI-based approval callback.

    Prints request details and waits for user input.
    """
    print("\n" + "=" * 60)
    print("🔐 APPROVAL REQUIRED")
    print("=" * 60)
    print(f"Tool: {request.tool_name}")
    print(f"Risk: {request.risk_level.upper()}")
    print(f"Description: {request.action_description}")
    print(f"Targets: {', '.join(request.targets)}")
    print(f"\nReasoning: {request.reasoning}")
    print(f"\nParameters:")
    for key, value in request.parameters.items():
        print(f"  {key}: {value}")
    print("-" * 60)

    while True:
        response = input("Approve? [y/n/s(kip)]: ").strip().lower()

        if response in ["y", "yes"]:
            return ApprovalDecision.APPROVED
        elif response in ["n", "no"]:
            return ApprovalDecision.DENIED
        elif response in ["s", "skip"]:
            return ApprovalDecision.SKIPPED
        else:
            print("Please enter 'y', 'n', or 's'")
