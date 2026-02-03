"""
Audit Repository - Data access layer for action logs.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from numasec.data.models import (
    ActionLog,
    ActionType,
    ApprovalDecision,
    PTESPhase,
    ToolRisk,
)


class AuditRepository:
    """Repository for audit log operations with hash-chain integrity."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self._last_hash: str | None = None

    async def _get_last_hash(self, engagement_id: str | None) -> str | None:
        """Get the hash of the last audit entry."""
        query = (
            select(ActionLog.entry_hash)
            .order_by(ActionLog.timestamp.desc())
            .limit(1)
        )

        if engagement_id is not None:
            query = query.where(ActionLog.engagement_id == engagement_id)

        result = await self.session.execute(query)
        row = result.scalar_one_or_none()
        return row

    def _compute_hash(
        self,
        action_type: ActionType,
        action: str,
        timestamp: datetime,
        previous_hash: str | None,
        metadata: dict | None,
    ) -> str:
        """Compute SHA-256 hash for hash chain."""
        data = {
            "action_type": action_type.value,
            "action": action,
            "timestamp": timestamp.isoformat(),
            "previous_hash": previous_hash or "genesis",
            "metadata": metadata or {},
        }
        serialized = json.dumps(data, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()

    async def log(
        self,
        action_type: ActionType,
        action: str,
        engagement_id: str | None = None,
        tool: str | None = None,
        target: str | None = None,
        success: bool = True,
        result_summary: str | None = None,
        error_message: str | None = None,
        user_approved: bool = True,
        approval_decision: ApprovalDecision | None = None,
        approval_reason: str | None = None,
        tool_risk: ToolRisk | None = None,
        ptes_phase: PTESPhase | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ActionLog:
        """
        Create an audit log entry with hash chain.

        The hash chain ensures log integrity - any tampering
        would break the chain and be detectable.
        """
        # Get previous hash
        previous_hash = await self._get_last_hash(engagement_id)

        timestamp = datetime.now(timezone.utc)

        # Compute entry hash
        entry_hash = self._compute_hash(
            action_type=action_type,
            action=action,
            timestamp=timestamp,
            previous_hash=previous_hash,
            metadata=metadata,
        )

        # Create entry
        log_entry = ActionLog(
            engagement_id=engagement_id,
            action_type=action_type,
            action=action,
            tool=tool,
            target=target,
            success=success,
            result_summary=result_summary,
            error_message=error_message,
            user_approved=user_approved,
            approval_decision=approval_decision,
            approval_reason=approval_reason,
            tool_risk=tool_risk,
            ptes_phase=ptes_phase,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            timestamp=timestamp,
            metadata=metadata or {},
        )

        self.session.add(log_entry)
        await self.session.flush()

        self._last_hash = entry_hash
        return log_entry

    async def get_by_engagement(
        self,
        engagement_id: str,
        action_type: ActionType | None = None,
        limit: int = 1000,
    ) -> Sequence[ActionLog]:
        """Get audit logs for an engagement."""
        query = (
            select(ActionLog)
            .where(ActionLog.engagement_id == engagement_id)
            .order_by(ActionLog.timestamp.desc())
        )

        if action_type is not None:
            query = query.where(ActionLog.action_type == action_type)

        query = query.limit(limit)
        result = await self.session.execute(query)
        return result.scalars().all()

    async def verify_chain(self, engagement_id: str | None = None) -> bool:
        """
        Verify the integrity of the hash chain.

        Returns True if chain is intact, False if tampered.
        """
        query = select(ActionLog).order_by(ActionLog.timestamp.asc())

        if engagement_id is not None:
            query = query.where(ActionLog.engagement_id == engagement_id)

        result = await self.session.execute(query)
        entries = result.scalars().all()

        if not entries:
            return True

        previous_hash = None
        for entry in entries:
            # Verify previous hash link
            if entry.previous_hash != previous_hash:
                return False

            # Verify entry hash
            expected_hash = self._compute_hash(
                action_type=entry.action_type,
                action=entry.action,
                timestamp=entry.timestamp,
                previous_hash=entry.previous_hash,
                metadata=entry.metadata,
            )
            if entry.entry_hash != expected_hash:
                return False

            previous_hash = entry.entry_hash

        return True

    async def get_tool_executions(
        self,
        engagement_id: str,
        tool: str | None = None,
    ) -> Sequence[ActionLog]:
        """Get tool execution logs."""
        query = (
            select(ActionLog)
            .where(ActionLog.engagement_id == engagement_id)
            .where(ActionLog.action_type == ActionType.TOOL_EXECUTION)
            .order_by(ActionLog.timestamp.desc())
        )

        if tool is not None:
            query = query.where(ActionLog.tool == tool)

        result = await self.session.execute(query)
        return result.scalars().all()

    async def get_approvals(
        self,
        engagement_id: str,
    ) -> Sequence[ActionLog]:
        """Get approval decision logs."""
        query = (
            select(ActionLog)
            .where(ActionLog.engagement_id == engagement_id)
            .where(ActionLog.action_type == ActionType.APPROVAL)
            .order_by(ActionLog.timestamp.desc())
        )
        result = await self.session.execute(query)
        return result.scalars().all()
