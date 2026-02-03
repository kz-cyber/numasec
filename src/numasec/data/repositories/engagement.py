"""
Engagement Repository - Data access layer for engagements.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from numasec.data.models import (
    Engagement,
    EngagementStatus,
    PTESPhase,
    ScopeEntry,
)


class EngagementRepository:
    """Repository for engagement CRUD operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        client_name: str,
        project_name: str,
        methodology: str = "PTES",
        approval_mode: str = "supervised",
        metadata: dict | None = None,
    ) -> Engagement:
        """Create a new engagement."""
        engagement = Engagement(
            client_name=client_name,
            project_name=project_name,
            methodology=methodology,
            approval_mode=approval_mode,
            status=EngagementStatus.DRAFT,
            current_phase=PTESPhase.PRE_ENGAGEMENT,
            metadata=metadata or {},
        )
        self.session.add(engagement)
        await self.session.flush()
        return engagement

    async def get_by_id(
        self, engagement_id: str, include_relations: bool = True
    ) -> Engagement | None:
        """Get engagement by ID."""
        query = select(Engagement).where(Engagement.id == engagement_id)

        if include_relations:
            query = query.options(
                selectinload(Engagement.scope_entries),
                selectinload(Engagement.findings),
            )

        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_active(self) -> Engagement | None:
        """Get the currently active engagement."""
        query = (
            select(Engagement)
            .where(Engagement.status == EngagementStatus.ACTIVE)
            .order_by(Engagement.updated_at.desc())
            .options(selectinload(Engagement.scope_entries))
            .limit(1)
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def list_all(
        self,
        status: EngagementStatus | None = None,
        limit: int = 100,
    ) -> Sequence[Engagement]:
        """List all engagements."""
        query = select(Engagement).order_by(Engagement.created_at.desc())

        if status is not None:
            query = query.where(Engagement.status == status)

        query = query.limit(limit)
        result = await self.session.execute(query)
        return result.scalars().all()

    async def update_status(
        self,
        engagement_id: str,
        status: EngagementStatus,
    ) -> bool:
        """Update engagement status."""
        stmt = (
            update(Engagement)
            .where(Engagement.id == engagement_id)
            .values(status=status, updated_at=datetime.now(timezone.utc))
        )
        result = await self.session.execute(stmt)
        return result.rowcount > 0

    async def update_phase(
        self,
        engagement_id: str,
        phase: PTESPhase,
    ) -> bool:
        """Update current PTES phase."""
        stmt = (
            update(Engagement)
            .where(Engagement.id == engagement_id)
            .values(current_phase=phase, updated_at=datetime.now(timezone.utc))
        )
        result = await self.session.execute(stmt)
        return result.rowcount > 0

    async def add_scope_entry(
        self,
        engagement_id: str,
        target: str,
        scope_type: str,
        is_excluded: bool = False,
        description: str | None = None,
    ) -> ScopeEntry:
        """Add scope entry to engagement."""
        from numasec.data.models import ScopeType

        entry = ScopeEntry(
            engagement_id=engagement_id,
            target=target,
            scope_type=ScopeType(scope_type),
            is_excluded=is_excluded,
            description=description,
        )
        self.session.add(entry)
        await self.session.flush()
        return entry

    async def close(
        self,
        engagement_id: str,
    ) -> bool:
        """Close an engagement."""
        stmt = (
            update(Engagement)
            .where(Engagement.id == engagement_id)
            .values(
                status=EngagementStatus.COMPLETE,
                end_date=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )
        result = await self.session.execute(stmt)
        return result.rowcount > 0

    async def delete(self, engagement_id: str) -> bool:
        """Delete an engagement and all related data."""
        engagement = await self.get_by_id(engagement_id, include_relations=False)
        if engagement is None:
            return False

        await self.session.delete(engagement)
        return True
