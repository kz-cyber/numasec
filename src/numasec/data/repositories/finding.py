"""
Finding Repository - Data access layer for security findings.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from numasec.data.models import (
    AffectedAsset,
    Evidence,
    EvidenceType,
    Finding,
    Severity,
)


class FindingRepository:
    """Repository for finding CRUD operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        engagement_id: str,
        title: str,
        severity: Severity,
        description: str,
        cvss_score: float = 0.0,
        cvss_vector: str = "",
        cwe_id: str = "",
        cwe_name: str = "",
        impact: str = "",
        remediation: str = "",
        affected_asset: str = "",
        affected_component: str = "",
        ai_generated: bool = False,
        metadata: dict | None = None,
    ) -> Finding:
        """Create a new finding."""
        finding = Finding(
            engagement_id=engagement_id,
            title=title,
            severity=severity,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            impact=impact,
            remediation=remediation,
            affected_asset=affected_asset,
            affected_component=affected_component,
            ai_generated=ai_generated,
            metadata=metadata or {},
        )
        self.session.add(finding)
        await self.session.flush()
        return finding

    async def get_by_id(
        self, finding_id: str, include_evidence: bool = True
    ) -> Finding | None:
        """Get finding by ID."""
        query = select(Finding).where(Finding.id == finding_id)

        if include_evidence:
            query = query.options(
                selectinload(Finding.evidence),
                selectinload(Finding.affected_assets),
            )

        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def list_by_engagement(
        self,
        engagement_id: str,
        severity: Severity | None = None,
        include_false_positives: bool = False,
    ) -> Sequence[Finding]:
        """List findings for an engagement."""
        query = (
            select(Finding)
            .where(Finding.engagement_id == engagement_id)
            .order_by(Finding.cvss_score.desc(), Finding.created_at.desc())
        )

        if severity is not None:
            query = query.where(Finding.severity == severity)

        if not include_false_positives:
            query = query.where(Finding.is_false_positive == False)

        result = await self.session.execute(query)
        return result.scalars().all()

    async def get_severity_counts(
        self, engagement_id: str
    ) -> dict[str, int]:
        """Get finding counts by severity."""
        query = (
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.engagement_id == engagement_id)
            .where(Finding.is_false_positive == False)
            .group_by(Finding.severity)
        )
        result = await self.session.execute(query)

        counts = {s.value: 0 for s in Severity}
        for severity, count in result:
            counts[severity.value] = count

        return counts

    async def update(
        self,
        finding_id: str,
        **kwargs,
    ) -> bool:
        """Update finding fields."""
        kwargs["updated_at"] = datetime.now(timezone.utc)
        stmt = (
            update(Finding)
            .where(Finding.id == finding_id)
            .values(**kwargs)
        )
        result = await self.session.execute(stmt)
        return result.rowcount > 0

    async def mark_false_positive(
        self, finding_id: str, is_false_positive: bool = True
    ) -> bool:
        """Mark finding as false positive."""
        return await self.update(
            finding_id, is_false_positive=is_false_positive
        )

    async def add_evidence(
        self,
        finding_id: str,
        evidence_type: EvidenceType,
        title: str,
        content: str | None = None,
        file_path: str | None = None,
        description: str | None = None,
        http_method: str | None = None,
        url: str | None = None,
        headers: dict | None = None,
        body: str | None = None,
    ) -> Evidence:
        """Add evidence to a finding."""
        evidence = Evidence(
            finding_id=finding_id,
            evidence_type=evidence_type,
            title=title,
            content=content,
            file_path=file_path,
            description=description,
            http_method=http_method,
            url=url,
            headers=headers,
            body=body,
        )
        self.session.add(evidence)
        await self.session.flush()
        return evidence

    async def add_affected_asset(
        self,
        finding_id: str,
        asset_type: str,
        asset_value: str,
        port: int | None = None,
        service: str | None = None,
        version: str | None = None,
    ) -> AffectedAsset:
        """Add affected asset to a finding."""
        asset = AffectedAsset(
            finding_id=finding_id,
            asset_type=asset_type,
            asset_value=asset_value,
            port=port,
            service=service,
            version=version,
        )
        self.session.add(asset)
        await self.session.flush()
        return asset

    async def delete(self, finding_id: str) -> bool:
        """Delete a finding and all related data."""
        finding = await self.get_by_id(finding_id, include_evidence=False)
        if finding is None:
            return False

        await self.session.delete(finding)
        return True
