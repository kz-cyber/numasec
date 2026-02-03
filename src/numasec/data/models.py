"""
NumaSec - SQLAlchemy Data Models

Complete data model following PRD Section 9.
All models use SQLAlchemy 2.0 with async support.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# ══════════════════════════════════════════════════════════════════════════════
# Base Class
# ══════════════════════════════════════════════════════════════════════════════


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""

    type_annotation_map = {
        dict[str, Any]: JSON,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Enums
# ══════════════════════════════════════════════════════════════════════════════


class EngagementStatus(str, enum.Enum):
    """Engagement lifecycle status."""

    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    REPORTING = "reporting"
    COMPLETE = "complete"
    ARCHIVED = "archived"


class Severity(str, enum.Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ScopeType(str, enum.Enum):
    """Type of scope entry."""

    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    WILDCARD = "wildcard"


class ActionType(str, enum.Enum):
    """Type of logged action."""

    TOOL_EXECUTION = "tool_execution"
    FINDING_CREATE = "finding_create"
    FINDING_UPDATE = "finding_update"
    SCOPE_CHECK = "scope_check"
    APPROVAL = "approval"
    PHASE_TRANSITION = "phase_transition"
    REPORT_GENERATION = "report_generation"
    AI_SUGGESTION = "ai_suggestion"
    MANUAL_ACTION = "manual_action"


class ToolRisk(str, enum.Enum):
    """Risk level of security tools."""

    LOW = "low"  # Read-only, passive
    MEDIUM = "medium"  # Active scanning
    HIGH = "high"  # Intrusive testing
    CRITICAL = "critical"  # Exploitation


class ApprovalDecision(str, enum.Enum):
    """Human approval decision."""

    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"
    TIMEOUT = "timeout"


class EvidenceType(str, enum.Enum):
    """Type of evidence attachment."""

    SCREENSHOT = "screenshot"
    REQUEST = "request"
    RESPONSE = "response"
    LOG = "log"
    FILE = "file"
    CODE = "code"
    TOOL_OUTPUT = "tool_output"


class PTESPhase(str, enum.Enum):
    """PTES 7-phase methodology."""

    PRE_ENGAGEMENT = "pre_engagement"
    INTELLIGENCE_GATHERING = "intelligence_gathering"
    THREAT_MODELING = "threat_modeling"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


# ══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ══════════════════════════════════════════════════════════════════════════════


def generate_uuid() -> str:
    """Generate a UUID string."""
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


# ══════════════════════════════════════════════════════════════════════════════
# Models
# ══════════════════════════════════════════════════════════════════════════════


class Engagement(Base):
    """
    Penetration testing engagement.

    Represents a complete pentest project with scope, findings, and reports.
    """

    __tablename__ = "engagements"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=generate_uuid
    )

    # Core fields
    client_name: Mapped[str] = mapped_column(String(255), nullable=False)
    project_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[EngagementStatus] = mapped_column(
        Enum(EngagementStatus), default=EngagementStatus.DRAFT
    )

    # Methodology
    methodology: Mapped[str] = mapped_column(String(50), default="PTES")
    current_phase: Mapped[PTESPhase] = mapped_column(
        Enum(PTESPhase), default=PTESPhase.PRE_ENGAGEMENT
    )

    # Time tracking
    start_date: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    end_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )

    # Approval mode
    approval_mode: Mapped[str] = mapped_column(String(20), default="supervised")

    # Extra metadata (JSON)
    meta_info: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Relationships
    scope_entries: Mapped[list["ScopeEntry"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    action_logs: Mapped[list["ActionLog"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Engagement(id={self.id[:8]}, client={self.client_name}, status={self.status.value})>"


class ScopeEntry(Base):
    """
    Authorized target scope entry.

    Defines what targets are in-scope for the engagement.
    """

    __tablename__ = "scope_entries"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=generate_uuid
    )
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id"), nullable=False
    )

    # Scope definition
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    scope_type: Mapped[ScopeType] = mapped_column(Enum(ScopeType), nullable=False)
    is_excluded: Mapped[bool] = mapped_column(Boolean, default=False)

    # Time restrictions
    time_window_start: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    time_window_end: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Notes
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    # Relationships
    engagement: Mapped["Engagement"] = relationship(back_populates="scope_entries")

    def __repr__(self) -> str:
        return f"<ScopeEntry(target={self.target}, type={self.scope_type.value})>"


class Finding(Base):
    """
    Security vulnerability finding.

    Includes CVSS scoring and CWE mapping.
    """

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=generate_uuid
    )
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id"), nullable=False
    )

    # Core finding data
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)

    # CVSS 3.1 scoring
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    cvss_vector: Mapped[str] = mapped_column(String(100), default="")

    # CWE classification
    cwe_id: Mapped[str] = mapped_column(String(20), default="")
    cwe_name: Mapped[str] = mapped_column(String(255), default="")

    # Narrative content
    description: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[str] = mapped_column(Text, default="")

    # Affected assets
    affected_asset: Mapped[str] = mapped_column(String(500), default="")
    affected_component: Mapped[str] = mapped_column(String(255), default="")

    # Status tracking
    is_confirmed: Mapped[bool] = mapped_column(Boolean, default=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)

    # AI-generated flag
    ai_generated: Mapped[bool] = mapped_column(Boolean, default=False)

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )

    # Extra metadata
    meta_info: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Relationships
    engagement: Mapped["Engagement"] = relationship(back_populates="findings")
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    affected_assets: Mapped[list["AffectedAsset"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Finding(id={self.id[:8]}, title={self.title[:30]}, severity={self.severity.value})>"


class Evidence(Base):
    """
    Evidence attachment for a finding.

    Screenshots, requests, responses, logs, etc.
    """

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=generate_uuid
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id"), nullable=False
    )

    # Evidence data
    evidence_type: Mapped[EvidenceType] = mapped_column(
        Enum(EvidenceType), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Content (stored as text or path)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    mime_type: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # For request/response evidence
    http_method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    url: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    headers: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timestamps
    captured_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    # Relationships
    finding: Mapped["Finding"] = relationship(back_populates="evidence")

    def __repr__(self) -> str:
        return f"<Evidence(id={self.id[:8]}, type={self.evidence_type.value})>"


class AffectedAsset(Base):
    """
    Asset affected by a finding.

    Multiple assets can be affected by a single finding.
    """

    __tablename__ = "affected_assets"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=generate_uuid
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id"), nullable=False
    )

    # Asset info
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)  # host, url, service
    asset_value: Mapped[str] = mapped_column(String(500), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    service: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    # Relationships
    finding: Mapped["Finding"] = relationship(back_populates="affected_assets")

    def __repr__(self) -> str:
        return f"<AffectedAsset(type={self.asset_type}, value={self.asset_value})>"


class ActionLog(Base):
    """
    Immutable audit log entry with hash chain.

    Every action is logged for compliance and reproducibility.
    """

    __tablename__ = "action_logs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=generate_uuid
    )
    engagement_id: Mapped[str | None] = mapped_column(
        ForeignKey("engagements.id"), nullable=True
    )

    # Action data
    action_type: Mapped[ActionType] = mapped_column(
        Enum(ActionType), nullable=False
    )
    action: Mapped[str] = mapped_column(String(500), nullable=False)
    tool: Mapped[str | None] = mapped_column(String(100), nullable=True)
    target: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Result
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Approval info
    user_approved: Mapped[bool] = mapped_column(Boolean, default=True)
    approval_decision: Mapped[ApprovalDecision | None] = mapped_column(
        Enum(ApprovalDecision), nullable=True
    )
    approval_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Tool risk
    tool_risk: Mapped[ToolRisk | None] = mapped_column(
        Enum(ToolRisk), nullable=True
    )

    # PTES phase
    ptes_phase: Mapped[PTESPhase | None] = mapped_column(
        Enum(PTESPhase), nullable=True
    )

    # Hash chain for integrity
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Timestamps
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    # Extra metadata
    meta_info: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Relationships
    engagement: Mapped["Engagement | None"] = relationship(
        back_populates="action_logs"
    )

    def __repr__(self) -> str:
        return f"<ActionLog(id={self.id[:8]}, action={self.action_type.value})>"


class Report(Base):
    """
    Generated report metadata.

    Tracks report generation history.
    """

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=generate_uuid
    )
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id"), nullable=False
    )

    # Report info
    template: Mapped[str] = mapped_column(String(50), nullable=False)
    format: Mapped[str] = mapped_column(String(20), nullable=False)  # pdf, docx, md
    title: Mapped[str] = mapped_column(String(500), nullable=False)

    # File info
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, default=0)
    file_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Content snapshot (finding count at generation time)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)

    # Generation info
    generated_by: Mapped[str] = mapped_column(String(100), default="numasec")
    generation_time_ms: Mapped[int] = mapped_column(Integer, default=0)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    def __repr__(self) -> str:
        return f"<Report(id={self.id[:8]}, format={self.format})>"


class ToolExecution(Base):
    """
    Tool execution record.

    Detailed record of every security tool execution.
    """

    __tablename__ = "tool_executions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=generate_uuid
    )
    engagement_id: Mapped[str | None] = mapped_column(
        ForeignKey("engagements.id"), nullable=True
    )

    # Tool info
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    tool_risk: Mapped[ToolRisk] = mapped_column(Enum(ToolRisk), nullable=False)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    parameters: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Target
    target: Mapped[str] = mapped_column(String(500), nullable=False)

    # Execution results
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    stderr_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    parsed_result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Timing
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Status
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    timed_out: Mapped[bool] = mapped_column(Boolean, default=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Approval
    approved: Mapped[bool] = mapped_column(Boolean, default=True)
    approved_by: Mapped[str] = mapped_column(String(100), default="user")

    def __repr__(self) -> str:
        return f"<ToolExecution(id={self.id[:8]}, tool={self.tool_name})>"
