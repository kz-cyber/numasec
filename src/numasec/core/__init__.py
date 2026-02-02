"""Core orchestration package for NumaSec.

Engagement lifecycle, scope enforcement, approval gateway, and audit logging.
"""

from numasec.core.engagement import (
    EngagementController,
    EngagementConfig,
    EngagementSummary,
    PhaseProgress,
    PTESPhase,
    PTES_PHASE_ORDER,
    PTES_PHASE_DESCRIPTIONS,
    PTES_PHASE_TOOLS,
    get_engagement_controller,
)
from numasec.core.scope import (
    ScopeEnforcer,
    ScopeEntry,
    ScopeEntryType,
    ScopeDecision,
    ScopeCheckResult,
    ScopeViolationError,
    get_scope_enforcer,
)
from numasec.core.approval import (
    ApprovalGateway,
    ApprovalMode,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStats,
    cli_approval_callback,
    get_approval_gateway,
)
from numasec.core.audit import (
    AuditLogger,
    AuditEntry,
    AuditAction,
    get_audit_logger,
    configure_audit_logger,
)
from numasec.core.safety import (
    SafetyController,
    SafetyState,
    SafetyViolation,
    SafetyViolationType,
    SafetyConfig,
    get_safety_controller,
    emergency_stop,
)

__all__ = [
    # Engagement
    "EngagementController",
    "EngagementConfig",
    "EngagementSummary",
    "PhaseProgress",
    "PTESPhase",
    "PTES_PHASE_ORDER",
    "PTES_PHASE_DESCRIPTIONS",
    "PTES_PHASE_TOOLS",
    "get_engagement_controller",
    # Scope
    "ScopeEnforcer",
    "ScopeEntry",
    "ScopeEntryType",
    "ScopeDecision",
    "ScopeCheckResult",
    "ScopeViolationError",
    "get_scope_enforcer",
    # Approval
    "ApprovalGateway",
    "ApprovalMode",
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalStats",
    "cli_approval_callback",
    "get_approval_gateway",
    # Audit
    "AuditLogger",
    "AuditEntry",
    "AuditAction",
    "get_audit_logger",
    "configure_audit_logger",
    # Safety
    "SafetyController",
    "SafetyState",
    "SafetyViolation",
    "SafetyViolationType",
    "SafetyConfig",
    "get_safety_controller",
    "emergency_stop",
]
