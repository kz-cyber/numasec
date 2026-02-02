"""
NumaSec - Engagement Controller

Manages engagement lifecycle and PTES phase tracking.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from numasec.data.models import EngagementStatus


# ══════════════════════════════════════════════════════════════════════════════
# PTES Phases
# ══════════════════════════════════════════════════════════════════════════════


class PTESPhase(str, Enum):
    """PTES methodology phases."""

    PRE_ENGAGEMENT = "pre_engagement"  # Phase 1
    INTELLIGENCE_GATHERING = "intelligence_gathering"  # Phase 2
    THREAT_MODELING = "threat_modeling"  # Phase 3
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"  # Phase 4
    EXPLOITATION = "exploitation"  # Phase 5
    POST_EXPLOITATION = "post_exploitation"  # Phase 6
    REPORTING = "reporting"  # Phase 7


PTES_PHASE_ORDER = [
    PTESPhase.PRE_ENGAGEMENT,
    PTESPhase.INTELLIGENCE_GATHERING,
    PTESPhase.THREAT_MODELING,
    PTESPhase.VULNERABILITY_ANALYSIS,
    PTESPhase.EXPLOITATION,
    PTESPhase.POST_EXPLOITATION,
    PTESPhase.REPORTING,
]

PTES_PHASE_DESCRIPTIONS = {
    PTESPhase.PRE_ENGAGEMENT: "Define scope, objectives, and rules of engagement",
    PTESPhase.INTELLIGENCE_GATHERING: "Passive and active reconnaissance",
    PTESPhase.THREAT_MODELING: "Identify assets, entry points, and attack vectors",
    PTESPhase.VULNERABILITY_ANALYSIS: "Discover and validate vulnerabilities",
    PTESPhase.EXPLOITATION: "Exploit vulnerabilities to gain access",
    PTESPhase.POST_EXPLOITATION: "Maintain access, escalate privileges, pivot",
    PTESPhase.REPORTING: "Document findings and generate reports",
}

PTES_PHASE_TOOLS = {
    PTESPhase.PRE_ENGAGEMENT: [],
    PTESPhase.INTELLIGENCE_GATHERING: ["subfinder", "httpx", "whatweb", "nmap"],
    PTESPhase.THREAT_MODELING: [],
    PTESPhase.VULNERABILITY_ANALYSIS: ["nuclei", "nikto", "ffuf"],
    PTESPhase.EXPLOITATION: ["sqlmap", "hydra", "script", "python_script", "shell_script"],
    PTESPhase.POST_EXPLOITATION: ["script", "python_script", "shell_script"],
    PTESPhase.REPORTING: [],
}


# ══════════════════════════════════════════════════════════════════════════════
# Engagement Models
# ══════════════════════════════════════════════════════════════════════════════


class EngagementConfig(BaseModel):
    """Configuration for a new engagement."""

    client_name: str
    project_name: str
    methodology: str = "ptes"
    start_date: datetime = Field(default_factory=datetime.utcnow)
    end_date: datetime | None = None
    objectives: list[str] = Field(default_factory=list)
    restrictions: list[str] = Field(default_factory=list)
    emergency_contacts: list[str] = Field(default_factory=list)
    notes: str = ""


class EngagementSummary(BaseModel):
    """Summary of an engagement."""

    id: str
    client_name: str
    project_name: str
    status: str
    current_phase: str
    findings_count: int = 0
    actions_count: int = 0
    created_at: datetime
    last_activity: datetime | None = None


class PhaseProgress(BaseModel):
    """Progress within a PTES phase."""

    phase: PTESPhase
    started_at: datetime | None = None
    completed_at: datetime | None = None
    actions_count: int = 0
    findings_count: int = 0
    notes: list[str] = Field(default_factory=list)

    @property
    def is_active(self) -> bool:
        return self.started_at is not None and self.completed_at is None

    @property
    def is_complete(self) -> bool:
        return self.completed_at is not None


# ══════════════════════════════════════════════════════════════════════════════
# Engagement Controller
# ══════════════════════════════════════════════════════════════════════════════


class EngagementController:
    """
    Manages engagement lifecycle.

    Responsibilities:
    - Create and manage engagements
    - Track PTES phase progression
    - Validate phase transitions
    - Provide engagement context for AI
    """

    def __init__(self) -> None:
        """Initialize controller."""
        self._current_engagement_id: str | None = None
        self._engagements: dict[str, dict[str, Any]] = {}
        self._phase_progress: dict[str, dict[PTESPhase, PhaseProgress]] = {}

    @property
    def current_engagement_id(self) -> str | None:
        """Get current engagement ID."""
        return self._current_engagement_id

    @property
    def current_engagement(self) -> dict[str, Any] | None:
        """Get current engagement data."""
        if not self._current_engagement_id:
            return None
        return self._engagements.get(self._current_engagement_id)

    def create_engagement(self, config: EngagementConfig) -> str:
        """
        Create a new engagement.

        Args:
            config: Engagement configuration

        Returns:
            Engagement ID
        """
        engagement_id = str(uuid4())

        engagement = {
            "id": engagement_id,
            "client_name": config.client_name,
            "project_name": config.project_name,
            "methodology": config.methodology,
            "status": EngagementStatus.DRAFT.value,
            "current_phase": PTESPhase.PRE_ENGAGEMENT.value,
            "start_date": config.start_date,
            "end_date": config.end_date,
            "objectives": config.objectives,
            "restrictions": config.restrictions,
            "emergency_contacts": config.emergency_contacts,
            "notes": config.notes,
            "created_at": datetime.now(timezone.utc),
            "findings": [],
            "scope": [],
            "actions": [],
        }

        self._engagements[engagement_id] = engagement

        # Initialize phase progress
        self._phase_progress[engagement_id] = {
            phase: PhaseProgress(phase=phase) for phase in PTES_PHASE_ORDER
        }

        return engagement_id

    def activate_engagement(self, engagement_id: str) -> bool:
        """
        Set an engagement as the current active engagement.

        Args:
            engagement_id: Engagement to activate

        Returns:
            True if successful
        """
        if engagement_id not in self._engagements:
            return False

        self._current_engagement_id = engagement_id
        self._engagements[engagement_id]["status"] = EngagementStatus.ACTIVE.value

        # Start first phase if not started
        progress = self._phase_progress[engagement_id][PTESPhase.PRE_ENGAGEMENT]
        if not progress.started_at:
            progress.started_at = datetime.now(timezone.utc)

        return True

    def get_current_phase(self) -> PTESPhase | None:
        """Get the current PTES phase."""
        if not self._current_engagement_id:
            return None

        engagement = self._engagements.get(self._current_engagement_id)
        if not engagement:
            return None

        return PTESPhase(engagement["current_phase"])

    def advance_phase(self) -> tuple[bool, str]:
        """
        Advance to the next PTES phase.

        Returns:
            (success, message)
        """
        if not self._current_engagement_id:
            return False, "No active engagement"

        current_phase = self.get_current_phase()
        if not current_phase:
            return False, "No current phase"

        current_idx = PTES_PHASE_ORDER.index(current_phase)

        if current_idx >= len(PTES_PHASE_ORDER) - 1:
            return False, "Already at final phase"

        # Mark current phase complete
        progress = self._phase_progress[self._current_engagement_id][current_phase]
        progress.completed_at = datetime.now(timezone.utc)

        # Move to next phase
        next_phase = PTES_PHASE_ORDER[current_idx + 1]
        self._engagements[self._current_engagement_id]["current_phase"] = next_phase.value

        # Start next phase
        next_progress = self._phase_progress[self._current_engagement_id][next_phase]
        next_progress.started_at = datetime.now(timezone.utc)

        return True, f"Advanced to {next_phase.value}"

    def get_phase_progress(self, phase: PTESPhase | None = None) -> PhaseProgress | dict[PTESPhase, PhaseProgress] | None:
        """Get progress for a phase or all phases."""
        if not self._current_engagement_id:
            return None

        all_progress = self._phase_progress.get(self._current_engagement_id)
        if not all_progress:
            return None

        if phase:
            return all_progress.get(phase)

        return all_progress

    def get_engagement_context(self) -> dict[str, Any]:
        """
        Get context for AI prompts.

        Returns:
            Dictionary with engagement context
        """
        if not self._current_engagement_id:
            return {"active": False}

        engagement = self._engagements.get(self._current_engagement_id, {})
        current_phase = self.get_current_phase()
        phase_progress = self.get_phase_progress()

        return {
            "active": True,
            "id": engagement.get("id"),
            "client": engagement.get("client_name"),
            "project": engagement.get("project_name"),
            "methodology": engagement.get("methodology"),
            "status": engagement.get("status"),
            "current_phase": current_phase.value if current_phase else None,
            "phase_description": PTES_PHASE_DESCRIPTIONS.get(current_phase, "") if current_phase else "",
            "recommended_tools": PTES_PHASE_TOOLS.get(current_phase, []) if current_phase else [],
            "objectives": engagement.get("objectives", []),
            "restrictions": engagement.get("restrictions", []),
            "scope": engagement.get("scope", []),
            "findings_count": len(engagement.get("findings", [])),
            "actions_count": len(engagement.get("actions", [])),
        }

    def add_to_scope(self, target: str, target_type: str = "host") -> bool:
        """Add a target to scope."""
        if not self._current_engagement_id:
            return False

        scope_entry = {
            "target": target,
            "type": target_type,
            "added_at": datetime.now(timezone.utc).isoformat(),
        }

        self._engagements[self._current_engagement_id]["scope"].append(scope_entry)
        return True

    def record_action(self, action: dict[str, Any]) -> None:
        """Record an action in the engagement."""
        if not self._current_engagement_id:
            return

        action["timestamp"] = datetime.now(timezone.utc).isoformat()
        self._engagements[self._current_engagement_id]["actions"].append(action)

        # Update phase progress
        current_phase = self.get_current_phase()
        if current_phase:
            progress = self._phase_progress[self._current_engagement_id][current_phase]
            progress.actions_count += 1

    def record_finding(self, finding: dict[str, Any]) -> None:
        """Record a finding in the engagement."""
        if not self._current_engagement_id:
            return

        finding["timestamp"] = datetime.now(timezone.utc).isoformat()
        self._engagements[self._current_engagement_id]["findings"].append(finding)

        # Update phase progress
        current_phase = self.get_current_phase()
        if current_phase:
            progress = self._phase_progress[self._current_engagement_id][current_phase]
            progress.findings_count += 1

    def list_engagements(self) -> list[EngagementSummary]:
        """List all engagements."""
        summaries = []

        for eng_id, engagement in self._engagements.items():
            summary = EngagementSummary(
                id=eng_id,
                client_name=engagement["client_name"],
                project_name=engagement["project_name"],
                status=engagement["status"],
                current_phase=engagement["current_phase"],
                findings_count=len(engagement.get("findings", [])),
                actions_count=len(engagement.get("actions", [])),
                created_at=engagement["created_at"],
            )
            summaries.append(summary)

        return summaries

    def complete_engagement(self) -> bool:
        """Mark current engagement as complete."""
        if not self._current_engagement_id:
            return False

        self._engagements[self._current_engagement_id]["status"] = EngagementStatus.COMPLETE.value
        self._engagements[self._current_engagement_id]["completed_at"] = datetime.now(timezone.utc)
        self._current_engagement_id = None
        return True


# Global instance
_controller: EngagementController | None = None


def get_engagement_controller() -> EngagementController:
    """Get the global engagement controller."""
    global _controller
    if _controller is None:
        _controller = EngagementController()
    return _controller
