"""
Compliance and Standard Utils.

Provides:
- PTES phases
- CVSS scoring
- CWE mapping
- Authorization and legal compliance
"""

from enum import Enum
from typing import Any
from dataclasses import dataclass

class PTESPhase(str, Enum):
    PRE_ENGAGEMENT = "Pre-engagement"
    INTELLIGENCE_GATHERING = "Intelligence Gathering"
    THREAT_MODELING = "Threat Modeling"
    VULNERABILITY_ANALYSIS = "Vulnerability Analysis"
    EXPLOITATION = "Exploitation"
    POST_EXPLOITATION = "Post Exploitation"
    REPORTING = "Reporting"

class AttackVector(str, Enum):
    NETWORK = "Network"
    ADJACENT = "Adjacent"
    LOCAL = "Local"
    PHYSICAL = "Physical"

class AttackComplexity(str, Enum):
    LOW = "Low"
    HIGH = "High"

class PrivilegesRequired(str, Enum):
    NONE = "None"
    LOW = "Low"
    HIGH = "High"

class UserInteraction(str, Enum):
    NONE = "None"
    REQUIRED = "Required"

class Scope(str, Enum):
    UNCHANGED = "Unchanged"
    CHANGED = "Changed"

class Impact(str, Enum):
    NONE = "None"
    LOW = "Low"
    HIGH = "High"

@dataclass
class CVSSResult:
    """Mock CVSS Result."""
    vector_string: str
    base_score: float
    severity: str

class CVSSCalculator:
    """Mock CVSS Calculator."""
    
    @staticmethod
    def calculate_score(
        vector: AttackVector,
        complexity: AttackComplexity,
        privileges: PrivilegesRequired,
        user_interaction: UserInteraction,
        scope: Scope,
        confidentiality: Impact,
        integrity: Impact,
        availability: Impact
    ) -> float:
        return 7.5  # Mock score
        
    @staticmethod
    def get_vector_string(
        vector: AttackVector,
        complexity: AttackComplexity,
        privileges: PrivilegesRequired,
        user_interaction: UserInteraction,
        scope: Scope,
        confidentiality: Impact,
        integrity: Impact,
        availability: Impact
    ) -> str:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

class PTESController:
    """Mock PTES Controller."""
    def get_current_phase(self) -> PTESPhase:
        return PTESPhase.INTELLIGENCE_GATHERING

def get_ptes_controller() -> PTESController:
    return PTESController()

class CWEMapper:
    """Mock CWE Mapper."""
    def get_cwe(self, name: str) -> dict[str, Any]:
        return {"id": 0, "name": "Unknown", "description": "Unknown CWE"}

def get_cwe_mapper() -> CWEMapper:
    return CWEMapper()

# Authorization and legal compliance
from numasec.compliance.authorization import (
    require_authorization,
    is_safe_target,
    add_to_whitelist,
    get_whitelist,
    SAFE_DOMAINS,
)

__all__ = [
    # PTES
    "PTESPhase",
    "PTESController",
    "get_ptes_controller",
    # CVSS
    "AttackVector",
    "AttackComplexity",
    "PrivilegesRequired",
    "UserInteraction",
    "Scope",
    "Impact",
    "CVSSCalculator",
    "CVSSResult",
    # CWE
    "CWEMapper",
    "get_cwe_mapper",
    # Authorization
    "require_authorization",
    "is_safe_target",
    "add_to_whitelist",
    "get_whitelist",
    "SAFE_DOMAINS",
]
