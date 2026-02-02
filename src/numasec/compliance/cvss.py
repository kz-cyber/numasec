"""
NumaSec - CVSS 3.1 Calculator

Full implementation of CVSS 3.1 Base Score calculation per FIRST specification.
Reference: https://www.first.org/cvss/v3.1/specification-document

This is a production-grade implementation used for compliance reporting.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
# CVSS 3.1 Enums (per FIRST specification)
# ══════════════════════════════════════════════════════════════════════════════


class AttackVector(str, Enum):
    """Attack Vector (AV) - How the vulnerability is exploited."""
    NETWORK = "N"      # 0.85 - Remotely exploitable
    ADJACENT = "A"     # 0.62 - Adjacent network required
    LOCAL = "L"        # 0.55 - Local access required
    PHYSICAL = "P"     # 0.20 - Physical access required
    
    # Alias for test compatibility
    ADJACENT_NETWORK = "A"


class AttackComplexity(str, Enum):
    """Attack Complexity (AC) - Conditions beyond attacker's control."""
    LOW = "L"          # 0.77 - No special conditions
    HIGH = "H"         # 0.44 - Special conditions required


class PrivilegesRequired(str, Enum):
    """Privileges Required (PR) - Level of privileges needed."""
    NONE = "N"         # 0.85 / 0.85 - No privileges needed
    LOW = "L"          # 0.62 / 0.68 - Low privileges (Unchanged/Changed Scope)
    HIGH = "H"         # 0.27 / 0.50 - High privileges (Unchanged/Changed Scope)


class UserInteraction(str, Enum):
    """User Interaction (UI) - Whether user action is required."""
    NONE = "N"         # 0.85 - No user interaction
    REQUIRED = "R"     # 0.62 - User interaction required


class Scope(str, Enum):
    """Scope (S) - Whether impact extends beyond vulnerable component."""
    UNCHANGED = "U"    # Impact limited to vulnerable component
    CHANGED = "C"      # Impact can extend to other components


class Impact(str, Enum):
    """Impact metrics for C/I/A."""
    NONE = "N"         # 0.00 - No impact
    LOW = "L"          # 0.22 - Low impact
    HIGH = "H"         # 0.56 - High impact


class Severity(str, Enum):
    """CVSS Severity rating."""
    CRITICAL = "Critical"      # 9.0 - 10.0
    HIGH = "High"              # 7.0 - 8.9
    MEDIUM = "Medium"          # 4.0 - 6.9
    LOW = "Low"                # 0.1 - 3.9
    INFORMATIONAL = "None"     # 0.0


# ══════════════════════════════════════════════════════════════════════════════
# CVSS 3.1 Metric Values (per FIRST specification)
# ══════════════════════════════════════════════════════════════════════════════


# Attack Vector values
AV_VALUES: dict[AttackVector, float] = {
    AttackVector.NETWORK: 0.85,
    AttackVector.ADJACENT: 0.62,
    AttackVector.LOCAL: 0.55,
    AttackVector.PHYSICAL: 0.20,
}

# Attack Complexity values
AC_VALUES: dict[AttackComplexity, float] = {
    AttackComplexity.LOW: 0.77,
    AttackComplexity.HIGH: 0.44,
}

# Privileges Required values - different for Unchanged vs Changed scope
PR_VALUES_UNCHANGED: dict[PrivilegesRequired, float] = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.62,
    PrivilegesRequired.HIGH: 0.27,
}

PR_VALUES_CHANGED: dict[PrivilegesRequired, float] = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.68,
    PrivilegesRequired.HIGH: 0.50,
}

# User Interaction values
UI_VALUES: dict[UserInteraction, float] = {
    UserInteraction.NONE: 0.85,
    UserInteraction.REQUIRED: 0.62,
}

# Impact values
IMPACT_VALUES: dict[Impact, float] = {
    Impact.NONE: 0.00,
    Impact.LOW: 0.22,
    Impact.HIGH: 0.56,
}


# ══════════════════════════════════════════════════════════════════════════════
# Result Data Class
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class CVSSResult:
    """Result of CVSS calculation."""
    
    base_score: float
    severity: Severity
    vector_string: str
    
    # Sub-scores for transparency
    impact_score: float
    exploitability_score: float
    
    # Input metrics for reference
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality: Impact
    integrity: Impact
    availability: Impact
    
    # Optional temporal score (not implemented yet, for test compatibility)
    temporal_score: float | None = None
    environmental_score: float | None = None
    
    @property
    def vector(self) -> str:
        """Alias for vector_string (test compatibility)."""
        return self.vector_string
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "base_score": self.base_score,
            "severity": self.severity.value,
            "vector_string": self.vector_string,
            "impact_score": round(self.impact_score, 1),
            "exploitability_score": round(self.exploitability_score, 1),
            "metrics": {
                "AV": self.attack_vector.value,
                "AC": self.attack_complexity.value,
                "PR": self.privileges_required.value,
                "UI": self.user_interaction.value,
                "S": self.scope.value,
                "C": self.confidentiality.value,
                "I": self.integrity.value,
                "A": self.availability.value,
            }
        }
        if self.temporal_score is not None:
            result["temporal_score"] = self.temporal_score
        if self.environmental_score is not None:
            result["environmental_score"] = self.environmental_score
        return result


# ══════════════════════════════════════════════════════════════════════════════
# CVSS Calculator
# ══════════════════════════════════════════════════════════════════════════════


class CVSSCalculator:
    """
    CVSS 3.1 Base Score Calculator.
    
    Implements the official FIRST CVSS 3.1 specification formulas.
    
    Usage:
        calculator = CVSSCalculator()
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        print(f"Score: {result.base_score}, Severity: {result.severity}")
    """
    
    def calculate(
        self,
        attack_vector: AttackVector,
        attack_complexity: AttackComplexity,
        privileges_required: PrivilegesRequired,
        user_interaction: UserInteraction,
        scope: Scope,
        confidentiality: Impact,
        integrity: Impact,
        availability: Impact,
    ) -> CVSSResult:
        """
        Calculate CVSS 3.1 Base Score.
        
        Formula per FIRST specification:
        - If Impact = 0: BaseScore = 0
        - If Scope Unchanged: BaseScore = Roundup(min(Impact + Exploitability, 10))
        - If Scope Changed: BaseScore = Roundup(min(1.08 × (Impact + Exploitability), 10))
        """
        # Get metric values
        av = AV_VALUES[attack_vector]
        ac = AC_VALUES[attack_complexity]
        ui = UI_VALUES[user_interaction]
        
        # PR depends on Scope
        if scope == Scope.UNCHANGED:
            pr = PR_VALUES_UNCHANGED[privileges_required]
        else:
            pr = PR_VALUES_CHANGED[privileges_required]
        
        # Impact values
        c = IMPACT_VALUES[confidentiality]
        i = IMPACT_VALUES[integrity]
        a = IMPACT_VALUES[availability]
        
        # Calculate ISS (Impact Sub Score)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        # Calculate Impact Score based on Scope
        if scope == Scope.UNCHANGED:
            impact_score = 6.42 * iss
        else:
            # Scope Changed formula
            impact_score = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        
        # Calculate Exploitability Score
        exploitability_score = 8.22 * av * ac * pr * ui
        
        # Calculate Base Score
        if impact_score <= 0:
            base_score = 0.0
        elif scope == Scope.UNCHANGED:
            base_score = min(impact_score + exploitability_score, 10)
            base_score = self._roundup(base_score)
        else:
            base_score = min(1.08 * (impact_score + exploitability_score), 10)
            base_score = self._roundup(base_score)
        
        # Determine severity
        severity = self._get_severity(base_score)
        
        # Build vector string
        vector_string = self._build_vector_string(
            attack_vector, attack_complexity, privileges_required,
            user_interaction, scope, confidentiality, integrity, availability
        )
        
        return CVSSResult(
            base_score=base_score,
            severity=severity,
            vector_string=vector_string,
            impact_score=impact_score,
            exploitability_score=exploitability_score,
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability,
        )
    
    def _roundup(self, value: float) -> float:
        """
        CVSS 3.1 Roundup function.
        
        Per specification: "Round up to nearest 0.1"
        This is NOT standard rounding - it always rounds UP.
        """
        return math.ceil(value * 10) / 10
    
    def _get_severity(self, score: float) -> Severity:
        """Map score to severity rating."""
        if score == 0.0:
            return Severity.INFORMATIONAL
        elif score < 4.0:
            return Severity.LOW
        elif score < 7.0:
            return Severity.MEDIUM
        elif score < 9.0:
            return Severity.HIGH
        else:
            return Severity.CRITICAL
    
    def _build_vector_string(
        self,
        av: AttackVector,
        ac: AttackComplexity,
        pr: PrivilegesRequired,
        ui: UserInteraction,
        s: Scope,
        c: Impact,
        i: Impact,
        a: Impact,
    ) -> str:
        """Build CVSS 3.1 vector string."""
        return (
            f"CVSS:3.1/AV:{av.value}/AC:{ac.value}/PR:{pr.value}/"
            f"UI:{ui.value}/S:{s.value}/C:{c.value}/I:{i.value}/A:{a.value}"
        )
    
    def parse_vector(self, vector_string: str) -> CVSSResult:
        """
        Parse a CVSS 3.1 vector string and calculate score.
        
        Args:
            vector_string: e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            
        Returns:
            CVSSResult with calculated score
        """
        # Parse vector components
        if not vector_string.startswith("CVSS:3.1/"):
            raise ValueError(f"Invalid CVSS 3.1 vector: {vector_string}")
        
        parts = vector_string.replace("CVSS:3.1/", "").split("/")
        metrics = {}
        
        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value
        
        # Map to enums
        av_map = {"N": AttackVector.NETWORK, "A": AttackVector.ADJACENT, 
                  "L": AttackVector.LOCAL, "P": AttackVector.PHYSICAL}
        ac_map = {"L": AttackComplexity.LOW, "H": AttackComplexity.HIGH}
        pr_map = {"N": PrivilegesRequired.NONE, "L": PrivilegesRequired.LOW, 
                  "H": PrivilegesRequired.HIGH}
        ui_map = {"N": UserInteraction.NONE, "R": UserInteraction.REQUIRED}
        s_map = {"U": Scope.UNCHANGED, "C": Scope.CHANGED}
        impact_map = {"N": Impact.NONE, "L": Impact.LOW, "H": Impact.HIGH}
        
        return self.calculate(
            attack_vector=av_map[metrics["AV"]],
            attack_complexity=ac_map[metrics["AC"]],
            privileges_required=pr_map[metrics["PR"]],
            user_interaction=ui_map[metrics["UI"]],
            scope=s_map[metrics["S"]],
            confidentiality=impact_map[metrics["C"]],
            integrity=impact_map[metrics["I"]],
            availability=impact_map[metrics["A"]],
        )
    
    def from_vector(self, vector_string: str) -> CVSSResult:
        """Alias for parse_vector (test compatibility)."""
        return self.parse_vector(vector_string)
    
    @staticmethod
    def from_vulnerability_type(vuln_type: str) -> CVSSResult:
        """
        Calculate CVSS score from common vulnerability type.
        
        This provides reasonable defaults for common vulnerability types.
        For accurate scoring, use calculate() with specific metrics.
        """
        calculator = CVSSCalculator()
        
        # Common vulnerability type mappings
        vuln_mappings = {
            "sql_injection": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality": Impact.HIGH,
                "integrity": Impact.HIGH,
                "availability": Impact.NONE,
            },
            "xss_reflected": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.REQUIRED,
                "scope": Scope.CHANGED,
                "confidentiality": Impact.LOW,
                "integrity": Impact.LOW,
                "availability": Impact.NONE,
            },
            "xss_stored": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.LOW,
                "user_interaction": UserInteraction.REQUIRED,
                "scope": Scope.CHANGED,
                "confidentiality": Impact.LOW,
                "integrity": Impact.LOW,
                "availability": Impact.NONE,
            },
            "rce": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.CHANGED,
                "confidentiality": Impact.HIGH,
                "integrity": Impact.HIGH,
                "availability": Impact.HIGH,
            },
            "lfi": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality": Impact.HIGH,
                "integrity": Impact.NONE,
                "availability": Impact.NONE,
            },
            "ssrf": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.CHANGED,
                "confidentiality": Impact.HIGH,
                "integrity": Impact.NONE,
                "availability": Impact.NONE,
            },
            "idor": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.LOW,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality": Impact.HIGH,
                "integrity": Impact.NONE,
                "availability": Impact.NONE,
            },
        }
        
        vuln_key = vuln_type.lower().replace(" ", "_").replace("-", "_")
        
        if vuln_key not in vuln_mappings:
            # Default to medium severity unknown vulnerability
            return calculator.calculate(
                attack_vector=AttackVector.NETWORK,
                attack_complexity=AttackComplexity.HIGH,
                privileges_required=PrivilegesRequired.LOW,
                user_interaction=UserInteraction.REQUIRED,
                scope=Scope.UNCHANGED,
                confidentiality=Impact.LOW,
                integrity=Impact.LOW,
                availability=Impact.NONE,
            )
        
        return calculator.calculate(**vuln_mappings[vuln_key])


# ══════════════════════════════════════════════════════════════════════════════
# Convenience Functions
# ══════════════════════════════════════════════════════════════════════════════


def calculate_cvss(
    attack_vector: AttackVector = AttackVector.NETWORK,
    attack_complexity: AttackComplexity = AttackComplexity.LOW,
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE,
    user_interaction: UserInteraction = UserInteraction.NONE,
    scope: Scope = Scope.UNCHANGED,
    confidentiality: Impact = Impact.NONE,
    integrity: Impact = Impact.NONE,
    availability: Impact = Impact.NONE,
) -> CVSSResult:
    """Convenience function for quick CVSS calculation."""
    return CVSSCalculator().calculate(
        attack_vector=attack_vector,
        attack_complexity=attack_complexity,
        privileges_required=privileges_required,
        user_interaction=user_interaction,
        scope=scope,
        confidentiality=confidentiality,
        integrity=integrity,
        availability=availability,
    )


def parse_cvss_vector(vector_string: str) -> CVSSResult:
    """Convenience function for parsing CVSS vectors."""
    return CVSSCalculator().parse_vector(vector_string)
