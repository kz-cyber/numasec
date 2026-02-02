"""Unit tests for CVSS 3.1 Calculator.

Tests the CVSSCalculator class for proper CVSS score calculation.
"""

import pytest
import sys
sys.path.insert(0, 'src')

from numasec.compliance.cvss import (
    CVSSCalculator,
    CVSSResult,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    Impact,
    Severity,
)


class TestCVSSCalculator:
    """Test suite for CVSS Calculator."""
    
    @pytest.fixture
    def calculator(self):
        """Create calculator instance."""
        return CVSSCalculator()
    
    # ==========================================================================
    # Severity Classification Tests
    # ==========================================================================
    
    def test_severity_critical(self, calculator):
        """Test Critical severity (9.0-10.0)."""
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        assert result.severity == Severity.CRITICAL
        assert result.base_score >= 9.0
    
    def test_severity_high(self, calculator):
        """Test High severity (7.0-8.9)."""
        # Use UI=Required to reduce exploitability and get HIGH instead of CRITICAL
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,  # Changed from NONE
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.NONE,
        )
        assert result.severity == Severity.HIGH
        assert 7.0 <= result.base_score < 9.0
    
    def test_severity_medium(self, calculator):
        """Test Medium severity (4.0-6.9)."""
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.LOW,  # Changed from NONE to LOW
        )
        assert result.severity == Severity.MEDIUM
        assert 4.0 <= result.base_score < 7.0
    
    def test_severity_low(self, calculator):
        """Test Low severity (0.1-3.9)."""
        result = calculator.calculate(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.NONE,
            integrity=Impact.LOW,
            availability=Impact.NONE,
        )
        assert result.severity == Severity.LOW
        assert 0.1 <= result.base_score < 4.0
    
    def test_severity_none(self, calculator):
        """Test None/Informational severity (0.0)."""
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.NONE,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        )
        assert result.severity == Severity.INFORMATIONAL
        assert result.base_score == 0.0
    
    # ==========================================================================
    # Specific Vulnerability Type Tests
    # ==========================================================================
    
    def test_sql_injection(self, calculator):
        """Test typical SQL Injection scoring (Critical/High)."""
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.NONE,
        )
        # SQL Injection typically scores 9.1
        assert result.base_score >= 9.0
        assert result.severity == Severity.CRITICAL
    
    def test_xss_reflected(self, calculator):
        """Test Reflected XSS scoring (Medium)."""
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.CHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.NONE,
        )
        # Reflected XSS typically scores 6.1
        assert 5.0 <= result.base_score <= 7.0
        assert result.severity == Severity.MEDIUM
    
    def test_xss_stored(self, calculator):
        """Test Stored XSS scoring (High)."""
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.NONE,
        )
        # Stored XSS with high impact
        assert result.base_score >= 7.0
    
    def test_rce(self, calculator):
        """Test Remote Code Execution scoring (Critical)."""
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        # RCE should be Critical
        assert result.base_score >= 9.8
        assert result.severity == Severity.CRITICAL
    
    def test_privilege_escalation_local(self, calculator):
        """Test Local Privilege Escalation scoring."""
        result = calculator.calculate(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        # Local privesc typically 7.8
        assert result.severity in [Severity.HIGH, Severity.CRITICAL]
    
    def test_information_disclosure(self, calculator):
        """Test Information Disclosure scoring."""
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        )
        # Info disclosure - high confidentiality, nothing else
        assert 7.0 <= result.base_score <= 8.0
    
    # ==========================================================================
    # Vector String Tests
    # ==========================================================================
    
    def test_vector_string_format(self, calculator):
        """Test CVSS vector string format."""
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.NONE,
        )
        # Should be valid CVSS 3.1 vector string
        assert result.vector.startswith("CVSS:3.1/")
        assert "AV:N" in result.vector
        assert "AC:L" in result.vector
        assert "PR:N" in result.vector
        assert "UI:N" in result.vector
        assert "S:U" in result.vector
        assert "C:H" in result.vector
        assert "I:H" in result.vector
        assert "A:N" in result.vector
    
    def test_parse_vector_string(self, calculator):
        """Test parsing CVSS vector string."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        result = calculator.from_vector(vector)
        
        assert result.base_score == pytest.approx(9.1, abs=0.1)
        assert result.severity == Severity.CRITICAL
    
    def test_parse_vector_string_with_scope_changed(self, calculator):
        """Test parsing vector with changed scope."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
        result = calculator.from_vector(vector)
        
        assert result.base_score > 0
        # Changed scope affects exploitability calculation
    
    # ==========================================================================
    # Edge Cases
    # ==========================================================================
    
    def test_all_high_impact(self, calculator):
        """Test maximum possible score."""
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        # Maximum should be 10.0
        assert result.base_score == 10.0
        assert result.severity == Severity.CRITICAL
    
    def test_physical_attack_vector(self, calculator):
        """Test physical attack vector (lowest exploitability)."""
        result = calculator.calculate(
            attack_vector=AttackVector.PHYSICAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.LOW,
        )
        # Physical access + high complexity should be low
        assert result.base_score < 4.0
    
    def test_adjacent_network(self, calculator):
        """Test adjacent network attack vector."""
        result = calculator.calculate(
            attack_vector=AttackVector.ADJACENT_NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        # Adjacent network should score lower than network
        assert result.base_score < 10.0
    
    # ==========================================================================
    # Temporal Score Tests (if implemented)
    # ==========================================================================
    
    def test_temporal_score_reduces(self, calculator):
        """Test that temporal score is <= base score."""
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
        # Temporal score should be <= base score
        if result.temporal_score is not None:
            assert result.temporal_score <= result.base_score


class TestCVSSResultModel:
    """Test CVSSResult dataclass model."""
    
    def test_result_serialization(self):
        """Test CVSSResult can be serialized to dict."""
        calculator = CVSSCalculator()
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.NONE,
        )
        
        data = result.to_dict()
        assert data["base_score"] >= 8.0
        assert data["severity"] in ["Critical", "High"]
        assert data["vector_string"].startswith("CVSS:3.1/")
    
    def test_result_json_roundtrip(self):
        """Test CVSSResult JSON serialization roundtrip."""
        import json
        
        calculator = CVSSCalculator()
        result = calculator.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        )
        
        # Serialize to JSON
        json_str = json.dumps(result.to_dict())
        parsed = json.loads(json_str)
        
        assert parsed["base_score"] == result.base_score
        assert parsed["severity"] == result.severity.value


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
