"""
Unit tests for FactStore (Epistemic State).

Tests the core fact storage, retrieval, and context injection functionality.
"""

import pytest
from datetime import datetime
from pathlib import Path
import tempfile
import json

from numasec.agent.fact_store import FactStore, Fact, FactType


@pytest.fixture
def temp_fact_store():
    """Create a temporary FactStore for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    store = FactStore(db_path=temp_path)
    yield store
    
    # Cleanup
    Path(temp_path).unlink(missing_ok=True)


def test_add_fact_high_confidence(temp_fact_store):
    """Test adding a fact with confidence >= 0.8."""
    fact = temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="sqli_login",
        value="Parameter 'username' vulnerable to SQLi",
        confidence=0.95,
        evidence="sqlmap confirmed with --dbs flag",
        iteration=5,
        tags=["sqli", "confirmed"]
    )
    
    assert fact.key == "sqli_login"
    assert fact.confidence == 0.95
    assert fact.type == FactType.VULNERABILITY
    assert "sqli" in fact.tags


def test_reject_low_confidence_fact(temp_fact_store):
    """Test that facts with confidence < 0.8 are rejected."""
    with pytest.raises(ValueError, match="Confidence .* too low"):
        temp_fact_store.add_fact(
            type=FactType.VULNERABILITY,
            key="maybe_vuln",
            value="Possibly vulnerable",
            confidence=0.7,  # Too low!
            evidence="Uncertain result",
            iteration=3
        )


def test_fact_retrieval(temp_fact_store):
    """Test retrieving facts by key."""
    # Add fact
    temp_fact_store.add_fact(
        type=FactType.CREDENTIAL,
        key="admin_creds",
        value="admin:password123",
        confidence=0.99,
        evidence="Hydra confirmed login",
        iteration=10
    )
    
    # Retrieve
    fact = temp_fact_store.get_fact("admin_creds")
    
    assert fact is not None
    assert fact.value == "admin:password123"
    assert fact.type == FactType.CREDENTIAL


def test_fact_persistence(temp_fact_store):
    """Test that facts persist to disk."""
    # Add fact
    temp_fact_store.add_fact(
        type=FactType.SESSION,
        key="session_token",
        value="abc123def456",
        confidence=0.9,
        evidence="Set-Cookie header",
        iteration=2
    )
    
    # Create new store pointing to same file
    new_store = FactStore(db_path=temp_fact_store.db_path)
    
    # Should load persisted fact
    fact = new_store.get_fact("session_token")
    assert fact is not None
    assert fact.value == "abc123def456"


def test_get_facts_by_type(temp_fact_store):
    """Test filtering facts by type."""
    # Add multiple facts
    temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="sqli_1",
        value="SQLi in param1",
        confidence=0.9,
        evidence="test",
        iteration=1
    )
    
    temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="sqli_2",
        value="SQLi in param2",
        confidence=0.85,
        evidence="test",
        iteration=2
    )
    
    temp_fact_store.add_fact(
        type=FactType.CREDENTIAL,
        key="creds",
        value="user:pass",
        confidence=0.95,
        evidence="test",
        iteration=3
    )
    
    # Get vulnerabilities only
    vulns = temp_fact_store.get_facts_by_type(FactType.VULNERABILITY)
    
    assert len(vulns) == 2
    assert all(f.type == FactType.VULNERABILITY for f in vulns)


def test_has_vulnerability(temp_fact_store):
    """Test checking for vulnerabilities."""
    # No vulnerabilities yet
    assert not temp_fact_store.has_vulnerability()
    
    # Add vulnerability
    temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="xss_reflected",
        value="XSS in search parameter",
        confidence=0.88,
        evidence="Manual confirmation",
        iteration=7
    )
    
    # Should detect vulnerability
    assert temp_fact_store.has_vulnerability()
    assert temp_fact_store.has_vulnerability("xss")
    assert not temp_fact_store.has_vulnerability("sqli")


def test_search_facts(temp_fact_store):
    """Test searching facts by keyword."""
    # Add facts with different keywords
    temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="sqli_login",
        value="SQL injection in login form",
        confidence=0.92,
        evidence="test",
        iteration=5,
        tags=["sqli", "authentication"]
    )
    
    temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="sqli_search",
        value="SQL injection in search endpoint",
        confidence=0.87,
        evidence="test",
        iteration=8,
        tags=["sqli", "search"]
    )
    
    temp_fact_store.add_fact(
        type=FactType.CREDENTIAL,
        key="admin_pw",
        value="admin:secret",
        confidence=0.95,
        evidence="test",
        iteration=10
    )
    
    # Search for "sqli"
    results = temp_fact_store.search("sqli")
    assert len(results) == 2
    
    # Results should be sorted by confidence (highest first)
    assert results[0].confidence >= results[1].confidence
    
    # Search for "admin"
    results = temp_fact_store.search("admin")
    assert len(results) == 1
    assert results[0].key == "admin_pw"


def test_context_for_prompt(temp_fact_store):
    """Test context generation for LLM prompt."""
    # Add multiple facts
    temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="sqli_main",
        value="Primary SQLi vector",
        confidence=0.95,
        evidence="test",
        iteration=3
    )
    
    temp_fact_store.add_fact(
        type=FactType.CREDENTIAL,
        key="admin_login",
        value="admin:admin123",
        confidence=0.99,
        evidence="test",
        iteration=5
    )
    
    # Get context
    context = temp_fact_store.get_context_for_prompt(max_facts=10)
    
    # Should contain epistemic state header
    assert "EPISTEMIC STATE" in context
    
    # Should contain fact details
    assert "sqli_main" in context
    assert "admin_login" in context
    assert "0.95" in context  # Confidence
    assert "iter: 3" in context  # Iteration


def test_empty_context_for_prompt(temp_fact_store):
    """Test context generation when no facts exist."""
    context = temp_fact_store.get_context_for_prompt()
    assert context == ""


def test_fact_update_higher_confidence(temp_fact_store):
    """Test updating fact with higher confidence."""
    # Add initial fact
    temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="vuln_test",
        value="Initial assessment",
        confidence=0.82,
        evidence="Preliminary test",
        iteration=3
    )
    
    # Update with higher confidence
    updated = temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="vuln_test",
        value="Confirmed vulnerability",
        confidence=0.95,
        evidence="Full exploitation",
        iteration=8
    )
    
    # Should have updated
    assert updated.confidence == 0.95
    assert updated.value == "Confirmed vulnerability"


def test_fact_not_updated_lower_confidence(temp_fact_store):
    """Test that fact is NOT updated with lower confidence."""
    # Add initial fact
    original = temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="vuln_test",
        value="Strong evidence",
        confidence=0.95,
        evidence="Multiple confirmations",
        iteration=5
    )
    
    # Try to update with lower confidence
    result = temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="vuln_test",
        value="Weaker evidence",
        confidence=0.85,
        evidence="Single test",
        iteration=8
    )
    
    # Should return original (not updated)
    assert result.confidence == 0.95
    assert result.value == "Strong evidence"


def test_get_stats(temp_fact_store):
    """Test statistics generation."""
    # Add facts
    temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="v1",
        value="test",
        confidence=0.9,
        evidence="test",
        iteration=1
    )
    
    temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="v2",
        value="test",
        confidence=0.85,
        evidence="test",
        iteration=2
    )
    
    temp_fact_store.add_fact(
        type=FactType.CREDENTIAL,
        key="c1",
        value="test",
        confidence=0.95,
        evidence="test",
        iteration=3
    )
    
    stats = temp_fact_store.get_stats()
    
    assert stats["total_facts"] == 3
    assert stats["by_type"]["vulnerability"] == 2
    assert stats["by_type"]["credential"] == 1
    assert stats["avg_confidence"] > 0.8
    assert stats["has_vulnerabilities"] is True


def test_clear_facts(temp_fact_store):
    """Test clearing all facts."""
    # Add facts
    temp_fact_store.add_fact(
        type=FactType.VULNERABILITY,
        key="v1",
        value="test",
        confidence=0.9,
        evidence="test",
        iteration=1
    )
    
    # Clear
    temp_fact_store.clear()
    
    # Should be empty
    assert len(temp_fact_store.facts) == 0
    assert not temp_fact_store.has_vulnerability()


def test_flag_fragment_storage(temp_fact_store):
    """Test storing flag fragments (multi-part flags)."""
    # Add first fragment
    temp_fact_store.add_fact(
        type=FactType.FLAG_FRAGMENT,
        key="flag_part1",
        value="picoCTF{first_part_",
        confidence=0.85,
        evidence="Found in /admin endpoint",
        iteration=10
    )
    
    # Add second fragment
    temp_fact_store.add_fact(
        type=FactType.FLAG_FRAGMENT,
        key="flag_part2",
        value="_second_part}",
        confidence=0.82,
        evidence="Found in /secret endpoint",
        iteration=15
    )
    
    # Get all fragments
    fragments = temp_fact_store.get_flag_fragments()
    
    assert len(fragments) == 2
    
    # In real agent, would combine fragments to form complete flag


def test_concurrent_fact_addition(temp_fact_store):
    """Test that multiple facts can be added without conflicts."""
    # Simulate discovering multiple things simultaneously
    facts_to_add = [
        ("vuln1", FactType.VULNERABILITY, "XSS in form", 0.9),
        ("vuln2", FactType.VULNERABILITY, "SQLi in search", 0.92),
        ("creds", FactType.CREDENTIAL, "admin:pass", 0.95),
        ("session", FactType.SESSION, "token123", 0.88),
    ]
    
    for key, ftype, value, conf in facts_to_add:
        temp_fact_store.add_fact(
            type=ftype,
            key=key,
            value=value,
            confidence=conf,
            evidence="test",
            iteration=1
        )
    
    # All should be stored
    assert len(temp_fact_store.facts) == 4
    
    # Each should be retrievable
    for key, _, _, _ in facts_to_add:
        assert temp_fact_store.has_fact(key)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
