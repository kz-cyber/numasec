"""Unit tests for Knowledge Store.

Tests the KnowledgeStore and InMemoryKnowledgeStore classes.
"""

import pytest
import asyncio
import sys
sys.path.insert(0, 'src')

from numasec.knowledge.store import (
    InMemoryKnowledgeStore,
    PayloadEntry,
    TechniqueEntry,
    WriteupEntry,
    ReflexionEntry,
    SearchResult,
    generate_payload_id,
)
from numasec.knowledge.seeds.payloads import (
    SQLI_PAYLOADS,
    XSS_PAYLOADS,
    get_payload_count,
    get_payload_stats,
)


class TestInMemoryKnowledgeStore:
    """Test suite for InMemoryKnowledgeStore."""
    
    @pytest.fixture
    def store(self):
        """Create store instance."""
        store = InMemoryKnowledgeStore()
        asyncio.get_event_loop().run_until_complete(store.initialize())
        return store
    
    # ==========================================================================
    # Payload Tests
    # ==========================================================================
    
    def test_add_payload(self, store):
        """Test adding a single payload."""
        payload = PayloadEntry(
            id="test-001",
            name="Test SQLi",
            category="sqli",
            payload="' OR '1'='1",
            description="Basic SQL injection",
            use_case="Login bypass",
            tags=["auth-bypass", "basic"],
        )
        
        result = asyncio.get_event_loop().run_until_complete(
            store.add_payload(payload)
        )
        
        assert result == "test-001"
    
    def test_add_payloads_bulk(self, store):
        """Test bulk adding payloads."""
        payloads = SQLI_PAYLOADS[:10]
        
        count = asyncio.get_event_loop().run_until_complete(
            store.add_payloads(payloads)
        )
        
        assert count == 10
    
    def test_search_payloads_keyword(self, store):
        """Test searching payloads by keyword."""
        # Add some payloads
        asyncio.get_event_loop().run_until_complete(
            store.add_payloads(SQLI_PAYLOADS[:20])
        )
        
        # Search
        results = asyncio.get_event_loop().run_until_complete(
            store.search_payloads("authentication bypass", limit=5)
        )
        
        assert len(results) > 0
        assert all(isinstance(r, SearchResult) for r in results)
    
    def test_search_payloads_category_filter(self, store):
        """Test searching with category filter."""
        # Add payloads from different categories
        asyncio.get_event_loop().run_until_complete(
            store.add_payloads(SQLI_PAYLOADS[:10])
        )
        asyncio.get_event_loop().run_until_complete(
            store.add_payloads(XSS_PAYLOADS[:10])
        )
        
        # Search only SQLi
        results = asyncio.get_event_loop().run_until_complete(
            store.search_payloads("injection", category="sqli", limit=5)
        )
        
        for r in results:
            assert r.entry["category"] == "sqli"
    
    def test_search_payloads_empty_query(self, store):
        """Test search with empty query."""
        results = asyncio.get_event_loop().run_until_complete(
            store.search_payloads("", limit=5)
        )
        
        # Should return empty or handle gracefully
        assert results is not None
    
    # ==========================================================================
    # Technique Tests
    # ==========================================================================
    
    def test_add_technique(self, store):
        """Test adding a technique."""
        technique = TechniqueEntry(
            id="tech-001",
            name="SQL Injection Detection",
            category="reconnaissance",
            description="Detect SQL injection vulnerabilities",
            steps=["Test parameters", "Analyze responses"],
            tools=["sqlmap", "manual testing"],
            mitre_id="T1190",
            tags=["web", "injection"],
        )
        
        result = asyncio.get_event_loop().run_until_complete(
            store.add_technique(technique)
        )
        
        assert result == "tech-001"
    
    def test_search_techniques(self, store):
        """Test searching techniques."""
        # Add technique
        technique = TechniqueEntry(
            id="tech-001",
            name="Privilege Escalation via SUID",
            category="privilege_escalation",
            description="Exploit SUID binaries for privilege escalation",
            steps=["Find SUID files", "Check GTFOBins"],
            tools=["find", "linpeas"],
            tags=["linux", "privesc"],
        )
        asyncio.get_event_loop().run_until_complete(
            store.add_technique(technique)
        )
        
        # Search
        results = asyncio.get_event_loop().run_until_complete(
            store.search_techniques("privilege escalation linux", limit=5)
        )
        
        assert len(results) > 0
    
    # ==========================================================================
    # Writeup Tests
    # ==========================================================================
    
    def test_add_writeup(self, store):
        """Test adding a writeup."""
        writeup = WriteupEntry(
            id="writeup-001",
            title="HackTheBox - Machine",
            platform="HackTheBox",
            category="web",
            difficulty="medium",
            summary="Web exploitation challenge",
            techniques=["SQL injection", "privilege escalation"],
            vulnerabilities=["CWE-89"],
            tools=["sqlmap", "linpeas"],
            key_insights=["Check for UNION-based SQLi"],
            content="Full writeup content here...",
            tags=["htb", "web", "sqli"],
        )
        
        result = asyncio.get_event_loop().run_until_complete(
            store.add_writeup(writeup)
        )
        
        assert result == "writeup-001"
    
    def test_search_writeups(self, store):
        """Test searching writeups."""
        # Add writeup
        writeup = WriteupEntry(
            id="writeup-001",
            title="PicoCTF - Web Challenge",
            platform="PicoCTF",
            category="web",
            summary="XSS and session hijacking",
            techniques=["XSS", "cookie stealing"],
            content="Writeup content...",
        )
        asyncio.get_event_loop().run_until_complete(
            store.add_writeup(writeup)
        )
        
        # Search
        results = asyncio.get_event_loop().run_until_complete(
            store.search_writeups("XSS cookie", limit=5)
        )
        
        assert len(results) > 0
    
    # ==========================================================================
    # Reflexion Tests
    # ==========================================================================
    
    def test_add_reflexion(self, store):
        """Test adding a reflexion entry."""
        reflexion = ReflexionEntry(
            id="refl-001",
            engagement_id="eng-123",
            action_type="sqli_attempt",
            action_description="Tried UNION-based SQLi",
            context={"target": "login.php", "parameter": "username"},
            outcome="failure",
            reason="WAF blocked UNION keyword",
            lesson_learned="Try case variation or encoding",
            confidence=0.8,
            applicable_scenarios=["WAF present", "UNION blocked"],
            tags=["waf-bypass", "sqli"],
        )
        
        result = asyncio.get_event_loop().run_until_complete(
            store.add_reflexion(reflexion)
        )
        
        assert result == "refl-001"
    
    def test_search_reflexions(self, store):
        """Test searching reflexions."""
        # Add reflexion
        reflexion = ReflexionEntry(
            id="refl-001",
            engagement_id="eng-123",
            action_type="xss_attempt",
            action_description="Tried basic XSS",
            outcome="success",
            reason="No output encoding",
            lesson_learned="Always try basic payloads first",
            tags=["xss", "basic"],
        )
        asyncio.get_event_loop().run_until_complete(
            store.add_reflexion(reflexion)
        )
        
        # Search
        results = asyncio.get_event_loop().run_until_complete(
            store.search_reflexions("XSS encoding", limit=5)
        )
        
        assert len(results) > 0
    
    # ==========================================================================
    # Unified Search Tests
    # ==========================================================================
    
    def test_unified_search(self, store):
        """Test unified search across all types."""
        # Add various entries
        asyncio.get_event_loop().run_until_complete(
            store.add_payloads(SQLI_PAYLOADS[:5])
        )
        
        technique = TechniqueEntry(
            id="tech-001",
            name="SQL Injection Testing",
            category="exploitation",
            description="Test for SQL injection",
        )
        asyncio.get_event_loop().run_until_complete(
            store.add_technique(technique)
        )
        
        # Unified search
        results = asyncio.get_event_loop().run_until_complete(
            store.search("SQL injection", limit=10)
        )
        
        assert results.total_count > 0
        # Should have both payloads and techniques
        entry_types = set(r.entry_type for r in results.results)
        assert len(entry_types) >= 1
    
    def test_unified_search_filter_types(self, store):
        """Test unified search with type filter."""
        asyncio.get_event_loop().run_until_complete(
            store.add_payloads(SQLI_PAYLOADS[:5])
        )
        
        # Search only payloads
        results = asyncio.get_event_loop().run_until_complete(
            store.search("injection", entry_types=["payload"], limit=10)
        )
        
        for r in results.results:
            assert r.entry_type == "payload"
    
    # ==========================================================================
    # Statistics Tests
    # ==========================================================================
    
    def test_get_stats(self, store):
        """Test getting store statistics."""
        asyncio.get_event_loop().run_until_complete(
            store.add_payloads(SQLI_PAYLOADS[:5])
        )
        
        stats = asyncio.get_event_loop().run_until_complete(
            store.get_stats()
        )
        
        assert stats["payloads"] == 5
        assert stats["techniques"] == 0
        assert stats["writeups"] == 0
        assert stats["reflexions"] == 0


class TestPayloadSeeds:
    """Test payload seeds."""
    
    def test_payload_count(self):
        """Test total payload count."""
        count = get_payload_count()
        
        # Should have at least 100 payloads
        assert count >= 100
    
    def test_payload_stats(self):
        """Test payload statistics."""
        stats = get_payload_stats()
        
        # Should have multiple categories
        assert len(stats) >= 5
        
        # Each category should have payloads
        for category, count in stats.items():
            assert count > 0
    
    def test_sqli_payloads_have_required_fields(self):
        """Test SQLi payloads have required fields."""
        for payload in SQLI_PAYLOADS:
            assert payload.id is not None
            assert payload.name is not None
            assert payload.category == "sqli"
            assert payload.payload is not None
            assert payload.description is not None
    
    def test_xss_payloads_have_required_fields(self):
        """Test XSS payloads have required fields."""
        for payload in XSS_PAYLOADS:
            assert payload.id is not None
            assert payload.name is not None
            assert payload.category == "xss"
            assert payload.payload is not None


class TestPayloadEntry:
    """Test PayloadEntry model."""
    
    def test_embedding_text(self):
        """Test embedding text generation."""
        payload = PayloadEntry(
            id="test-001",
            name="Test Payload",
            category="sqli",
            payload="' OR '1'='1",
            description="SQL injection bypass",
            use_case="Login forms",
            tags=["auth", "bypass"],
        )
        
        text = payload.embedding_text
        
        assert "sqli" in text
        assert "Test Payload" in text
        assert "SQL injection bypass" in text
        assert "auth" in text
    
    def test_id_generation(self):
        """Test deterministic ID generation."""
        id1 = generate_payload_id("sqli", "test")
        id2 = generate_payload_id("sqli", "test")
        id3 = generate_payload_id("xss", "test")
        
        # Same inputs should give same ID
        assert id1 == id2
        
        # Different inputs should give different IDs
        assert id1 != id3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
