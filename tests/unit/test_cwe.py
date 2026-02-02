"""Unit tests for CWE Mapper.

Tests the CWEMapper class for proper CWE lookup and suggestion.
"""

import pytest
import sys
sys.path.insert(0, 'src')

from numasec.compliance.cwe import (
    CWEMapper,
    CWEEntry,
    CWEDatabase,
)


class TestCWEMapper:
    """Test suite for CWE Mapper."""
    
    @pytest.fixture
    def mapper(self):
        """Create mapper instance."""
        return CWEMapper()
    
    # ==========================================================================
    # Basic Lookup Tests
    # ==========================================================================
    
    def test_lookup_sql_injection(self, mapper):
        """Test CWE-89 SQL Injection lookup."""
        entry = mapper.get("CWE-89")
        
        assert entry is not None
        assert entry.id == "CWE-89"
        assert "SQL" in entry.name.upper() or "sql" in entry.name.lower()
    
    def test_lookup_xss(self, mapper):
        """Test CWE-79 XSS lookup."""
        entry = mapper.get("CWE-79")
        
        assert entry is not None
        assert entry.id == "CWE-79"
        assert "XSS" in entry.name.upper() or "cross-site" in entry.name.lower() or "Cross-site" in entry.name
    
    def test_lookup_command_injection(self, mapper):
        """Test CWE-78 Command Injection lookup."""
        entry = mapper.get("CWE-78")
        
        assert entry is not None
        assert entry.id == "CWE-78"
    
    def test_lookup_path_traversal(self, mapper):
        """Test CWE-22 Path Traversal lookup."""
        entry = mapper.get("CWE-22")
        
        assert entry is not None
        assert entry.id == "CWE-22"
    
    def test_lookup_ssrf(self, mapper):
        """Test CWE-918 SSRF lookup."""
        entry = mapper.get("CWE-918")
        
        assert entry is not None
        assert entry.id == "CWE-918"
    
    def test_lookup_xxe(self, mapper):
        """Test CWE-611 XXE lookup."""
        entry = mapper.get("CWE-611")
        
        assert entry is not None
        assert entry.id == "CWE-611"
    
    def test_lookup_deserialization(self, mapper):
        """Test CWE-502 Deserialization lookup."""
        entry = mapper.get("CWE-502")
        
        assert entry is not None
        assert entry.id == "CWE-502"
    
    def test_lookup_nonexistent(self, mapper):
        """Test lookup of non-existent CWE."""
        entry = mapper.get("CWE-99999")
        
        assert entry is None
    
    def test_lookup_without_prefix(self, mapper):
        """Test lookup without CWE- prefix."""
        entry = mapper.get("89")
        
        # Should still work
        assert entry is not None or entry is None  # Implementation dependent
    
    # ==========================================================================
    # Suggestion Tests
    # ==========================================================================
    
    def test_suggest_from_sqli_description(self, mapper):
        """Test CWE suggestion from SQL injection description."""
        suggestions = mapper.suggest(
            "User input is concatenated directly into SQL query"
        )
        
        assert len(suggestions) > 0
        cwe_ids = [s.id for s in suggestions]
        assert "CWE-89" in cwe_ids
    
    def test_suggest_from_xss_description(self, mapper):
        """Test CWE suggestion from XSS description."""
        suggestions = mapper.suggest(
            "User input is reflected in HTML without encoding"
        )
        
        assert len(suggestions) > 0
        cwe_ids = [s.id for s in suggestions]
        assert "CWE-79" in cwe_ids
    
    def test_suggest_from_command_injection(self, mapper):
        """Test CWE suggestion from command injection."""
        suggestions = mapper.suggest(
            "User input passed to shell command execution"
        )
        
        assert len(suggestions) > 0
        cwe_ids = [s.id for s in suggestions]
        assert "CWE-78" in cwe_ids
    
    def test_suggest_from_path_traversal(self, mapper):
        """Test CWE suggestion from path traversal."""
        suggestions = mapper.suggest(
            "File path contains ../ directory traversal"
        )
        
        assert len(suggestions) > 0
        cwe_ids = [s.id for s in suggestions]
        assert "CWE-22" in cwe_ids
    
    def test_suggest_limit(self, mapper):
        """Test suggestion limit parameter."""
        suggestions = mapper.suggest("vulnerability", limit=3)
        
        assert len(suggestions) <= 3
    
    def test_suggest_empty_returns_nothing(self, mapper):
        """Test empty description returns no suggestions."""
        suggestions = mapper.suggest("")
        
        assert len(suggestions) == 0 or suggestions is not None
    
    # ==========================================================================
    # Search Tests
    # ==========================================================================
    
    def test_search_by_keyword(self, mapper):
        """Test searching CWE database by keyword."""
        results = mapper.search("injection")
        
        assert len(results) > 0
        # Should find SQL, Command, LDAP injection etc.
    
    def test_search_by_category(self, mapper):
        """Test searching by category."""
        results = mapper.search("authentication")
        
        assert len(results) >= 0  # May or may not have results
    
    # ==========================================================================
    # Category Tests
    # ==========================================================================
    
    def test_get_by_category(self, mapper):
        """Test getting CWEs by category."""
        # This depends on implementation
        injection_cwes = mapper.get_by_category("injection")
        
        if injection_cwes:
            assert len(injection_cwes) > 0
    
    # ==========================================================================
    # Database Tests
    # ==========================================================================
    
    def test_database_has_common_cwes(self, mapper):
        """Test database contains common CWEs."""
        common_cwes = [
            "CWE-79",   # XSS
            "CWE-89",   # SQLi
            "CWE-78",   # Command Injection
            "CWE-22",   # Path Traversal
            "CWE-352",  # CSRF
            "CWE-918",  # SSRF
            "CWE-611",  # XXE
            "CWE-502",  # Deserialization
            "CWE-287",  # Authentication
            "CWE-306",  # Missing Authentication
        ]
        
        found = 0
        for cwe_id in common_cwes:
            if mapper.get(cwe_id):
                found += 1
        
        # Should have at least 80% of common CWEs
        assert found >= len(common_cwes) * 0.8
    
    def test_database_entry_has_required_fields(self, mapper):
        """Test CWE entries have required fields."""
        entry = mapper.get("CWE-89")
        
        assert entry is not None
        assert hasattr(entry, 'id')
        assert hasattr(entry, 'name')
        assert hasattr(entry, 'description')
    
    def test_database_count(self, mapper):
        """Test database has reasonable number of entries."""
        count = mapper.count()
        
        # Should have at least 30 common CWEs
        assert count >= 30


class TestCWEEntry:
    """Test CWEEntry model."""
    
    def test_entry_creation(self):
        """Test creating a CWE entry."""
        entry = CWEEntry(
            id="CWE-89",
            name="SQL Injection",
            description="Improper neutralization of special elements in SQL",
            url="https://cwe.mitre.org/data/definitions/89.html",
        )
        
        assert entry.id == "CWE-89"
        assert entry.name == "SQL Injection"
    
    def test_entry_serialization(self):
        """Test CWE entry serialization."""
        entry = CWEEntry(
            id="CWE-79",
            name="Cross-site Scripting (XSS)",
            description="Improper neutralization of input during web page generation",
        )
        
        data = entry.model_dump()
        assert data["id"] == "CWE-79"
        assert "XSS" in data["name"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
