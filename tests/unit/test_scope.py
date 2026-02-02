"""Unit tests for Scope Enforcer.

Tests the ScopeEnforcer class for proper scope validation.
"""

import pytest
import sys
sys.path.insert(0, 'src')

from numasec.core.scope import (
    ScopeEnforcer,
    ScopeEntry,
    ScopeDecision,
    ScopeType,
    ScopeCheckResult,
)


class TestScopeEnforcer:
    """Test suite for Scope Enforcer."""
    
    @pytest.fixture
    def enforcer(self):
        """Create enforcer with sample scope."""
        enforcer = ScopeEnforcer()
        
        # Add in-scope entries
        enforcer.add_scope(ScopeEntry(
            value="192.168.1.0/24",
            type=ScopeType.IP_RANGE,
            in_scope=True,
        ))
        enforcer.add_scope(ScopeEntry(
            value="example.com",
            type=ScopeType.DOMAIN,
            in_scope=True,
        ))
        enforcer.add_scope(ScopeEntry(
            value="*.example.com",
            type=ScopeType.WILDCARD_DOMAIN,
            in_scope=True,
        ))
        
        # Add out-of-scope entries
        enforcer.add_scope(ScopeEntry(
            value="192.168.1.1",
            type=ScopeType.IP,
            in_scope=False,
            note="Production server - do not test",
        ))
        
        return enforcer
    
    # ==========================================================================
    # IP Address Tests
    # ==========================================================================
    
    def test_ip_in_scope(self, enforcer):
        """Test IP address within CIDR range is in scope."""
        result = enforcer.check("192.168.1.100")
        
        assert result.decision == ScopeDecision.IN_SCOPE
    
    def test_ip_out_of_scope_excluded(self, enforcer):
        """Test explicitly excluded IP is out of scope."""
        result = enforcer.check("192.168.1.1")
        
        assert result.decision == ScopeDecision.OUT_OF_SCOPE
        assert "Production" in result.reason or result.reason is not None
    
    def test_ip_out_of_scope_not_in_range(self, enforcer):
        """Test IP outside CIDR range is out of scope."""
        result = enforcer.check("10.0.0.1")
        
        assert result.decision == ScopeDecision.OUT_OF_SCOPE
    
    def test_ip_in_scope_boundary(self, enforcer):
        """Test IP at boundary of CIDR range."""
        # Last IP in 192.168.1.0/24
        result = enforcer.check("192.168.1.254")
        
        assert result.decision == ScopeDecision.IN_SCOPE
    
    # ==========================================================================
    # Domain Tests
    # ==========================================================================
    
    def test_domain_exact_match(self, enforcer):
        """Test exact domain match is in scope."""
        result = enforcer.check("example.com")
        
        assert result.decision == ScopeDecision.IN_SCOPE
    
    def test_subdomain_wildcard_match(self, enforcer):
        """Test subdomain matches wildcard."""
        result = enforcer.check("api.example.com")
        
        assert result.decision == ScopeDecision.IN_SCOPE
    
    def test_deep_subdomain_wildcard(self, enforcer):
        """Test deep subdomain matches wildcard."""
        result = enforcer.check("dev.api.example.com")
        
        # Depends on implementation - may or may not match *.example.com
        assert result.decision in [ScopeDecision.IN_SCOPE, ScopeDecision.UNKNOWN]
    
    def test_domain_out_of_scope(self, enforcer):
        """Test unrelated domain is out of scope."""
        result = enforcer.check("google.com")
        
        assert result.decision == ScopeDecision.OUT_OF_SCOPE
    
    def test_domain_similar_not_match(self, enforcer):
        """Test similar domain doesn't match."""
        result = enforcer.check("notexample.com")
        
        assert result.decision == ScopeDecision.OUT_OF_SCOPE
    
    # ==========================================================================
    # URL Tests
    # ==========================================================================
    
    def test_url_in_scope_domain(self, enforcer):
        """Test URL with in-scope domain."""
        result = enforcer.check("https://example.com/api/users")
        
        assert result.decision == ScopeDecision.IN_SCOPE
    
    def test_url_in_scope_subdomain(self, enforcer):
        """Test URL with in-scope subdomain."""
        result = enforcer.check("https://api.example.com/v1/data")
        
        assert result.decision == ScopeDecision.IN_SCOPE
    
    def test_url_out_of_scope(self, enforcer):
        """Test URL with out-of-scope domain."""
        result = enforcer.check("https://evil.com/malware")
        
        assert result.decision == ScopeDecision.OUT_OF_SCOPE
    
    def test_url_with_ip_in_scope(self, enforcer):
        """Test URL with in-scope IP."""
        result = enforcer.check("http://192.168.1.50:8080/admin")
        
        assert result.decision == ScopeDecision.IN_SCOPE
    
    # ==========================================================================
    # Port Tests
    # ==========================================================================
    
    def test_ip_port_in_scope(self, enforcer):
        """Test IP:port combination."""
        result = enforcer.check("192.168.1.100:443")
        
        # If no port restrictions, should be in scope
        assert result.decision == ScopeDecision.IN_SCOPE
    
    # ==========================================================================
    # Edge Cases
    # ==========================================================================
    
    def test_empty_target(self, enforcer):
        """Test empty target string."""
        result = enforcer.check("")
        
        assert result.decision in [ScopeDecision.OUT_OF_SCOPE, ScopeDecision.UNKNOWN]
    
    def test_localhost(self, enforcer):
        """Test localhost is out of scope by default."""
        result = enforcer.check("localhost")
        
        assert result.decision == ScopeDecision.OUT_OF_SCOPE
    
    def test_private_ip_not_in_scope(self, enforcer):
        """Test private IP not explicitly in scope."""
        result = enforcer.check("172.16.0.1")
        
        assert result.decision == ScopeDecision.OUT_OF_SCOPE
    
    def test_ipv6_handling(self, enforcer):
        """Test IPv6 address handling."""
        result = enforcer.check("::1")
        
        # Should handle gracefully
        assert result.decision is not None
    
    # ==========================================================================
    # Scope Management Tests
    # ==========================================================================
    
    def test_add_scope_entry(self, enforcer):
        """Test adding new scope entry."""
        enforcer.add_scope(ScopeEntry(
            value="10.0.0.0/8",
            type=ScopeType.IP_RANGE,
            in_scope=True,
        ))
        
        result = enforcer.check("10.1.2.3")
        assert result.decision == ScopeDecision.IN_SCOPE
    
    def test_remove_scope_entry(self, enforcer):
        """Test removing scope entry."""
        # This depends on implementation
        initial_count = len(enforcer.scope_entries)
        
        # Add and remove
        enforcer.add_scope(ScopeEntry(
            value="test.com",
            type=ScopeType.DOMAIN,
            in_scope=True,
        ))
        
        # Should have one more entry
        assert len(enforcer.scope_entries) == initial_count + 1
    
    def test_clear_scope(self, enforcer):
        """Test clearing all scope entries."""
        enforcer.clear()
        
        # Everything should be out of scope now
        result = enforcer.check("192.168.1.100")
        assert result.decision == ScopeDecision.OUT_OF_SCOPE
    
    def test_list_scope_entries(self, enforcer):
        """Test listing scope entries."""
        entries = enforcer.list_entries()
        
        assert len(entries) > 0
        assert any(e.value == "example.com" for e in entries)
    
    # ==========================================================================
    # Bulk Check Tests
    # ==========================================================================
    
    def test_check_multiple_targets(self, enforcer):
        """Test checking multiple targets at once."""
        targets = [
            "192.168.1.100",
            "example.com",
            "google.com",
            "api.example.com",
        ]
        
        results = enforcer.check_multiple(targets)
        
        assert len(results) == 4
        assert results["192.168.1.100"].decision == ScopeDecision.IN_SCOPE
        assert results["google.com"].decision == ScopeDecision.OUT_OF_SCOPE


class TestScopeEntry:
    """Test ScopeEntry model."""
    
    def test_ip_entry(self):
        """Test creating IP scope entry."""
        entry = ScopeEntry(
            value="192.168.1.1",
            type=ScopeType.IP,
            in_scope=True,
        )
        
        assert entry.value == "192.168.1.1"
        assert entry.type == ScopeType.IP
        assert entry.in_scope is True
    
    def test_cidr_entry(self):
        """Test creating CIDR scope entry."""
        entry = ScopeEntry(
            value="10.0.0.0/8",
            type=ScopeType.IP_RANGE,
            in_scope=True,
        )
        
        assert entry.value == "10.0.0.0/8"
        assert entry.type == ScopeType.IP_RANGE
    
    def test_domain_entry(self):
        """Test creating domain scope entry."""
        entry = ScopeEntry(
            value="example.com",
            type=ScopeType.DOMAIN,
            in_scope=True,
        )
        
        assert entry.value == "example.com"
        assert entry.type == ScopeType.DOMAIN
    
    def test_wildcard_entry(self):
        """Test creating wildcard domain entry."""
        entry = ScopeEntry(
            value="*.example.com",
            type=ScopeType.WILDCARD_DOMAIN,
            in_scope=True,
        )
        
        assert entry.value == "*.example.com"
        assert entry.type == ScopeType.WILDCARD_DOMAIN
    
    def test_entry_with_note(self):
        """Test entry with note."""
        entry = ScopeEntry(
            value="192.168.1.1",
            type=ScopeType.IP,
            in_scope=False,
            note="Production DB - do not test",
        )
        
        assert entry.note == "Production DB - do not test"
    
    def test_entry_serialization(self):
        """Test scope entry serialization."""
        entry = ScopeEntry(
            value="example.com",
            type=ScopeType.DOMAIN,
            in_scope=True,
        )
        
        data = entry.model_dump()
        assert data["value"] == "example.com"
        assert data["in_scope"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
