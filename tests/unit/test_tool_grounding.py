"""
Unit tests for Tool Grounding (Zero Hallucination).

Tests that ONLY valid tools are accepted and hallucinated tools are rejected.
"""

import pytest
from numasec.mcp.tools import validate_tool_call, VALID_TOOLS


def test_valid_tool_accepted():
    """Test that valid tools are accepted."""
    # Test all valid tools
    for tool in VALID_TOOLS:
        is_valid, error = validate_tool_call(tool, {})
        assert is_valid, f"Valid tool '{tool}' was rejected"
        assert error == ""


def test_hallucinated_tool_rejected():
    """Test that hallucinated tools are rejected."""
    hallucinated_tools = [
        "burp_scan",
        "metasploit_run",
        "run_sqlinjection",
        "nessus_scan",
        "wireshark_capture",
        "exploit_buffer_overflow",
        "run_command",
    ]
    
    for tool in hallucinated_tools:
        is_valid, error = validate_tool_call(tool, {})
        assert not is_valid, f"Hallucinated tool '{tool}' was accepted!"
        assert "does not exist" in error
        assert "Valid tools:" in error


def test_error_message_contains_valid_tools():
    """Test that error message shows valid tools."""
    is_valid, error = validate_tool_call("fake_tool", {})
    
    assert not is_valid
    
    # Should list at least some valid tools
    assert "web_request" in error or "Valid tools:" in error


def test_tool_name_case_sensitivity():
    """Test that tool names are case-sensitive."""
    # Lowercase version should be valid
    is_valid, _ = validate_tool_call("web_request", {})
    assert is_valid
    
    # Uppercase version should be rejected
    is_valid, error = validate_tool_call("WEB_REQUEST", {})
    assert not is_valid
    assert "does not exist" in error


def test_valid_tools_frozenset_immutable():
    """Test that VALID_TOOLS is immutable (security guarantee)."""
    with pytest.raises(AttributeError):
        VALID_TOOLS.add("malicious_tool")
    
    with pytest.raises(AttributeError):
        VALID_TOOLS.remove("web_request")


def test_all_tool_categories_present():
    """Test that all tool categories are represented."""
    # Engagement tools
    assert "engagement_create" in VALID_TOOLS
    assert "engagement_status" in VALID_TOOLS
    
    # Recon tools
    assert "recon_nmap" in VALID_TOOLS
    assert "recon_dns" in VALID_TOOLS
    
    # Web tools
    assert "web_request" in VALID_TOOLS
    assert "web_sqlmap" in VALID_TOOLS
    
    # Exploit tools
    assert "exploit_script" in VALID_TOOLS
    assert "exploit_hydra" in VALID_TOOLS
    
    # Finding tools
    assert "finding_create" in VALID_TOOLS
    assert "finding_list" in VALID_TOOLS
    
    # Scratchpad tools
    assert "notes_write" in VALID_TOOLS
    assert "notes_read" in VALID_TOOLS


def test_tool_count():
    """Test that we have exactly 28 tools (as documented)."""
    # Updated from 26 → 28 (added notes_write, notes_read)
    assert len(VALID_TOOLS) == 28, (
        f"Expected 28 tools, found {len(VALID_TOOLS)}. "
        f"Update this test if tools are added/removed."
    )


def test_no_duplicate_tools():
    """Test that there are no duplicate tool names."""
    # Convert to list to check for duplicates
    tools_list = list(VALID_TOOLS)
    
    # frozenset automatically prevents duplicates, but verify
    assert len(tools_list) == len(set(tools_list))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
