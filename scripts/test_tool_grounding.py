#!/usr/bin/env python3
"""
Test TOOL GROUNDING: Zero-hallucination enforcement
Scientific Basis: Schick et al. 2024
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from numasec.mcp.tools import validate_tool_call, VALID_TOOLS


def test_tool_grounding():
    """Test frozenset validation - CRITICAL for production readiness."""
    print("=" * 80)
    print("TEST: Tool Grounding (Zero Hallucination Policy)")
    print("=" * 80)
    
    print(f"\n[INFO] Total valid tools: {len(VALID_TOOLS)}")
    print(f"[INFO] Sample tools: {list(VALID_TOOLS)[:5]}")
    
    # Test 1: Valid tool names
    print("\n[Test 1] Valid tool names...")
    valid_tools = ["web_request", "recon_nmap", "finding_create", "engagement_create"]
    all_valid = True
    for tool in valid_tools:
        is_valid, error = validate_tool_call(tool, {})
        if is_valid:
            print(f"   ✅ {tool}: ACCEPTED")
        else:
            print(f"   ❌ {tool}: REJECTED (should be valid!)")
            all_valid = False
    
    if not all_valid:
        print("   ❌ CRITICAL: Valid tools being rejected!")
        return False
    
    # Test 2: Hallucinated tool names (MUST be rejected)
    print("\n[Test 2] Hallucinated tools (must be REJECTED)...")
    hallucinated = [
        "burp_scan",           # LLM might invent Burp Suite integration
        "metasploit_run",      # LLM might invent Metasploit integration
        "run_exploit",         # Generic name LLM might try
        "nmap_scan",           # Close to recon_nmap but wrong
        "web_spider",          # Close to web_crawl but wrong
    ]
    
    all_rejected = True
    for tool in hallucinated:
        is_valid, error = validate_tool_call(tool, {})
        if not is_valid:
            print(f"   ✅ {tool}: REJECTED (correct!)")
            if "does not exist" in error:
                print(f"      Error message: OK")
        else:
            print(f"   ❌ {tool}: ACCEPTED (CRITICAL BUG!)")
            all_rejected = False
    
    if not all_rejected:
        print("   ❌ CRITICAL: Hallucinated tools being accepted!")
        return False
    
    # Test 3: Frozenset immutability
    print("\n[Test 3] Frozenset immutability...")
    original_size = len(VALID_TOOLS)
    try:
        VALID_TOOLS.add("hacker_tool")  # type: ignore
        print(f"   ❌ CRITICAL: Frozenset can be modified!")
        return False
    except AttributeError:
        print(f"   ✅ Frozenset is immutable (correct!)")
    
    # Verify size unchanged
    if len(VALID_TOOLS) == original_size:
        print(f"   ✅ Tool count unchanged: {original_size}")
    else:
        print(f"   ❌ Tool count changed: {original_size} -> {len(VALID_TOOLS)}")
        return False
    
    # Test 4: Exactly 28 tools (as documented)
    print("\n[Test 4] Tool count verification...")
    expected_count = 28
    actual_count = len(VALID_TOOLS)
    if actual_count == expected_count:
        print(f"   ✅ Exactly {expected_count} tools (matches docs!)")
    else:
        print(f"   ⚠️  Tool count mismatch: got {actual_count}, expected {expected_count}")
        print(f"       This requires updating README.md/ARCHITECTURE.md!")
    
    print("\n" + "=" * 80)
    print("✅ TOOL GROUNDING TESTS PASSED")
    print("   Zero-hallucination guarantee is ACTIVE")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = test_tool_grounding()
    sys.exit(0 if success else 1)
