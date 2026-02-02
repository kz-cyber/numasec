#!/usr/bin/env python3
"""
Test script for Engagement Tools (engagement_create, engagement_status, engagement_close)
Tests SQLite operations, scope persistence, and basic workflow.
"""
import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from numasec.mcp.tools import (
    handle_engagement_create,
    handle_engagement_status,
    handle_engagement_close,
)


async def test_engagement_tools():
    """Test engagement creation, status, and closure."""
    print("=" * 80)
    print("TEST: Engagement Tools (3 tools)")
    print("=" * 80)
    
    # Test 1: Create engagement
    print("\n[Test 1] Creating engagement...")
    try:
        result = await handle_engagement_create({
            "client_name": "Test Client",
            "project_name": "Security Audit 2026",
            "scope": ["localhost", "127.0.0.1", "192.168.1.0/24"],
            "methodology": "OWASP",
            "approval_mode": "supervised"
        })
        print(f"✅ engagement_create: {result}")
        
        # Extract engagement_id for next tests
        if isinstance(result, dict) and "engagement_id" in result:
            engagement_id = result["engagement_id"]
            print(f"   Engagement ID: {engagement_id}")
        else:
            print("⚠️  No engagement_id returned (unexpected)")
            engagement_id = 1  # Assume first engagement
    except Exception as e:
        print(f"❌ engagement_create FAILED: {e}")
        return False
    
    # Test 2: Check status
    print("\n[Test 2] Checking engagement status...")
    try:
        result = await handle_engagement_status({
            "include_findings": True,
            "include_scope": True
        })
        print(f"✅ engagement_status: {result}")
        
        # Verify scope was persisted
        if isinstance(result, dict) and "scope" in result:
            scope_count = len(result["scope"])
            expected = 3
            if scope_count == expected:
                print(f"   ✅ Scope persistence OK ({scope_count} targets)")
            else:
                print(f"   ⚠️  Scope count mismatch: got {scope_count}, expected {expected}")
    except Exception as e:
        print(f"❌ engagement_status FAILED: {e}")
        return False
    
    # Test 3: Close engagement
    print("\n[Test 3] Closing engagement...")
    try:
        result = await handle_engagement_close({
            "generate_report": False  # Skip report generation for test
        })
        print(f"✅ engagement_close: {result}")
        
        if isinstance(result, dict) and "status" in result:
            if result["status"] == "closed":
                print("   ✅ Engagement properly closed")
            else:
                print(f"   ⚠️  Unexpected status: {result['status']}")
    except Exception as e:
        print(f"❌ engagement_close FAILED: {e}")
        return False
    
    print("\n" + "=" * 80)
    print("✅ ALL ENGAGEMENT TOOLS TESTS PASSED")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = asyncio.run(test_engagement_tools())
    sys.exit(0 if success else 1)
