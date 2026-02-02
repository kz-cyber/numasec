#!/usr/bin/env python3
"""
Test Finding Management Tools (MCP Protocol)
Task 5/34: Verify finding_create, finding_list, finding_update
"""

import sys
import json
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from numasec.mcp.tools import (
    VALID_TOOLS,
    handle_finding_create,
    handle_finding_list,
    handle_finding_update,
    handle_engagement_create
)


async def test_finding_management():
    """Test full finding lifecycle: create → update → list"""
    
    print("=" * 80)
    print("TEST: Finding Management (MCP Tools)")
    print("=" * 80)
    
    # Setup: Create engagement first
    print("\n[Setup] Creating engagement...")
    try:
        eng_result = await handle_engagement_create({
            "target": "test-findings.local",
            "scope": ["test-findings.local"]
        })
        print(f"   ✅ Engagement active: {eng_result.get('name', 'N/A')}")
    except Exception as e:
        print(f"   ❌ Engagement setup failed: {e}")
        return False
    
    # Test 1: Create finding
    print("\n[Test 1] Creating finding...")
    create_params = {
        "title": "SQL Injection in Login",
        "severity": "critical",
        "description": "Username parameter vulnerable to SQL injection. Payload: admin'-- bypassed authentication.",
        "endpoint": "/login",
        "parameter": "username",
        "payload": "admin'--",
        "evidence": "HTTP/1.1 200 OK\n{\"status\": \"authenticated\"}"
    }
    
    try:
        result = await handle_finding_create(create_params)
        result_dict = json.loads(result) if isinstance(result, str) else result
        
        if result_dict.get("success"):
            finding_id = result_dict.get("finding_id", result_dict.get("id"))
            print(f"   ✅ Finding created: ID={finding_id}")
        else:
            print(f"   ❌ Creation failed: {result_dict.get('error', 'Unknown')}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Test 2: List all findings
    print("\n[Test 2] Listing all findings...")
    try:
        result = await handle_finding_list({})
        result_dict = json.loads(result) if isinstance(result, str) else result
        
        findings = result_dict.get("findings", [])
        count = result_dict.get("count", 0)
        
        if count >= 1:
            print(f"   ✅ Found {count} finding(s)")
            for f in findings:
                print(f"      - [{f.get('severity', 'N/A')}] {f.get('title', 'N/A')}")
        else:
            print(f"   ❌ No findings returned (expected at least 1)")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Test 3: Update finding (add remediation)
    print("\n[Test 3] Updating finding...")
    update_params = {
        "finding_id": finding_id,
        "updates": {
            "remediation": "Use parameterized queries or prepared statements"
        }
    }
    
    try:
        result = await handle_finding_update(update_params)
        result_dict = json.loads(result) if isinstance(result, str) else result
        
        if result_dict.get("success"):
            print(f"   ✅ Finding updated")
        else:
            print(f"   ❌ Update failed")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    print("\n" + "=" * 80)
    print("✅ FINDING MANAGEMENT TESTS PASSED")
    print("   All 3 tools (create/list/update) are FUNCTIONAL")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = asyncio.run(test_finding_management())
    sys.exit(0 if success else 1)
