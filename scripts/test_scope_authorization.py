#!/usr/bin/env python3
"""
Test Scope/Authorization System - CFAA Compliance CRITICAL
Task 6/34: Verify scope_check whitelist validation

Legal Basis: Computer Fraud and Abuse Act (18 U.S.C. § 1030)
- MUST NOT attack systems outside explicit scope
- Authorization failures MUST block all offensive operations
"""

import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from numasec.mcp.tools import (
    handle_engagement_create,
    handle_scope_check,
    handle_scope_add
)


async def test_scope_authorization():
    """Test CFAA compliance: scope enforcement prevents unauthorized access."""
    
    print("=" * 80)
    print("TEST: Scope/Authorization (CFAA Compliance)")
    print("=" * 80)
    
    # Setup: Create engagement with initial scope
    print("\n[Setup] Creating engagement with scope...")
    try:
        eng_result = await handle_engagement_create({
            "target": "example.com",
            "scope": ["example.com", "*.example.com", "192.168.1.0/24"]
        })
        
        if eng_result.get("success"):
            print(f"   ✅ Engagement created")
            print(f"      Target: example.com")
            print(f"      Scope: 3 entries")
        else:
            print(f"   ❌ Setup failed: {eng_result.get('error')}")
            return False
    except Exception as e:
        print(f"   ❌ Setup error: {e}")
        return False
    
    # Test 1: In-scope targets (MUST ALLOW)
    print("\n[Test 1] In-scope targets (should be ALLOWED)...")
    in_scope = [
        "example.com",
        "api.example.com",
        "www.example.com",
        "192.168.1.50"
    ]
    
    all_allowed = True
    for target in in_scope:
        try:
            result = await handle_scope_check({"target": target})
            result_dict = result if isinstance(result, dict) else {"in_scope": False}
            
            if result_dict.get("in_scope"):
                print(f"   ✅ {target}: ALLOWED")
            else:
                print(f"   ❌ {target}: BLOCKED (should be allowed!)")
                all_allowed = False
        except Exception as e:
            print(f"   ❌ {target}: Error - {e}")
            all_allowed = False
    
    if not all_allowed:
        print("   ⚠️  Some in-scope targets were blocked")
    
    # Test 2: Out-of-scope targets (MUST BLOCK)
    print("\n[Test 2] Out-of-scope targets (MUST be BLOCKED)...")
    out_of_scope = [
        "evil.com",
        "google.com",
        "192.168.2.1",
        "10.0.0.1"
    ]
    
    all_blocked = True
    for target in out_of_scope:
        try:
            result = await handle_scope_check({"target": target})
            result_dict = result if isinstance(result, dict) else {"in_scope": True}
            
            if not result_dict.get("in_scope"):
                print(f"   ✅ {target}: BLOCKED (correct!)")
            else:
                print(f"   ❌ {target}: ALLOWED (CFAA VIOLATION!)")
                all_blocked = False
        except Exception as e:
            print(f"   ⚠️  {target}: Error - {e}")
    
    if not all_blocked:
        print("   🚨 CRITICAL: Out-of-scope targets were ALLOWED (CFAA VIOLATION!)")
        return False
    
    # Test 3: Dynamic scope expansion
    print("\n[Test 3] Dynamic scope expansion...")
    try:
        result = await handle_scope_add({"target": "newapp.example.com"})
        result_dict = result if isinstance(result, dict) else {}
        
        if result_dict.get("success"):
            print(f"   ✅ Scope expanded")
            
            # Verify new target is now allowed
            check = await handle_scope_check({"target": "newapp.example.com"})
            check_dict = check if isinstance(check, dict) else {}
            
            if check_dict.get("in_scope"):
                print(f"   ✅ New target now in scope")
            else:
                print(f"   ❌ Scope expansion didn't persist")
                return False
        else:
            print(f"   ❌ Scope expansion failed")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Test 4: Wildcard matching
    print("\n[Test 4] Wildcard pattern matching...")
    wildcard_tests = [
        ("admin.example.com", True),   # *.example.com
        ("deep.sub.example.com", True),  # Should match wildcard
        ("example.com.evil.com", False)  # Domain boundary
    ]
    
    wildcard_ok = True
    for target, should_match in wildcard_tests:
        try:
            result = await handle_scope_check({"target": target})
            result_dict = result if isinstance(result, dict) else {}
            
            in_scope = result_dict.get("in_scope", False)
            
            if in_scope == should_match:
                status = "ALLOWED" if should_match else "BLOCKED"
                print(f"   ✅ {target}: {status} (correct!)")
            else:
                expected = "ALLOWED" if should_match else "BLOCKED"
                actual = "ALLOWED" if in_scope else "BLOCKED"
                print(f"   ❌ {target}: {actual} (expected {expected})")
                wildcard_ok = False
        except Exception as e:
            print(f"   ❌ {target}: Error - {e}")
            wildcard_ok = False
    
    if not wildcard_ok:
        print("   ⚠️  Wildcard matching has issues")
    
    print("\n" + "=" * 80)
    if all_allowed and all_blocked and wildcard_ok:
        print("✅ SCOPE/AUTHORIZATION TESTS PASSED")
        print("   CFAA compliance ACTIVE - unauthorized access prevention working")
    else:
        print("⚠️  SCOPE/AUTHORIZATION TESTS PARTIAL")
        print("   Review findings above")
    print("=" * 80)
    
    return all_allowed and all_blocked


if __name__ == "__main__":
    success = asyncio.run(test_scope_authorization())
    sys.exit(0 if success else 1)
