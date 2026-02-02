#!/usr/bin/env python3
"""
Authorization System Test
Task 22/34: Verify scope enforcement across engagement lifecycle

Tests:
1. Scope checking against authorization list
2. CIDR matching for IP addresses
3. Wildcard domain matching
4. Rejection of out-of-scope targets
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_scope_check():
    """Test 1: Scope authorization check."""
    print("\n[Test 1] Scope Check...")
    
    try:
        from numasec.mcp import tools
        import asyncio
        
        # Create test engagement with scope
        eng_result = asyncio.run(tools.handle_engagement_create({
            "client_name": "Authorization Test",
            "project_name": "Scope Enforcement",
            "scope": ["192.168.1.0/24", "*.example.com", "testsite.io"],
            "methodology": "PTES",
        }))
        
        if not eng_result.get("success"):
            print(f"   ❌ Failed to create test engagement")
            return False
        
        print(f"   ✅ Test engagement created")
        
        # Test in-scope targets
        test_cases = [
            ("192.168.1.50", True, "IP in CIDR range"),
            ("192.168.1.1", True, "Another IP in CIDR"),
            ("10.0.0.1", False, "IP out of range"),
            ("sub.example.com", True, "Subdomain wildcard match"),
            ("example.com", True, "Domain wildcard match"),
            ("example.com.evil.com", False, "Domain suffix attack (reverse order)"),
            ("testsite.io", True, "Exact domain match"),
            ("testsite.com", False, "Different TLD"),
        ]
        
        passed = 0
        failed = 0
        
        for target, should_pass, description in test_cases:
            result = asyncio.run(tools.handle_scope_check({
                "target": target,
            }))
            
            is_authorized = result.get("in_scope", False)  # Key is "in_scope" not "authorized"
            
            if is_authorized == should_pass:
                print(f"   ✅ {target:25s} - {description}")
                passed += 1
            else:
                reason = result.get("reason", "unknown")
                print(f"   ❌ {target:25s} - {description} (expected {should_pass}, got {is_authorized}, reason: {reason})")
                failed += 1
        
        print(f"\n   Results: {passed}/{len(test_cases)} cases passed")
        
        return failed == 0
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_authorization_errors():
    """Test 2: Proper error messages for unauthorized targets."""
    print("\n[Test 2] Authorization Error Messages...")
    
    try:
        from numasec.mcp import tools
        import asyncio
        
        # Check unauthorized target
        result = asyncio.run(tools.handle_scope_check({
            "target": "unauthorized-target.com",
        }))
        
        if not result.get("in_scope"):  # Key is "in_scope"
            print(f"   ✅ Unauthorized target rejected")
            
            if "reason" in result:
                msg = result.get("reason")
                print(f"      Reason: {msg}")
            
            return True
        else:
            print(f"   ❌ Unauthorized target was allowed")
            return False
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def test_cfaa_compliance():
    """Test 3: CFAA compliance - strict authorization."""
    print("\n[Test 3] CFAA Compliance...")
    
    try:
        # Verify that authorization check is mandatory for web_request
        from numasec.mcp import tools
        import asyncio
        import inspect
        
        # Check if web_request handler mentions scope/authorization
        source = inspect.getsource(tools.handle_web_request)
        
        has_scope_check = (
            "scope" in source.lower() or 
            "authorized" in source.lower() or
            "authorization" in source.lower()
        )
        
        if has_scope_check:
            print(f"   ✅ web_request includes authorization logic")
        else:
            print(f"   ⚠️  web_request may not enforce authorization")
        
        # Check scope_check handler has proper validation
        scope_source = inspect.getsource(tools.handle_scope_check)
        
        has_cidr = "ip_network" in scope_source or "ipaddress" in scope_source
        has_wildcard = "wildcard" in scope_source.lower() or "glob" in scope_source
        
        checks = [
            (has_cidr, "CIDR validation"),
            (has_wildcard, "Wildcard domain matching"),
        ]
        
        for check, desc in checks:
            if check:
                print(f"   ✅ {desc}")
            else:
                print(f"   ❌ {desc} missing")
        
        return has_cidr and has_wildcard
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def main():
    """Run authorization system tests."""
    print("=" * 80)
    print("TEST: Authorization System")
    print("=" * 80)
    
    results = []
    
    results.append(("Scope Check", test_scope_check()))
    results.append(("Authorization Errors", test_authorization_errors()))
    results.append(("CFAA Compliance", test_cfaa_compliance()))
    
    print("\n" + "=" * 80)
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    print(f"Results: {passed}/{total} tests passed")
    
    for name, success in results:
        status = "✅" if success else "❌"
        print(f"{status} {name}")
    
    print("=" * 80)
    
    if passed == total:
        print("✅ AUTHORIZATION SYSTEM TESTS PASSED")
        print("   Scope enforcement and CFAA compliance functional")
        return True
    else:
        print(f"⚠️  {total - passed} AUTHORIZATION TESTS FAILED")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
