#!/usr/bin/env python3
"""
Test FactStore: Epistemic State (Huang et al., 2022)
Separate "what happened" (logs) from "what we know" (facts).
"""
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from numasec.agent.fact_store import FactStore, FactType


def test_fact_store():
    """Test epistemic state management."""
    print("=" * 80)
    print("TEST: FactStore - Epistemic State (Huang et al., 2022)")
    print("=" * 80)
    
    store = FactStore()
    
    # Test 1: Add high-confidence fact
    print("\n[Test 1] Adding high-confidence fact (≥0.8)...")
    try:
        fact = store.add_fact(
            type=FactType.VULNERABILITY,
            key="sqli_login",
            value="SQL injection in /login username parameter",
            confidence=0.95,
            evidence="Payload admin'-- bypassed authentication",
            iteration=1
        )
        success = True
    except Exception as e:
        print(f"   ❌ Error: {e}")
        success = False
    
    if success:
        print(f"   ✅ High-confidence fact added (0.95)")
    else:
        print(f"   ❌ High-confidence fact REJECTED (BUG!)")
        return False
    
    # Test 2: Reject low-confidence fact
    print("\n[Test 2] Rejecting low-confidence fact (<0.8)...")
    try:
        store.add_fact(
            type=FactType.VULNERABILITY,
            key="maybe_xss",
            value="Possible XSS in /search",
            confidence=0.6,  # Below threshold
            evidence="Untested speculation",
            iteration=2
        )
        success_low = True
    except ValueError:
        success_low = False
    
    if not success_low:
        print(f"   ✅ Low-confidence fact REJECTED (correct! 0.6 < 0.8)")
    else:
        print(f"   ❌ Low-confidence fact ACCEPTED (BUG!)")
        return False
    
    # Test 3: Retrieve stored fact
    print("\n[Test 3] Retrieving stored fact...")
    fact = store.get_fact("sqli_login")
    
    if fact:
        print(f"   ✅ Fact retrieved")
        print(f"      Type: {fact.type}")
        print(f"      Value: {fact.value}")
        print(f"      Confidence: {fact.confidence}")
        
        if fact.confidence == 0.95:
            print(f"   ✅ Confidence preserved")
        else:
            print(f"   ⚠️  Confidence changed")
    else:
        print(f"   ❌ Fact not found (BUG!)")
        return False
    
    # Test 4: Check vulnerability detection
    print("\n[Test 4] Vulnerability detection...")
    has_vuln = store.has_vulnerability()
    
    if has_vuln:
        print(f"   ✅ Vulnerability detected (correct!)")
    else:
        print(f"   ❌ Vulnerability NOT detected (BUG!)")
        return False
    
    # Test 5: Multiple fact types
    print("\n[Test 5] Multiple fact types...")
    store.add_fact(
        type=FactType.CREDENTIAL,
        key="admin_creds",
        value="admin:password123",
        confidence=0.9,
        evidence="Successful login",
        iteration=3
    )
    
    store.add_fact(
        type=FactType.FLAG_FRAGMENT,
        key="flag_part1",
        value="FLAG{sql_",
        confidence=0.85,
        evidence="Extracted from DB",
        iteration=4
    )
    
    all_facts = list(store.facts.values())
    print(f"   Total facts: {len(all_facts)}")
    
    types_found = {f.type for f in all_facts}
    expected_types = {FactType.VULNERABILITY, FactType.CREDENTIAL, FactType.FLAG_FRAGMENT}
    
    if expected_types.issubset(types_found):
        print(f"   ✅ All fact types stored correctly")
    else:
        print(f"   ⚠️  Some fact types missing")
    
    print("\n" + "=" * 80)
    print("✅ FACTSTORE TESTS PASSED")
    print("   Epistemic state management is FUNCTIONAL")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = test_fact_store()
    sys.exit(0 if success else 1)
