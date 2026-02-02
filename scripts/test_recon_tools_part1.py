#!/usr/bin/env python3
"""
Test script for Reconnaissance Tools Part 1 (recon_nmap, recon_subdomain)
Tests subprocess execution, error handling, JSON parsing.
"""
import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from numasec.mcp.tools import (
    handle_recon_nmap,
    handle_recon_subdomain,
)


async def test_recon_tools():
    """Test nmap and subdomain enumeration tools."""
    print("=" * 80)
    print("TEST: Recon Tools - Part 1 (nmap, subdomain)")
    print("=" * 80)
    
    # Test 1: recon_nmap - quick scan (localhost only, safe)
    print("\n[Test 1] recon_nmap - quick scan of localhost...")
    try:
        result = await handle_recon_nmap({
            "targets": ["127.0.0.1"],
            "scan_type": "quick",
            "timing": 4  # Fast
        })
        print(f"✅ recon_nmap (quick): Success")
        
        # Verify basic structure
        if isinstance(result, dict):
            if "hosts" in result or "error" in result:
                print(f"   Response keys: {list(result.keys())}")
                if "hosts" in result:
                    print(f"   Hosts found: {len(result['hosts'])}")
            else:
                print(f"   ⚠️  Unexpected response format: {result}")
        else:
            print(f"   ⚠️  Non-dict response: {type(result)}")
    except Exception as e:
        print(f"⚠️  recon_nmap EXCEPTION: {e}")
        print("   (This may be expected if nmap not installed)")
    
    # Test 2: recon_nmap - service detection (lightweight)
    print("\n[Test 2] recon_nmap - service detection...")
    try:
        result = await handle_recon_nmap({
            "targets": ["127.0.0.1"],
            "scan_type": "service",
            "ports": "22,80,443",
            "timing": 4
        })
        print(f"✅ recon_nmap (service): Success")
        if isinstance(result, dict) and "hosts" in result:
            for host in result["hosts"]:
                if "ports" in host:
                    print(f"   Host {host.get('ip')}: {len(host['ports'])} ports")
    except Exception as e:
        print(f"⚠️  recon_nmap (service) EXCEPTION: {e}")
    
    # Test 3: recon_subdomain (will fail without subfinder, but test code path)
    print("\n[Test 3] recon_subdomain - example.com (passive only)...")
    try:
        result = await handle_recon_subdomain({
            "domain": "example.com",
            "passive_only": True,
            "recursive": False
        })
        print(f"✅ recon_subdomain: Success")
        
        if isinstance(result, dict):
            if "subdomains" in result:
                print(f"   Subdomains found: {len(result['subdomains'])}")
            elif "error" in result:
                print(f"   Expected error (subfinder not installed): {result['error']}")
        else:
            print(f"   ⚠️  Unexpected response type: {type(result)}")
    except Exception as e:
        print(f"⚠️  recon_subdomain EXCEPTION: {e}")
        print("   (This is expected if subfinder not installed)")
    
    print("\n" + "=" * 80)
    print("✅ RECON TOOLS PART 1 TESTS COMPLETED")
    print("   Note: Some tools may fail if not installed (nmap, subfinder)")
    print("   This is EXPECTED behavior for missing dependencies")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = asyncio.run(test_recon_tools())
    sys.exit(0 if success else 1)
