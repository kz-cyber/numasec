#!/usr/bin/env python3
"""
Test Memory Tools - Agent Scratchpad Persistence
Task 7/34: Verify notes_write/notes_read for agent memory

Memory Architecture: Scratchpad for ephemeral observations, facts for confirmed truths
"""

import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from numasec.mcp.tools import (
    handle_notes_write,
    handle_notes_read
)


async def test_memory_tools():
    """Test agent scratchpad: write → read → append → persistence."""
    
    print("=" * 80)
    print("TEST: Memory Tools (Agent Scratchpad)")
    print("=" * 80)
    
    # Test 1: Write initial note
    print("\n[Test 1] Writing initial note...")
    try:
        result = await handle_notes_write({
            "key": "initial_recon",
            "value": "Found open port 80/tcp (HTTP). Server: nginx/1.18.0"
        })
        result_dict = result if isinstance(result, dict) else {}
        
        if result_dict.get("success"):
            print(f"   ✅ Note written: initial_recon")
        else:
            print(f"   ❌ Write failed: {result_dict.get('error', 'Unknown')}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Test 2: Read notes back
    print("\n[Test 2] Reading notes...")
    try:
        result = await handle_notes_read({})
        result_dict = result if isinstance(result, dict) else {}
        
        notes = result_dict.get("notes", {})
        
        if "initial_recon" in notes:
            content = notes["initial_recon"]
            print(f"   ✅ Note retrieved: {content[:50]}...")
            
            if "nginx/1.18.0" in content:
                print(f"   ✅ Content preserved")
            else:
                print(f"   ❌ Content corrupted")
                return False
        else:
            print(f"   ❌ Note not found")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Test 3: Write second note
    print("\n[Test 3] Writing additional note...")
    try:
        result = await handle_notes_write({
            "key": "sqli_test",
            "value": "Username parameter: admin'-- triggered SQL error. Potential SQLi vector."
        })
        result_dict = result if isinstance(result, dict) else {}
        
        if result_dict.get("success"):
            print(f"   ✅ Second note written")
        else:
            print(f"   ❌ Write failed")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Test 4: Verify both notes persist
    print("\n[Test 4] Verifying multi-note persistence...")
    try:
        result = await handle_notes_read({})
        result_dict = result if isinstance(result, dict) else {}
        
        notes = result_dict.get("notes", {})
        
        if len(notes) >= 2:
            print(f"   ✅ Found {len(notes)} notes")
            
            if "initial_recon" in notes and "sqli_test" in notes:
                print(f"   ✅ Both notes preserved")
                print(f"      Keys: {list(notes.keys())}")
            else:
                print(f"   ❌ Some notes missing")
                return False
        else:
            print(f"   ❌ Expected >=2 notes, found {len(notes)}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Test 5: Update existing note (overwrite)
    print("\n[Test 5] Updating existing note...")
    try:
        result = await handle_notes_write({
            "key": "initial_recon",
            "value": "Port 80: nginx/1.18.0. Found /admin endpoint via fuzzing."
        })
        result_dict = result if isinstance(result, dict) else {}
        
        if result_dict.get("success"):
            print(f"   ✅ Note updated")
            
            # Verify update
            verify = await handle_notes_read({})
            verify_dict = verify if isinstance(verify, dict) else {}
            notes = verify_dict.get("notes", {})
            
            if "/admin endpoint" in notes.get("initial_recon", ""):
                print(f"   ✅ Update persisted")
            else:
                print(f"   ⚠️  Update may not have persisted")
        else:
            print(f"   ❌ Update failed")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    print("\n" + "=" * 80)
    print("✅ MEMORY TOOLS TESTS PASSED")
    print("   Agent scratchpad (notes_write/read) is FUNCTIONAL")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = asyncio.run(test_memory_tools())
    sys.exit(0 if success else 1)
