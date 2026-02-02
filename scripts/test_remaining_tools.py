#!/usr/bin/env python3
"""
Test Remaining MCP Tools - Comprehensive Handler Verification
Task 11/34: Verify all remaining tool handlers for graceful error handling

Tests: recon (httpx, whatweb, dns), web (ffuf, nuclei, sqlmap, nikto, crawl),
       exploit (hydra, script), reporting (generate, preview), knowledge (search, add)
"""

import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from numasec.mcp.tools import VALID_TOOLS


async def test_tool_handler(tool_name: str, handler_func, test_args: dict):
    """Generic tool handler test - verify it returns dict with success/error."""
    try:
        result = await handler_func(test_args)
        result_dict = result if isinstance(result, dict) else {}
        
        # Check structure
        if "success" in result_dict or "error" in result_dict or "output" in result_dict:
            return True, "Handler returns proper structure"
        else:
            return False, f"Missing success/error/output keys: {list(result_dict.keys())}"
    except Exception as e:
        # Graceful error handling is OK for missing external tools
        if "not found" in str(e).lower() or "command" in str(e).lower():
            return True, f"Graceful error: {str(e)[:50]}"
        else:
            return False, f"Unexpected error: {e}"


async def test_remaining_tools():
    """Test all remaining MCP tool handlers for proper error handling."""
    
    print("=" * 80)
    print("TEST: Remaining MCP Tools - Batch Verification")
    print("=" * 80)
    
    # Import handlers dynamically
    from numasec.mcp.tools import (
        handle_recon_httpx,
        handle_recon_whatweb,
        handle_recon_dns,
        handle_web_ffuf,
        handle_web_nuclei,
        handle_web_sqlmap,
        handle_web_nikto,
        handle_web_crawl,
        handle_exploit_hydra,
        handle_exploit_script,
        handle_report_generate,
        handle_report_preview,
        handle_scope_add
    )
    
    # Test suite: (name, handler, minimal args)
    tools_to_test = [
        # Recon tools
        ("recon_httpx", handle_recon_httpx, {"target": "example.com"}),
        ("recon_whatweb", handle_recon_whatweb, {"target": "http://example.com"}),
        ("recon_dns", handle_recon_dns, {"domain": "example.com"}),
        
        # Web tools
        ("web_ffuf", handle_web_ffuf, {"url": "http://example.com/FUZZ", "wordlist": "common.txt"}),
        ("web_nuclei", handle_web_nuclei, {"target": "http://example.com"}),
        ("web_sqlmap", handle_web_sqlmap, {"url": "http://example.com/login?id=1"}),
        ("web_nikto", handle_web_nikto, {"target": "http://example.com"}),
        ("web_crawl", handle_web_crawl, {"target": "http://example.com", "max_depth": 2}),
        
        # Exploit tools
        ("exploit_hydra", handle_exploit_hydra, {"target": "example.com", "service": "ssh"}),
        ("exploit_script", handle_exploit_script, {"script_path": "/tmp/test.py", "args": []}),
        
        # Reporting tools
        ("report_generate", handle_report_generate, {}),
        ("report_preview", handle_report_preview, {}),
        
        # Scope management
        ("scope_add", handle_scope_add, {"target": "newdomain.com"}),
    ]
    
    passed = 0
    failed = 0
    
    print(f"\n[INFO] Testing {len(tools_to_test)} tool handlers...")
    print("-" * 80)
    
    for tool_name, handler, args in tools_to_test:
        success, message = await test_tool_handler(tool_name, handler, args)
        
        if success:
            print(f"✅ {tool_name:20s} - {message}")
            passed += 1
        else:
            print(f"❌ {tool_name:20s} - {message}")
            failed += 1
    
    print("-" * 80)
    print(f"\nResults: {passed}/{len(tools_to_test)} passed")
    
    # Knowledge tools (may fail if dependencies missing - non-blocking)
    print("\n[OPTIONAL] Testing knowledge tools (may fail without dependencies)...")
    try:
        from numasec.mcp.tools import handle_knowledge_search, handle_knowledge_add
        
        search_ok, search_msg = await test_tool_handler(
            "knowledge_search", 
            handle_knowledge_search, 
            {"query": "SQL injection"}
        )
        print(f"{'✅' if search_ok else '⚠️ '} knowledge_search - {search_msg}")
        
        add_ok, add_msg = await test_tool_handler(
            "knowledge_add",
            handle_knowledge_add,
            {"title": "Test", "content": "Test content", "tags": ["test"]}
        )
        print(f"{'✅' if add_ok else '⚠️ '} knowledge_add - {add_msg}")
        
    except Exception as e:
        print(f"⚠️  Knowledge tools not available: {e}")
    
    print("\n" + "=" * 80)
    if failed == 0:
        print("✅ ALL TOOL HANDLERS PASSED")
        print("   All tools return proper structure or handle errors gracefully")
    else:
        print(f"⚠️  {failed} TOOL HANDLERS FAILED")
        print("   Review failures above")
    print("=" * 80)
    
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(test_remaining_tools())
    sys.exit(0 if success else 1)
