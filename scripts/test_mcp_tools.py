#!/usr/bin/env python3
"""
Test MCP Tools - OPEN_SOURCE_READINESS Task 1.3
Tests all 28 MCP tools across 9 categories.
"""
import os
import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from numasec.client.mcp_client import AsyncMCPClient
from numasec.client.transports.direct import DirectTransport

async def test_engagement_tools(client: AsyncMCPClient):
    """Test engagement management tools (3)"""
    print("\n[TEST CATEGORY] Engagement Management")
    print("="*60)
    
    results = []
    
    # Tool 1: engagement_create
    print("├─ Testing: engagement_create")
    try:
        tool = next((t for t in client.tools if t.name == "engagement_create"), None)
        assert tool is not None, "engagement_create not found"
        assert "client_name" in str(tool.parameters), "Missing client_name param"
        assert "scope" in str(tool.parameters), "Missing scope param"
        print("│  ✅ PASS: engagement_create schema OK")
        results.append(True)
    except Exception as e:
        print(f"│  ❌ FAIL: {e}")
        results.append(False)
    
    # Tool 2: engagement_status
    print("├─ Testing: engagement_status")
    try:
        tool = next((t for t in client.tools if t.name == "engagement_status"), None)
        assert tool is not None, "engagement_status not found"
        print("│  ✅ PASS: engagement_status schema OK")
        results.append(True)
    except Exception as e:
        print(f"│  ❌ FAIL: {e}")
        results.append(False)
    
    # Tool 3: engagement_close
    print("└─ Testing: engagement_close")
    try:
        tool = next((t for t in client.tools if t.name == "engagement_close"), None)
        assert tool is not None, "engagement_close not found"
        print("   ✅ PASS: engagement_close schema OK")
        results.append(True)
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        results.append(False)
    
    return sum(results), len(results)

async def test_recon_tools(client: AsyncMCPClient):
    """Test reconnaissance tools (5)"""
    print("\n[TEST CATEGORY] Reconnaissance")
    print("="*60)
    
    results = []
    tools = ["recon_nmap", "recon_subdomain", "recon_httpx", "recon_whatweb", "recon_dns"]
    
    for tool_name in tools:
        is_last = tool_name == tools[-1]
        prefix = "└─" if is_last else "├─"
        try:
            tool = next((t for t in client.tools if t.name == tool_name), None)
            assert tool is not None, f"{tool_name} not found"
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}✅ PASS: {tool_name} schema OK")
            results.append(True)
        except Exception as e:
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}❌ FAIL: {e}")
            results.append(False)
    
    return sum(results), len(results)

async def test_web_tools(client: AsyncMCPClient):
    """Test web application tools (6)"""
    print("\n[TEST CATEGORY] Web Application")
    print("="*60)
    
    results = []
    tools = ["web_ffuf", "web_nuclei", "web_sqlmap", "web_nikto", "web_request", "web_crawl"]
    
    for tool_name in tools:
        is_last = tool_name == tools[-1]
        prefix = "└─" if is_last else "├─"
        try:
            tool = next((t for t in client.tools if t.name == tool_name), None)
            assert tool is not None, f"{tool_name} not found"
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}✅ PASS: {tool_name} schema OK")
            results.append(True)
        except Exception as e:
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}❌ FAIL: {e}")
            results.append(False)
    
    return sum(results), len(results)

async def test_exploit_tools(client: AsyncMCPClient):
    """Test exploitation tools (2)"""
    print("\n[TEST CATEGORY] Exploitation")
    print("="*60)
    
    results = []
    tools = ["exploit_hydra", "exploit_script"]
    
    for tool_name in tools:
        is_last = tool_name == tools[-1]
        prefix = "└─" if is_last else "├─"
        try:
            tool = next((t for t in client.tools if t.name == tool_name), None)
            assert tool is not None, f"{tool_name} not found"
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}✅ PASS: {tool_name} schema OK")
            results.append(True)
        except Exception as e:
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}❌ FAIL: {e}")
            results.append(False)
    
    return sum(results), len(results)

async def test_finding_tools(client: AsyncMCPClient):
    """Test finding management tools (4)"""
    print("\n[TEST CATEGORY] Finding Management")
    print("="*60)
    
    results = []
    tools = ["finding_create", "finding_list", "finding_update", "finding_add_evidence"]
    
    for tool_name in tools:
        is_last = tool_name == tools[-1]
        prefix = "└─" if is_last else "├─"
        try:
            tool = next((t for t in client.tools if t.name == tool_name), None)
            assert tool is not None, f"{tool_name} not found"
            
            # Validate critical params for finding_create
            if tool_name == "finding_create":
                assert "title" in str(tool.parameters), "Missing title param"
                assert "severity" in str(tool.parameters), "Missing severity param"
                # cvss_vector is optional, not cvss_score
            
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}✅ PASS: {tool_name} schema OK")
            results.append(True)
        except Exception as e:
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}❌ FAIL: {e}")
            results.append(False)
    
    return sum(results), len(results)

async def test_report_tools(client: AsyncMCPClient):
    """Test reporting tools (2)"""
    print("\n[TEST CATEGORY] Reporting")
    print("="*60)
    
    results = []
    tools = ["report_generate", "report_preview"]
    
    for tool_name in tools:
        is_last = tool_name == tools[-1]
        prefix = "└─" if is_last else "├─"
        try:
            tool = next((t for t in client.tools if t.name == tool_name), None)
            assert tool is not None, f"{tool_name} not found"
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}✅ PASS: {tool_name} schema OK")
            results.append(True)
        except Exception as e:
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}❌ FAIL: {e}")
            results.append(False)
    
    return sum(results), len(results)

async def test_knowledge_tools(client: AsyncMCPClient):
    """Test knowledge base tools (2)"""
    print("\n[TEST CATEGORY] Knowledge Base")
    print("="*60)
    
    results = []
    tools = ["knowledge_search", "knowledge_add"]
    
    for tool_name in tools:
        is_last = tool_name == tools[-1]
        prefix = "└─" if is_last else "├─"
        try:
            tool = next((t for t in client.tools if t.name == tool_name), None)
            assert tool is not None, f"{tool_name} not found"
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}✅ PASS: {tool_name} schema OK")
            results.append(True)
        except Exception as e:
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}❌ FAIL: {e}")
            results.append(False)
    
    return sum(results), len(results)

async def test_scope_tools(client: AsyncMCPClient):
    """Test scope management tools (2)"""
    print("\n[TEST CATEGORY] Scope Management")
    print("="*60)
    
    results = []
    tools = ["scope_check", "scope_add"]
    
    for tool_name in tools:
        is_last = tool_name == tools[-1]
        prefix = "└─" if is_last else "├─"
        try:
            tool = next((t for t in client.tools if t.name == tool_name), None)
            assert tool is not None, f"{tool_name} not found"
            
            # Validate critical param for scope_check
            if tool_name == "scope_check":
                assert "target" in str(tool.parameters), "Missing target param"
            
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}✅ PASS: {tool_name} schema OK")
            results.append(True)
        except Exception as e:
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}❌ FAIL: {e}")
            results.append(False)
    
    return sum(results), len(results)

async def test_memory_tools(client: AsyncMCPClient):
    """Test memory/notes tools (2)"""
    print("\n[TEST CATEGORY] Memory (Notes)")
    print("="*60)
    
    results = []
    tools = ["notes_write", "notes_read"]
    
    for tool_name in tools:
        is_last = tool_name == tools[-1]
        prefix = "└─" if is_last else "├─"
        try:
            tool = next((t for t in client.tools if t.name == tool_name), None)
            assert tool is not None, f"{tool_name} not found"
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}✅ PASS: {tool_name} schema OK")
            results.append(True)
        except Exception as e:
            print(f"{prefix} Testing: {tool_name}")
            print(f"{'   ' if is_last else '│  '}❌ FAIL: {e}")
            results.append(False)
    
    return sum(results), len(results)

async def main():
    print("\n" + "="*60)
    print("NumaSec - MCP Tools Test Suite")
    print("Phase 1.3: MCP Tools Verification")
    print("="*60)
    
    # Connect to MCP
    transport = DirectTransport()
    client = AsyncMCPClient(transport)
    await client.connect()
    
    print(f"\nMCP Server Connected: {len(client.tools)} tools available")
    
    # Run all category tests
    category_results = []
    
    category_results.append(await test_engagement_tools(client))
    category_results.append(await test_recon_tools(client))
    category_results.append(await test_web_tools(client))
    category_results.append(await test_exploit_tools(client))
    category_results.append(await test_finding_tools(client))
    category_results.append(await test_report_tools(client))
    category_results.append(await test_knowledge_tools(client))
    category_results.append(await test_scope_tools(client))
    category_results.append(await test_memory_tools(client))
    
    await client.disconnect()
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    total_passed = sum(passed for passed, _ in category_results)
    total_tests = sum(total for _, total in category_results)
    
    print(f"Total tools tested: {total_tests}/28")
    print(f"Tests passed: {total_passed}/{total_tests}")
    
    if total_passed == total_tests:
        print("\n✅ All MCP tools PASSED")
        return 0
    else:
        print(f"\n❌ {total_tests - total_passed} tests FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
