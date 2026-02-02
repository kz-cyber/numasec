#!/usr/bin/env python3
"""
Test CLI Commands - OPEN_SOURCE_READINESS Task 1.2
Tests all interactive CLI commands without requiring API keys.
"""
import os
import sys
import asyncio
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

async def test_cli_help_command():
    """Test if /help command works"""
    from numasec.cli.cyberpunk_interface import NumaSecCLI
    
    cli = NumaSecCLI()
    
    print("\n[TEST] /help command")
    print("="*60)
    try:
        result = await cli._handle_command("/help")
        assert result == True
        print("✅ PASS: /help command works")
        return True
    except Exception as e:
        print(f"❌ FAIL: /help command failed: {e}")
        return False

async def test_cli_metrics_display():
    """Test if metrics display works"""
    from numasec.cli.cyberpunk_interface import NumaSecCLI
    
    cli = NumaSecCLI()
    cli.total_cost = 1.23
    cli.total_tokens_in = 5000
    cli.total_tokens_out = 3000
    cli.iteration_count = 10
    cli.findings_count = 3
    cli.current_model = "deepseek"
    
    print("\n[TEST] Metrics display")
    print("="*60)
    try:
        result = await cli._handle_command("/metrics")
        assert result == True
        print("✅ PASS: Metrics display works")
        return True
    except Exception as e:
        print(f"❌ FAIL: Metrics display failed: {e}")
        return False

async def test_cli_clear():
    """Test if /clear command works"""
    from numasec.cli.cyberpunk_interface import NumaSecCLI
    
    cli = NumaSecCLI()
    
    # Add some fake data
    cli.output_manager.add('tool', 'Test tool call', 1.5)
    
    print("\n[TEST] /clear command")
    print("="*60)
    try:
        result = await cli._handle_command("/clear")
        
        # Verify clear worked
        assert len(cli.output_manager.records) == 0
        assert result == True
        
        print("✅ PASS: /clear command works")
        return True
    except Exception as e:
        print(f"❌ FAIL: /clear command failed: {e}")
        return False

async def test_output_manager():
    """Test OutputManager (history tracking)"""
    from numasec.cli.cyberpunk_interface import OutputManager
    
    print("\n[TEST] OutputManager")
    print("="*60)
    try:
        om = OutputManager()
        
        # Add records
        id1 = om.add('tool', 'Test tool 1', 1.2)
        id2 = om.add('think', 'Test thought', 0.5)
        id3 = om.add('error', 'Test error', 0.1)
        
        # Verify retrieval
        assert om.get(id1).type == 'tool'
        assert om.get(id2).type == 'think'
        assert om.get(id3).type == 'error'
        assert len(om.records) == 3
        
        # Test clear
        om.clear()
        assert len(om.records) == 0
        assert om.counter == 1
        
        print("✅ PASS: OutputManager works correctly")
        return True
    except Exception as e:
        print(f"❌ FAIL: OutputManager failed: {e}")
        return False

async def test_env_loading():
    """Test .env loading (without actual API keys)"""
    from numasec.cli.cyberpunk_interface import NumaSecCLI
    
    print("\n[TEST] Environment loading")
    print("="*60)
    try:
        cli = NumaSecCLI()
        cli._load_env()
        
        print("✅ PASS: _load_env() doesn't crash")
        return True
    except Exception as e:
        print(f"❌ FAIL: Environment loading failed: {e}")
        return False

async def test_cli_tools_list():
    """Test if /tools command works (requires MCP connection)"""
    from numasec.cli.cyberpunk_interface import NumaSecCLI
    from numasec.client.mcp_client import AsyncMCPClient
    from numasec.client.transports.direct import DirectTransport
    
    print("\n[TEST] /tools command (with MCP connection)")
    print("="*60)
    try:
        # Connect to MCP
        transport = DirectTransport()
        mcp_client = AsyncMCPClient(transport)
        await mcp_client.connect()
        
        # Create CLI
        cli = NumaSecCLI()
        cli.mcp_client = mcp_client
        
        # Test /tools command
        result = await cli._handle_command("/tools")
        assert result == True
        
        await mcp_client.disconnect()
        
        print(f"✅ PASS: /tools command lists {len(mcp_client.tools)} tools")
        return True
    except Exception as e:
        print(f"❌ FAIL: /tools command failed: {e}")
        return False

async def test_cli_show_command():
    """Test /show command for viewing action history"""
    from numasec.cli.cyberpunk_interface import NumaSecCLI
    
    cli = NumaSecCLI()
    
    # Add a record
    rec_id = cli.output_manager.add('tool', 'Test output content', 2.5)
    
    print("\n[TEST] /show command")
    print("="*60)
    try:
        result = await cli._handle_command(f"/show {rec_id}")
        assert result == True
        print("✅ PASS: /show command works")
        return True
    except Exception as e:
        print(f"❌ FAIL: /show command failed: {e}")
        return False

async def main():
    print("\n" + "="*60)
    print("NumaSec - CLI Commands Test Suite")
    print("Phase 1.2: CLI Interface Verification")
    print("="*60)
    
    results = []
    
    # Run all tests
    results.append(await test_output_manager())
    results.append(await test_env_loading())
    results.append(await test_cli_help_command())
    results.append(await test_cli_metrics_display())
    results.append(await test_cli_clear())
    results.append(await test_cli_tools_list())
    results.append(await test_cli_show_command())
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    passed = sum(results)
    total = len(results)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("\n✅ All CLI tests PASSED")
        return 0
    else:
        print(f"\n❌ {total - passed} tests FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
