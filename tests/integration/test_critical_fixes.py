#!/usr/bin/env python3
"""
Integration test to verify the three critical fixes work together.

This test reproduces the exact crash scenario from the debug log.
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import patch, Mock, AsyncMock

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from numasec.agent.agent import NumaSecAgent, AgentConfig
from numasec.ai.router import LLMRouter
from numasec.core.approval import ApprovalMode
from numasec.agent.fact_store import FactType


def _create_mock_mcp_client():
    """Create a mock MCP client for testing."""
    mcp = Mock()
    mcp.tools = []
    return mcp


# Mock require_authorization for all tests
@patch('asyncio.create_task')  # Mock to avoid event loop requirement
@patch('numasec.compliance.authorization.require_authorization', return_value=True)
async def test_fix_1_loop_detection_no_crash(mock_auth, mock_create_task):
    """Fix #1: Verify loop detection doesn't crash with AttributeError."""
    print("\n" + "="*70)
    print("TEST 1: Loop Detection Without Crash (Fix #1)")
    print("="*70)
    
    router = Mock()
    mcp = _create_mock_mcp_client()
    config = AgentConfig()
    
    agent = NumaSecAgent(router, mcp, config, ApprovalMode.AUTONOMOUS)
    agent.start("http://localhost", "Test objective")  # localhost is whitelisted
    
    # Simulate 3 identical results (triggers loop detection)
    try:
        for i in range(3):
            is_loop = agent._detect_identical_results('{"status_code": 200, "body": "same content"}')
            print(f"  Iteration {i+1}: loop={is_loop}")
        
        print("  ✅ PASS: No AttributeError crash!")
        return True
    except AttributeError as e:
        print(f"  ❌ FAIL: AttributeError: {e}")
        return False


@patch('asyncio.create_task')  # Mock to avoid event loop requirement
@patch('numasec.compliance.authorization.require_authorization', return_value=True)
async def test_fix_2_state_isolation(mock_auth, mock_create_task):
    """Fix #2: Verify facts don't leak between runs."""
    print("\n" + "="*70)
    print("TEST 2: State Isolation Between Runs (Fix #2)")
    print("="*70)
    
    router = Mock()
    mcp = _create_mock_mcp_client()
    config = AgentConfig()
    
    agent = NumaSecAgent(router, mcp, config, ApprovalMode.AUTONOMOUS)
    
    # First run: add contaminating fact
    agent.start("http://target1.local", "First objective")
    agent.facts.add_fact(
        type=FactType.FLAG_FRAGMENT,
        key="contamination_flag",
        value="picoCTF{old_flag_from_previous_run}",
        confidence=0.9,
        evidence="Test contamination",
        iteration=28  # Like in the debug log
    )
    # Use correct API: facts is a dict, get values
    facts_run1 = len(list(agent.facts.facts.values()))
    print(f"  Run 1: Added {facts_run1} fact(s)")
    
    # Second run: facts should be cleared
    agent.start("http://target2.local", "Second objective")
    facts_run2 = list(agent.facts.facts.values())
    
    if len(facts_run2) == 0:
        print(f"  Run 2: {len(facts_run2)} facts (clean state)")
        print("  ✅ PASS: No state pollution!")
    else:
        print(f"  Run 2: {len(facts_run2)} facts leaked:")
        for fact in facts_run2:
            print(f"    - {fact.key}: {fact.value[:50]}...")
        print("  ❌ FAIL: State contamination detected!")
        assert False, "State contamination detected!"


@patch('asyncio.create_task')  # Mock to avoid event loop requirement
@patch('numasec.compliance.authorization.require_authorization', return_value=True)
def test_fix_3_no_duplicate_prompt(mock_auth, mock_create_task):
    """Fix #3: Verify prompt has no duplicate sections."""
    print("\n" + "="*70)
    print("TEST 3: No Duplicate Prompt Sections (Fix #3)")
    print("="*70)
    
    router = Mock()
    mcp_client = _create_mock_mcp_client()
    
    agent = NumaSecAgent(router, mcp_client)
    agent.start("http://localhost", "Test objective")  # localhost is whitelisted
    
    # Get system messages
    system_messages = [
        msg for msg in agent.state.context_messages
        if msg.role == "system"
    ]
    
    # Verify we have exactly one system message (no duplicates)
    assert len(system_messages) == 1, f"Expected 1 system message, got {len(system_messages)}"
    
    # Check for duplicate major sections in the prompt
    full_prompt = system_messages[0].content if system_messages else ""
    
    # Common section headers that should appear only once
    unique_sections = [
        "## REASONING FORMAT",
        "## TARGET:",
        "## OBJECTIVE:",
    ]
    
    for section in unique_sections:
        count = full_prompt.count(section)
        if count > 1:
            print(f"  ❌ FAIL: Found {count} copies of '{section}' (expected 1)")
            assert False, f"Duplicate section found: {section}"
    
    print(f"  ✅ PASS: No duplicate sections! (1 system message)")


async def main():
    """Run all integration tests."""
    print("\n" + "="*70)
    print("NumaSec Critical Fixes - Integration Test Suite")
    print("="*70)
    print("\nTesting fixes for:")
    print("  Fix #1: AttributeError crash in loop detection")
    print("  Fix #2: State pollution between runs")
    print("  Fix #3: Duplicate prompt sections")
    
    results = []
    
    # Test Fix #1
    try:
        result1 = await test_fix_1_loop_detection_no_crash()
        results.append(("Fix #1 (Loop Detection)", result1))
    except Exception as e:
        print(f"  ❌ EXCEPTION: {e}")
        results.append(("Fix #1 (Loop Detection)", False))
    
    # Test Fix #2
    try:
        result2 = await test_fix_2_state_isolation()
        results.append(("Fix #2 (State Isolation)", result2))
    except Exception as e:
        print(f"  ❌ EXCEPTION: {e}")
        results.append(("Fix #2 (State Isolation)", False))
    
    # Test Fix #3
    try:
        result3 = test_fix_3_no_duplicate_prompt()
        results.append(("Fix #3 (Duplicate Prompt)", result3))
    except Exception as e:
        print(f"  ❌ EXCEPTION: {e}")
        results.append(("Fix #3 (Duplicate Prompt)", False))
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}: {test_name}")
    
    total_passed = sum(1 for _, passed in results if passed)
    total_tests = len(results)
    
    print("\n" + "="*70)
    if total_passed == total_tests:
        print(f"🎉 ALL TESTS PASSED ({total_passed}/{total_tests})")
        print("="*70)
        print("\n✅ NumaSec is ready to run without crashing!")
        return 0
    else:
        print(f"⚠️  SOME TESTS FAILED ({total_passed}/{total_tests})")
        print("="*70)
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
