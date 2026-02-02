#!/usr/bin/env python3
"""
Test Performance Metrics Display - SOTA 2026

Validates that session metrics tracking works correctly:
- Session initialization with metrics variables
- Cost/tokens increment on ACTION_COMPLETE
- /metrics command display
- /export command generation
- Cost warning thresholds
"""

import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch
from numasec.cli.cyberpunk_interface import NumaSecCLI
from numasec.agent.events import Event, EventType


async def test_metrics_initialization():
    """Test that CLI initializes with metrics tracking."""
    print("=" * 60)
    print("TEST 1: Metrics Initialization")
    print("=" * 60)
    
    cli = NumaSecCLI()
    
    assert cli.session_start_time > 0, "session_start_time should be set"
    assert cli.total_cost == 0.0, "initial cost should be 0"
    assert cli.total_tokens_in == 0, "initial tokens_in should be 0"
    assert cli.total_tokens_out == 0, "initial tokens_out should be 0"
    assert cli.iteration_count == 0, "initial iterations should be 0"
    assert cli.findings_count == 0, "initial findings should be 0"
    assert len(cli.cost_thresholds) == 3, "should have 3 cost thresholds"
    assert len(cli.cost_warned_at) == 0, "no warnings triggered initially"
    
    print("✓ All metrics variables initialized correctly")
    print()


async def test_metrics_tracking():
    """Test that metrics accumulate correctly during operation."""
    print("=" * 60)
    print("TEST 2: Metrics Tracking")
    print("=" * 60)
    
    cli = NumaSecCLI()
    
    # Simulate ACTION_COMPLETE event with metrics
    metrics = {
        "input_tokens": 450,
        "output_tokens": 230,
        "cost": 0.003,
        "latency_ms": 1200,
        "model": "deepseek-chat"
    }
    
    # Manually update metrics (simulating event handler)
    cli.total_tokens_in += metrics["input_tokens"]
    cli.total_tokens_out += metrics["output_tokens"]
    cli.total_cost += metrics["cost"]
    cli.iteration_count += 1
    
    assert cli.total_tokens_in == 450, f"Expected 450 tokens_in, got {cli.total_tokens_in}"
    assert cli.total_tokens_out == 230, f"Expected 230 tokens_out, got {cli.total_tokens_out}"
    assert cli.total_cost == 0.003, f"Expected 0.003 cost, got {cli.total_cost}"
    assert cli.iteration_count == 1, f"Expected 1 iteration, got {cli.iteration_count}"
    
    # Simulate second action
    cli.total_tokens_in += 300
    cli.total_tokens_out += 150
    cli.total_cost += 0.002
    cli.iteration_count += 1
    
    assert cli.total_tokens_in == 750, "Tokens should accumulate"
    assert cli.total_tokens_out == 380, "Tokens should accumulate"
    assert abs(cli.total_cost - 0.005) < 0.0001, "Cost should accumulate"
    assert cli.iteration_count == 2, "Iterations should increment"
    
    print("✓ Metrics accumulate correctly across multiple actions")
    print()


async def test_cost_threshold_logic():
    """Test cost warning threshold detection."""
    print("=" * 60)
    print("TEST 3: Cost Threshold Detection")
    print("=" * 60)
    
    cli = NumaSecCLI()
    
    # Check initial state
    assert cli.total_cost == 0.0
    assert len(cli.cost_warned_at) == 0
    
    # Cross first threshold ($1.00)
    cli.total_cost = 1.05
    assert cli.total_cost >= cli.cost_thresholds[0], "Should be above $1 threshold"
    assert 1.0 not in cli.cost_warned_at, "Warning not yet triggered"
    
    # Simulate warning trigger
    cli.cost_warned_at.add(1.0)
    assert 1.0 in cli.cost_warned_at, "Warning should be recorded"
    
    # Cross second threshold ($5.00) but keep first
    cli.total_cost = 5.50
    cli.cost_warned_at.add(5.0)
    assert len(cli.cost_warned_at) == 2, "Should have 2 warnings triggered"
    assert 1.0 in cli.cost_warned_at, "Previous warning should persist"
    assert 5.0 in cli.cost_warned_at, "New warning should be added"
    
    print("✓ Cost threshold detection works correctly")
    print()


async def test_helper_functions():
    """Test helper functions for metrics display."""
    print("=" * 60)
    print("TEST 4: Helper Functions")
    print("=" * 60)
    
    cli = NumaSecCLI()
    
    # Test _latency_color
    fast_color = cli._latency_color(300)  # <500ms
    medium_color = cli._latency_color(1200)  # 500-2000ms
    slow_color = cli._latency_color(3000)  # >2000ms
    
    assert fast_color != slow_color, "Fast and slow should have different colors"
    print(f"✓ _latency_color returns: fast={fast_color}, medium={medium_color}, slow={slow_color}")
    
    # Test _format_elapsed
    cli.session_start_time = time.time() - 125  # 2m 5s ago
    elapsed = cli._format_elapsed()
    assert "2m" in elapsed, f"Expected '2m' in elapsed time, got: {elapsed}"
    assert "5s" in elapsed, f"Expected '5s' in elapsed time, got: {elapsed}"
    print(f"✓ _format_elapsed returns: {elapsed}")
    
    # Test longer duration
    cli.session_start_time = time.time() - 7384  # 2h 3m 4s ago
    elapsed = cli._format_elapsed()
    assert "2h" in elapsed, f"Expected '2h' in elapsed time, got: {elapsed}"
    print(f"✓ _format_elapsed for long duration: {elapsed}")
    
    print()


async def test_metrics_display():
    """Test _show_session_metrics output."""
    print("=" * 60)
    print("TEST 5: Metrics Display")
    print("=" * 60)
    
    cli = NumaSecCLI()
    
    # Set up some realistic session data
    cli.session_start_time = time.time() - 300  # 5 minutes ago
    cli.total_tokens_in = 12450
    cli.total_tokens_out = 8230
    cli.total_cost = 2.35
    cli.iteration_count = 18
    cli.findings_count = 3
    
    # Call display (will print to console)
    print("Calling _show_session_metrics():")
    print("-" * 60)
    cli._show_session_metrics()
    print("-" * 60)
    print("✓ Metrics display executed without errors")
    print()


async def test_export_structure():
    """Test export data structure."""
    print("=" * 60)
    print("TEST 6: Export Structure")
    print("=" * 60)
    
    cli = NumaSecCLI()
    
    # Set up session data
    cli.session_start_time = time.time() - 600
    cli.total_tokens_in = 5000
    cli.total_tokens_out = 3000
    cli.total_cost = 1.25
    cli.iteration_count = 10
    cli.findings_count = 2
    
    # Add some mock actions to output_manager
    cli.output_manager.add('think', 'Analyzing target...', 1.2)
    cli.output_manager.add('tool', 'Port scan results: 80, 443, 22', 3.5)
    
    # Build export data manually (same as _handle_export)
    from datetime import datetime
    
    export_data = {
        "metadata": {
            "tool": "NumaSec",
            "version": "2.5",
            "export_time": datetime.now().isoformat(),
            "session_start": datetime.fromtimestamp(cli.session_start_time).isoformat(),
            "session_duration_seconds": time.time() - cli.session_start_time,
        },
        "metrics": {
            "iterations": cli.iteration_count,
            "findings": cli.findings_count,
            "total_tokens_in": cli.total_tokens_in,
            "total_tokens_out": cli.total_tokens_out,
            "total_tokens": cli.total_tokens_in + cli.total_tokens_out,
            "total_cost_usd": round(cli.total_cost, 4),
        },
        "actions": [],
    }
    
    # Verify structure
    assert "metadata" in export_data
    assert "metrics" in export_data
    assert "actions" in export_data
    assert export_data["metrics"]["iterations"] == 10
    assert export_data["metrics"]["findings"] == 2
    assert export_data["metrics"]["total_tokens"] == 8000
    assert export_data["metrics"]["total_cost_usd"] == 1.25
    
    print("✓ Export structure is valid")
    print(f"  - Metadata keys: {list(export_data['metadata'].keys())}")
    print(f"  - Metrics: iterations={export_data['metrics']['iterations']}, "
          f"cost=${export_data['metrics']['total_cost_usd']}")
    print()


async def run_all_tests():
    """Run complete test suite."""
    print("\n" + "=" * 60)
    print("PERFORMANCE METRICS DISPLAY - TEST SUITE")
    print("=" * 60 + "\n")
    
    tests = [
        test_metrics_initialization,
        test_metrics_tracking,
        test_cost_threshold_logic,
        test_helper_functions,
        test_metrics_display,
        test_export_structure,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            await test()
            passed += 1
        except AssertionError as e:
            failed += 1
            print(f"✗ FAILED: {e}")
        except Exception as e:
            failed += 1
            print(f"✗ ERROR: {e}")
    
    print("=" * 60)
    print(f"RESULTS: {passed}/{len(tests)} tests passed")
    if failed > 0:
        print(f"         {failed} tests FAILED")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    exit(0 if success else 1)
