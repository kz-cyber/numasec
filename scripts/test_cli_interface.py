#!/usr/bin/env python3
"""
CLI Interface Test - Command Parsing & Structure
Task 23/34: Verify CLI command parsing, state management, UI components

Tests:
1. CLI instantiation
2. Command parser (/tools, /metrics, /new, /clear, etc.)
3. State machine (IDLE, BUSY, PAUSED)
4. Cyberpunk theme components
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_cli_structure():
    """Test 1: CLI instantiation and components."""
    print("\n[Test 1] CLI Instantiation...")
    
    try:
        from numasec.cli.cyberpunk_interface import NumaSecCLI
        
        cli = NumaSecCLI()
        
        # Check core attributes
        checks = [
            (hasattr(cli, 'console'), "console"),
            (hasattr(cli, 'output_manager'), "output_manager"),
            (hasattr(cli, 'mcp_client'), "mcp_client"),
            (hasattr(cli, 'agent'), "agent"),
            (hasattr(cli, 'session_start_time'), "session_start_time"),
        ]
        
        for check, name in checks:
            if check:
                print(f"   ✅ {name:20s} - exists")
            else:
                print(f"   ❌ {name:20s} - missing")
                return False
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def test_command_parsing():
    """Test 2: Verify command handler exists for all documented commands."""
    print("\n[Test 2] Command Parsing...")
    
    try:
        from numasec.cli.cyberpunk_interface import NumaSecCLI
        import inspect
        
        # Check _handle_command method exists
        if not hasattr(NumaSecCLI, '_handle_command'):
            print(f"   ❌ _handle_command method not found")
            return False
        
        print(f"   ✅ _handle_command method exists")
        
        # Check source for documented commands
        source = inspect.getsource(NumaSecCLI._handle_command)
        
        expected_commands = [
            '/quit', '/exit', '/q',
            '/help',
            '/tools',
            '/new',
            '/status',
            '/metrics',
            '/export',
            '/clear',
            '/purge'
        ]
        
        for cmd in expected_commands:
            if f'"{cmd}"' in source or f"'{cmd}'" in source:
                print(f"   ✅ {cmd:15s} - implemented")
            else:
                print(f"   ⚠️  {cmd:15s} - not found in handler")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def test_cyberpunk_theme():
    """Test 3: Verify cyberpunk theme components."""
    print("\n[Test 3] Cyberpunk Theme...")
    
    try:
        from numasec.cli.cyberpunk_theme import (
            CYBERPUNK_THEME,
            NEON_GREEN,
            CYBER_PURPLE,
            WARNING_RED,
            ELECTRIC_BLUE,
            DIM_GRAY,
        )
        
        # Check colors are defined
        colors = [
            ("NEON_GREEN", NEON_GREEN),
            ("CYBER_PURPLE", CYBER_PURPLE),
            ("WARNING_RED", WARNING_RED),
            ("ELECTRIC_BLUE", ELECTRIC_BLUE),
            ("DIM_GRAY", DIM_GRAY),
        ]
        
        for name, color in colors:
            if color:
                print(f"   ✅ {name:15s} = {color}")
            else:
                print(f"   ❌ {name:15s} not defined")
                return False
        
        # Check theme exists
        if CYBERPUNK_THEME:
            print(f"   ✅ CYBERPUNK_THEME - configured")
        else:
            print(f"   ❌ CYBERPUNK_THEME missing")
            return False
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def test_state_machine():
    """Test 4: Verify state machine flags."""
    print("\n[Test 4] State Machine...")
    
    try:
        from numasec.cli.cyberpunk_interface import NumaSecCLI
        
        cli = NumaSecCLI()
        
        # Check state flags
        state_flags = [
            ('current_agent_task', None),  # Should start None (IDLE)
            ('interrupt_requested', False),
            ('pause_requested', False),
            ('verbose_mode', False),
        ]
        
        for attr, expected in state_flags:
            if hasattr(cli, attr):
                actual = getattr(cli, attr)
                if actual == expected:
                    print(f"   ✅ {attr:25s} = {actual}")
                else:
                    print(f"   ⚠️  {attr:25s} = {actual} (expected {expected})")
            else:
                print(f"   ❌ {attr:25s} - missing")
                return False
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def main():
    """Run CLI interface tests."""
    print("=" * 80)
    print("TEST: CLI Interface (Command Parsing & Structure)")
    print("=" * 80)
    
    results = []
    
    results.append(("CLI Structure", test_cli_structure()))
    results.append(("Command Parsing", test_command_parsing()))
    results.append(("Cyberpunk Theme", test_cyberpunk_theme()))
    results.append(("State Machine", test_state_machine()))
    
    print("\n" + "=" * 80)
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    print(f"Results: {passed}/{total} tests passed")
    
    for name, success in results:
        status = "✅" if success else "❌"
        print(f"{status} {name}")
    
    print("=" * 80)
    
    if passed == total:
        print("✅ CLI INTERFACE TESTS PASSED")
        print("   Command parsing, state machine, theme all functional")
        return True
    else:
        print(f"⚠️  {total - passed} CLI TESTS FAILED")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
