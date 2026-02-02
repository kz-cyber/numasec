#!/usr/bin/env python3
"""
Validation script for the Cyberpunk CLI implementation.
Tests imports and basic functionality without requiring API keys.
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_imports():
    """Test that all imports work"""
    print("Testing imports...")
    
    try:
        from numasec.cli.cyberpunk_theme import (
            CYBERPUNK_THEME,
            CyberpunkUI,
            CyberpunkArt,
            NEON_GREEN,
            CYBER_PURPLE,
            WARNING_RED,
        )
        print("✓ cyberpunk_theme imports OK")
    except Exception as e:
        print(f"✗ cyberpunk_theme import failed: {e}")
        return False
    
    try:
        from numasec.cli.cyberpunk_interface import (
            NumaSecCLI,
            CLIState,
            main,
            run,
        )
        print("✓ cyberpunk_interface imports OK")
    except Exception as e:
        print(f"✗ cyberpunk_interface import failed: {e}")
        return False
    
    try:
        from numasec.cli import app, NumaSecCLI, run
        print("✓ cli package exports OK")
    except Exception as e:
        print(f"✗ cli package export failed: {e}")
        return False
    
    return True


def test_theme_components():
    """Test theme rendering without running the full CLI"""
    print("\nTesting theme components...")
    
    try:
        from rich.console import Console
        from numasec.cli.cyberpunk_theme import CyberpunkUI, CYBERPUNK_THEME
        
        console = Console(theme=CYBERPUNK_THEME)
        ui = CyberpunkUI(console)
        
        # Test panel creation (doesn't print, just creates objects)
        panel = ui.panel_thinking("Test reasoning", 1)
        assert panel is not None
        print("✓ panel_thinking OK")
        
        panel = ui.panel_tool("test_tool", {"param": "value"}, "result")
        assert panel is not None
        print("✓ panel_tool OK")
        
        panel = ui.panel_vulnerability("XSS", "HIGH", "Test evidence")
        assert panel is not None
        print("✓ panel_vulnerability OK")
        
        panel = ui.panel_complete(10, 2, "completed")
        assert panel is not None
        print("✓ panel_complete OK")
        
        table = ui.table_tools([{"name": "test", "description": "test tool"}])
        assert table is not None
        print("✓ table_tools OK")
        
        return True
        
    except Exception as e:
        print(f"✗ Theme component test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cli_instantiation():
    """Test that CLI can be instantiated (without connecting)"""
    print("\nTesting CLI instantiation...")
    
    try:
        from numasec.cli.cyberpunk_interface import NumaSecCLI, CLIState
        
        cli = NumaSecCLI()
        
        # Check attributes
        assert cli.console is not None
        assert cli.ui is not None
        assert cli.state == CLIState.IDLE
        assert cli.current_agent_task is None
        assert cli.interrupt_requested is False
        assert cli.key_bindings is not None
        
        print("✓ CLI instantiation OK")
        print(f"  - Initial state: {cli.state}")
        print(f"  - Key bindings: {len(cli.key_bindings.bindings)} bindings registered")
        
        return True
        
    except Exception as e:
        print(f"✗ CLI instantiation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_state_enum():
    """Test CLIState enum"""
    print("\nTesting CLIState enum...")
    
    try:
        from numasec.cli.cyberpunk_interface import CLIState
        
        assert CLIState.IDLE.value == "idle"
        assert CLIState.BUSY.value == "busy"
        assert CLIState.INTERRUPTED.value == "interrupted"
        
        print("✓ CLIState enum OK")
        print(f"  - States: {[s.value for s in CLIState]}")
        
        return True
        
    except Exception as e:
        print(f"✗ CLIState test failed: {e}")
        return False


def main():
    """Run all validation tests"""
    print("=" * 60)
    print("NumaSec - Cyberpunk CLI Validation")
    print("=" * 60)
    
    tests = [
        ("Imports", test_imports),
        ("Theme Components", test_theme_components),
        ("State Enum", test_state_enum),
        ("CLI Instantiation", test_cli_instantiation),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n✗ {name} raised exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All validations passed! The Cyberpunk CLI is ready.")
        return 0
    else:
        print(f"\n⚠ {total - passed} validation(s) failed. Review errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
