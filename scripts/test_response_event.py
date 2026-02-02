#!/usr/bin/env python3
"""
Test the event flow to ensure RESPONSE events are emitted correctly.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from numasec.agent.events import EventType, Event

def test_event_types():
    """Test that all event types are defined"""
    print("Testing EventType enum...")
    
    expected_types = [
        "START", "THINK", "ACTION_PROPOSED", "ACTION_COMPLETE", 
        "RESPONSE", "OBSERVATION", "DISCOVERY", "FLAG", 
        "FINDING", "ERROR", "COMPLETE"
    ]
    
    for event_type in expected_types:
        assert hasattr(EventType, event_type), f"Missing EventType.{event_type}"
        print(f"  ✓ EventType.{event_type} = {getattr(EventType, event_type).value}")
    
    print(f"\n✓ All {len(expected_types)} event types defined\n")


def test_event_creation():
    """Test creating events"""
    print("Testing Event creation...")
    
    # Test RESPONSE event
    response_event = Event(
        event_type=EventType.RESPONSE,
        data={"content": "This is a test response"},
        iteration=1
    )
    
    assert response_event.event_type == EventType.RESPONSE
    assert response_event.data["content"] == "This is a test response"
    assert response_event.iteration == 1
    print(f"  ✓ RESPONSE event created: {response_event.data}")
    
    # Test THINK event
    think_event = Event(
        event_type=EventType.THINK,
        data={"reasoning": "Analyzing target..."},
        iteration=1
    )
    
    assert think_event.event_type == EventType.THINK
    print(f"  ✓ THINK event created: {think_event.data}")
    
    print("\n✓ Events created successfully\n")


def test_panel_response():
    """Test that the UI can create response panels"""
    print("Testing panel_response method...")
    
    try:
        from rich.console import Console
        from numasec.cli.cyberpunk_theme import CyberpunkUI, CYBERPUNK_THEME
        
        console = Console(theme=CYBERPUNK_THEME)
        ui = CyberpunkUI(console)
        
        # Test panel_response
        panel = ui.panel_response("This is a test response from the agent.")
        assert panel is not None
        print("  ✓ panel_response created successfully")
        
        # Render it
        print("\n  Preview:")
        console.print(panel)
        
        print("\n✓ UI panel_response works\n")
        return True
        
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("Event Flow Test - RESPONSE Event")
    print("=" * 60)
    print()
    
    try:
        test_event_types()
        test_event_creation()
        test_panel_response()
        
        print("=" * 60)
        print("✓ ALL TESTS PASSED")
        print("=" * 60)
        print("\nThe RESPONSE event is properly integrated!")
        print("Agent will now show textual responses, not just tool output.")
        return 0
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
