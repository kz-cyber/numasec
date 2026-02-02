#!/usr/bin/env python3
"""
Test Agent Cognitive Components - ReAct/Reasoning/Loop Detection
Task 16-19 Combined: Verify cognitive architecture without LLM calls

Components:
- ReAct loop structure (events, state management)
- Cognitive reasoner mode selection
- Loop detection (evidence-first)
- Meta-learning (strategy tracker)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_react_structure():
    """Test 1: Verify ReAct loop infrastructure exists."""
    print("\n[Test 1] ReAct Loop Structure...")
    
    try:
        from numasec.agent.events import Event, EventType
        from numasec.agent.state import AgentState
        
        # Verify EventTypes for ReAct cycle
        required_events = [
            EventType.THINK,           # Reasoning
            EventType.ACTION_PROPOSED, # Plan
            EventType.ACTION_COMPLETE, # Act
            EventType.OBSERVATION,     # Perceive
        ]
        
        for event_type in required_events:
            print(f"   ✅ {event_type.value:20s} - Event type exists")
        
        # Verify AgentState structure
        state = AgentState(target="test.com", objective="test")
        
        if hasattr(state, 'iterations') and hasattr(state, 'history'):
            print(f"   ✅ AgentState structure - iteration tracking OK")
        else:
            print(f"   ❌ AgentState missing required fields")
            return False
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def test_cognitive_reasoner():
    """Test 2: Verify cognitive reasoner mode selection."""
    print("\n[Test 2] Cognitive Reasoner Modes...")
    
    try:
        from numasec.agent.cognitive_reasoner import CognitiveReasoner, ReasoningMode
        from numasec.ai.router import LLMRouter
        
        # Check modes exist
        modes = [
            ReasoningMode.SINGLE,  # Fast (1 call)
            ReasoningMode.LIGHT,   # Medium (3-5 calls)
            ReasoningMode.DEEP,    # Slow (8+ calls)
        ]
        
        for mode in modes:
            print(f"   ✅ {mode.value:10s} mode - exists")
        
        # Verify reasoner can be instantiated
        router = None  # Mock
        reasoner = CognitiveReasoner(router)
        
        if hasattr(reasoner, '_select_mode'):
            print(f"   ✅ Mode selection logic - exists")
        else:
            print(f"   ⚠️  _select_mode method not found")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def test_loop_detection():
    """Test 3: Verify loop detection (evidence-first)."""
    print("\n[Test 3] Loop Detection (Evidence-First)...")
    
    try:
        from numasec.agent.agent import NumaSecAgent
        from collections import deque
        
        # Verify agent has loop tracking
        # We can't instantiate agent without router, but can check class
        
        # Check if loop_history attribute is defined in __init__
        import inspect
        init_source = inspect.getsource(NumaSecAgent.__init__)
        
        if "loop_history" in init_source and "deque" in init_source:
            print(f"   ✅ loop_history deque - initialized")
        else:
            print(f"   ❌ loop_history not found in __init__")
            return False
        
        # Check if _detect_identical_results method exists
        if hasattr(NumaSecAgent, '_detect_identical_results'):
            print(f"   ✅ _detect_identical_results - method exists")
        else:
            print(f"   ⚠️  _detect_identical_results not found")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def test_meta_learning():
    """Test 4: Verify meta-learning (strategy tracker)."""
    print("\n[Test 4] Meta-Learning (Strategy Tracker)...")
    
    try:
        from numasec.agent.unified_adaptive_strategy import UnifiedAdaptiveStrategy
        from numasec.agent.meta_learning_orchestrator import MetaLearningOrchestrator
        
        # Check UnifiedAdaptiveStrategy
        strategy = UnifiedAdaptiveStrategy()
        
        if hasattr(strategy, 'meta_learner'):
            print(f"   ✅ meta_learner - exists")
        else:
            print(f"   ⚠️  meta_learner not found")
        
        if hasattr(strategy, 'state'):
            print(f"   ✅ Strategy state tracking - exists")
        else:
            print(f"   ⚠️  state attribute not found")
        
        # Check MetaLearningOrchestrator
        if hasattr(MetaLearningOrchestrator, 'record_action'):
            print(f"   ✅ record_action - exists")
        else:
            print(f"   ⚠️  record_action not found")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False


def main():
    """Run all cognitive component tests."""
    print("=" * 80)
    print("TEST: Agent Cognitive Components (Architecture Verification)")
    print("=" * 80)
    
    results = []
    
    results.append(("ReAct Structure", test_react_structure()))
    results.append(("Cognitive Reasoner", test_cognitive_reasoner()))
    results.append(("Loop Detection", test_loop_detection()))
    results.append(("Meta-Learning", test_meta_learning()))
    
    print("\n" + "=" * 80)
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    print(f"Results: {passed}/{total} components verified")
    
    for name, success in results:
        status = "✅" if success else "❌"
        print(f"{status} {name}")
    
    print("=" * 80)
    
    if passed == total:
        print("✅ ALL COGNITIVE COMPONENTS PRESENT")
        print("   ReAct loop, reasoning modes, loop detection, meta-learning exist")
        return True
    else:
        print(f"⚠️  {total - passed} COMPONENTS MISSING OR INCOMPLETE")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
