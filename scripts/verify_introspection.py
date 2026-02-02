
import sys
import os
import json
import logging
from dataclasses import asdict

# Add src to path
sys.path.append('src')

from numasec.agent.state import EpistemicState, TargetModel, Budget, Finding, Hypothesis
from numasec.agent.cognitive_reasoner import CognitiveReasoner
from numasec.ai.router import LLMRouter

# Mock objects
class MockRouter(LLMRouter):
    def __init__(self):
        pass

def test_epistemic_state():
    print("Testing EpistemicState...")
    
    state = EpistemicState(
        target=TargetModel(url="http://test.com"),
        budget=Budget(total_iterations=30, used_iterations=5, failures_consecutive=2)
    )
    
    state.record_failure("sqli")
    state.record_failure("sqli")
    state.record_failure("sqli") # Should lock
    
    state_json = state.to_string()
    data = json.loads(state_json)
    
    assert data['CONSTRAINTS']['budget']['remaining'] == 25
    assert "sqli" in data['CONSTRAINTS']['locked_strategies']
    assert data['CONSTRAINTS']['failures_by_category']['sqli'] == "3/3 (LOCKED)"
    
    print("✅ EpistemicState serialized correctly with Budget and Locks.")

def test_reasoning_validation():
    print("Testing Reasoning Validation...")
    
    reasoner = CognitiveReasoner(MockRouter())
    
    # Valid XML
    valid_xml = """
    <analysis>Previous step failed.</analysis>
    <hypothesis>Testing SQLi now.</hypothesis>
    <confidence>PROBABLE</confidence>
    <action>web_request</action>
    <expectation>Status 500</expectation>
    """
    assert reasoner._validate_reasoning(valid_xml) is None
    
    # Missing tag
    invalid_xml_tag = """
    <analysis>Missing hypothesis</analysis>
    <confidence>PROBABLE</confidence>
    <action>tool</action>
    <expectation>test</expectation>
    """
    error = reasoner._validate_reasoning(invalid_xml_tag)
    assert error is not None and "Missing required XML tags" in error
    
    # Invalid confidence
    invalid_conf = """
    <analysis>A</analysis><hypothesis>H</hypothesis>
    <confidence>VERY SURE</confidence>
    <action>A</action><expectation>E</expectation>
    """
    error = reasoner._validate_reasoning(invalid_conf)
    assert error is not None and "Invalid confidence level" in error
    
    print("✅ Reasoning validation works.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        test_epistemic_state()
        test_reasoning_validation()
        print("\n🎉 ALL INTROSPECTION TESTS PASSED!")
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)
