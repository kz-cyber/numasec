"""
Tests for Error-Aware Intelligence (SOTA 2026).

Verifies that the agent provides GUIDANCE instead of terminating:
1. Nmap syntax errors get explained
2. Connection failures get diagnosed
3. Repeated errors trigger pivot suggestions
"""

import pytest
from unittest.mock import Mock, AsyncMock
from collections import deque

from numasec.agent.agent import AgentConfig


class TestAgentConfigErrorThresholds:
    """Test AgentConfig has correct error threshold defaults."""
    
    def test_default_thresholds(self):
        """Verify default error thresholds are set correctly."""
        config = AgentConfig()
        
        assert config.max_consecutive_connection_errors == 3
        assert config.max_same_error_repeats == 2
        assert config.max_tool_repetitions == 3
    
    def test_custom_thresholds(self):
        """Verify custom thresholds can be set."""
        config = AgentConfig(
            max_consecutive_connection_errors=5,
            max_same_error_repeats=3,
            max_tool_repetitions=4
        )
        
        assert config.max_consecutive_connection_errors == 5
        assert config.max_same_error_repeats == 3
        assert config.max_tool_repetitions == 4


class TestGenerateErrorGuidance:
    """Test _generate_error_guidance provides intelligent feedback."""
    
    @pytest.fixture
    def mock_agent(self):
        """Create a minimal mock agent for testing error guidance."""
        from numasec.agent.agent import NumaSecAgent
        
        # Create mock dependencies
        mock_router = Mock()
        mock_mcp = Mock()
        mock_mcp.tools = []
        
        # Create agent with custom config
        config = AgentConfig(
            max_consecutive_connection_errors=3,
            max_same_error_repeats=2,
            max_tool_repetitions=3
        )
        
        agent = NumaSecAgent.__new__(NumaSecAgent)
        agent.config = config
        agent._consecutive_connection_errors = 0
        agent._last_error_message = ""
        agent._same_error_count = 0
        agent._tool_call_history = deque(maxlen=10)
        
        return agent
    
    def test_nmap_syntax_error_provides_guidance(self, mock_agent):
        """Nmap -F -p conflict should provide specific fix."""
        result = '{"status": "failed", "error": "You cannot use -F (fast scan) with -p"}'
        
        guidance = mock_agent._generate_error_guidance(
            "recon_nmap", {"ports": "80", "scan_type": "quick"}, result
        )
        
        assert guidance is not None
        assert "NMAP SYNTAX ERROR" in guidance
        assert "FIX:" in guidance
        assert "scan_type='default'" in guidance
    
    def test_connection_error_provides_diagnosis(self, mock_agent):
        """Connection errors should provide actionable diagnosis."""
        result = '{"success": false, "error": "All connection attempts failed"}'
        
        # First error - warning
        guidance = mock_agent._generate_error_guidance(
            "web_request", {"url": "http://test.com"}, result
        )
        assert guidance is not None
        assert "Connection failed (1/3)" in guidance
        
        # Third error - strong guidance
        mock_agent._generate_error_guidance("web_request", {}, result)
        guidance = mock_agent._generate_error_guidance("web_request", {}, result)
        
        assert "TARGET UNREACHABLE" in guidance
        assert "INFORM THE USER" in guidance
    
    def test_successful_request_resets_counter(self, mock_agent):
        """Successful request should reset connection error counter."""
        # First, trigger error
        error_result = '{"success": false, "error": "Connection refused"}'
        mock_agent._generate_error_guidance("web_request", {}, error_result)
        assert mock_agent._consecutive_connection_errors == 1
        
        # Now successful request
        success_result = '{"success": true, "status_code": 200}'
        mock_agent._generate_error_guidance("web_request", {}, success_result)
        assert mock_agent._consecutive_connection_errors == 0
    
    def test_repeated_error_suggests_pivot(self, mock_agent):
        """Same error repeated should suggest changing approach."""
        result = '{"status": "failed", "error": "Permission denied"}'
        
        # First occurrence
        guidance = mock_agent._generate_error_guidance("test_tool", {}, result)
        assert guidance is None or "REPEATED ERROR" not in guidance
        
        # Same error again - should suggest pivot
        guidance = mock_agent._generate_error_guidance("test_tool", {}, result)
        
        assert guidance is not None
        assert "REPEATED ERROR" in guidance
        assert "DIFFERENT approach" in guidance
    
    def test_timeout_error_provides_guidance(self, mock_agent):
        """Timeout errors should suggest reducing scope."""
        result = '{"status": "timeout", "error": "Process timed out after 300 seconds"}'
        
        guidance = mock_agent._generate_error_guidance("recon_whatweb", {}, result)
        
        assert guidance is not None
        assert "TIMEOUT" in guidance
        assert "Reduce scope" in guidance
    
    def test_no_guidance_for_success(self, mock_agent):
        """Successful results should return no guidance."""
        result = '{"success": true, "data": {"hosts": []}}'
        
        guidance = mock_agent._generate_error_guidance("recon_nmap", {}, result)
        
        assert guidance is None
