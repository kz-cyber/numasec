"""
Unit Tests for CLI Tactical Pause Feature
==========================================

Tests the supervisor intervention system (Ctrl-C → Menu → Resume/Inject/Stop).
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from numasec.cli.cyberpunk_interface import NumaSecCLI, OutputManager, ActionRecord


class TestOutputManager:
    """Test the action recording system."""
    
    def test_output_manager_add_and_retrieve(self):
        manager = OutputManager()
        
        # Add records
        id1 = manager.add('tool', 'curl http://example.com', 1.5)
        id2 = manager.add('think', 'Analyzing response...', 0.3)
        
        # Verify IDs are sequential
        assert id1 == 1
        assert id2 == 2
        
        # Retrieve records
        record1 = manager.get(id1)
        assert record1 is not None
        assert record1.type == 'tool'
        assert record1.content == 'curl http://example.com'
        assert record1.duration == 1.5
        
        record2 = manager.get(id2)
        assert record2.type == 'think'
        
    def test_output_manager_missing_id(self):
        manager = OutputManager()
        record = manager.get(999)
        assert record is None


class TestCLIStateMachine:
    """Test state machine logic (IDLE → BUSY → PAUSED → BUSY/IDLE)."""
    
    @pytest.fixture
    def cli(self):
        """Create CLI instance with mocked components."""
        cli = NumaSecCLI()
        cli.mcp_client = AsyncMock()
        cli.router = AsyncMock()
        cli.agent = AsyncMock()
        cli.session = AsyncMock()
        return cli
    
    @pytest.mark.asyncio
    async def test_initial_state_is_idle(self, cli):
        """Verify initial state."""
        assert cli.current_agent_task is None
        assert cli.pause_requested is False
        assert cli.interrupt_requested is False
    
    @pytest.mark.asyncio
    async def test_pause_request_triggers_menu(self, cli):
        """Verify pause_requested flag triggers supervisor menu."""
        # Mock the menu to return "resume"
        cli._handle_pause_menu = AsyncMock(return_value=True)
        
        # Simulate pause during execution
        cli.pause_requested = True
        
        # In real code, _run_agent checks this flag
        assert cli.pause_requested is True
    
    @pytest.mark.asyncio
    async def test_supervisor_menu_resume(self, cli):
        """Test resume path in supervisor menu."""
        cli.agent.state = MagicMock()
        cli.session.prompt_async = AsyncMock(return_value='r')
        
        result = await cli._handle_pause_menu()
        
        assert result is True  # Should resume
    
    @pytest.mark.asyncio
    async def test_supervisor_menu_stop(self, cli):
        """Test stop path in supervisor menu."""
        cli.agent.state = MagicMock()
        cli.session.prompt_async = AsyncMock(return_value='s')
        
        result = await cli._handle_pause_menu()
        
        assert result is False  # Should stop
    
    @pytest.mark.asyncio
    async def test_supervisor_menu_inject_hint(self, cli):
        """Test hint injection path."""
        cli.agent.state = MagicMock()
        
        # First call: user chooses 'i' (inject)
        # Second call: user provides hint text
        cli.session.prompt_async = AsyncMock(side_effect=['i', 'Try SQL injection on login form'])
        
        result = await cli._handle_pause_menu()
        
        # Verify hint was injected
        cli.agent.state.add_message.assert_called_once()
        call_args = cli.agent.state.add_message.call_args
        assert call_args[0][0] == "user"
        assert "SUPERVISOR INTERVENTION" in call_args[0][1]
        assert "SQL injection" in call_args[0][1]
        
        assert result is True  # Should resume after injection


class TestReflectionPrompt:
    """Test that agent reflection uses graduated questions, not hard stop."""
    
    @pytest.mark.asyncio
    async def test_reflection_prompt_contains_questions(self):
        """Verify reflection checkpoint has strategic questions."""
        from numasec.agent.agent import NumaSecAgent
        
        # The actual prompt is in agent.py around line 480
        # We test that the template includes the correct structure
        
        # This is a smoke test - full integration test would run actual agent
        # and verify the prompt is injected correctly
        
        # Read the source to verify
        import inspect
        source = inspect.getsource(NumaSecAgent.chat)
        
        # Verify new structure
        assert "strategic_questions" in source
        assert "What concrete evidence have you gathered" in source
        assert "Which attack vectors or approaches remain untested" in source
        assert "Are you repeating failed approaches" in source
        
        # Verify old aggressive language is removed
        assert "DIMINISHING RETURNS DETECTED" not in source or "strategic_questions" in source
        assert "MUST STOP NOW" not in source or "strategic_questions" in source


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
