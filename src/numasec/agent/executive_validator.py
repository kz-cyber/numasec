"""
Emergency Executive Validator - Immediate Fix for Agent Loops

MISSION: Prevent systematic repeated failures by adding deterministic
validation layer before tool execution.

This is NOT over-engineering. This is mathematics:
- LLM generates intentions (probabilistic)
- Validator ensures sanity (deterministic)
- Only validated actions execute

Scientific basis:
- Human cognition has Executive Function for action control
- Current agent lacks this entirely
- Result: Working memory corruption leads to repeated systematic errors
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import logging
from collections import defaultdict

logger = logging.getLogger("numasec.executive")


@dataclass
class ActionResult:
    """Record of an executed action."""
    tool: str
    args: Dict[str, Any]
    success: bool
    error: Optional[str] = None
    timestamp: float = 0.0


@dataclass
class Intention:
    """LLM-generated intention before validation."""
    goal: str           # High-level objective
    tool: str          # Tool to use
    args: Dict[str, Any]  # Tool arguments
    reasoning: str     # LLM reasoning
    confidence: float  # LLM confidence


class EmergencyValidator:
    """
    Deterministic validator to prevent obvious systematic errors.
    
    Philosophy: Block actions that are mathematically wrong
    given the context and history.
    """
    
    def __init__(self):
        self.action_history: List[ActionResult] = []
        self.failure_counts: Dict[str, int] = defaultdict(int)
    
    def validate(self, intention: Intention) -> tuple[bool, str]:
        """
        Validate if intention should be executed.
        
        Returns:
            (is_valid, reason_if_invalid)
        """
        # Emergency Brake 1: Identical Repeated Failures
        if self._is_repeated_failure(intention):
            return False, f"BLOCKED: Identical action failed {self.failure_counts[self._action_key(intention)]} times"
        
        # Emergency Brake 2: URL Logic Check for Web Requests
        if intention.tool == "web_request":
            url_check = self._validate_web_url(intention)
            if not url_check[0]:
                return url_check
        
        # Emergency Brake 3: Obvious Context Violations
        context_check = self._validate_context_logic(intention)
        if not context_check[0]:
            return context_check
        
        return True, "Valid"
    
    def record_result(self, intention: Intention, success: bool, error: Optional[str] = None):
        """Record execution result for learning."""
        result = ActionResult(
            tool=intention.tool,
            args=intention.args.copy(),
            success=success,
            error=error
        )
        
        self.action_history.append(result)
        
        # Track failures for repeat prevention
        if not success:
            action_key = self._action_key(intention)
            self.failure_counts[action_key] += 1
            logger.warning(f"🚨 Action failed: {action_key} (count: {self.failure_counts[action_key]})")
    
    def _action_key(self, intention: Intention) -> str:
        """Create unique key for action tracking."""
        # For web_request, key by method+url
        if intention.tool == "web_request":
            method = intention.args.get("method", "GET")
            url = intention.args.get("url", "")
            return f"{intention.tool}:{method}:{url}"
        
        # For other tools, key by tool+main_arg
        main_args = str(sorted(intention.args.items()))
        return f"{intention.tool}:{main_args}"
    
    def _is_repeated_failure(self, intention: Intention) -> bool:
        """Check if this exact action has failed multiple times."""
        action_key = self._action_key(intention)
        return self.failure_counts[action_key] >= 2  # Allow 2 tries max
    
    def _validate_web_url(self, intention: Intention) -> tuple[bool, str]:
        """Validate web request URL makes sense for the goal."""
        url = intention.args.get("url", "")
        goal = intention.goal.lower()
        
        # Rule: If goal is "login" but URL contains "flag", block it
        if "login" in goal and "/flag" in url:
            return False, f"BLOCKED: Goal is '{intention.goal}' but URL is '{url}' - mismatch"
        
        # Rule: If goal is "get flag" but URL is login page, suggest redirect
        if "flag" in goal and "login" in url and intention.args.get("method") == "GET":
            return False, f"BLOCKED: Goal is '{intention.goal}' but trying GET on login URL - need auth first"
        
        return True, "Valid web URL"
    
    def _validate_context_logic(self, intention: Intention) -> tuple[bool, str]:
        """Check for obvious logical inconsistencies."""
        
        # Rule: Don't repeat identical GET requests IMMEDIATELY (only if last action was successful)
        if (intention.tool == "web_request" and 
            intention.args.get("method") == "GET" and
            len(self.action_history) > 0):
            
            last_action = self.action_history[-1]
            if (last_action.tool == "web_request" and
                last_action.args.get("method") == "GET" and
                last_action.args.get("url") == intention.args.get("url") and
                last_action.success):  # Only block if last was successful
                return False, "BLOCKED: Identical GET request to same URL as successful last action"
        
        return True, "Valid context"
    
    def get_recent_failures(self, limit: int = 5) -> List[ActionResult]:
        """Get recent failed actions for debugging."""
        return [action for action in self.action_history[-limit:] if not action.success]
    
    def is_stuck_in_loop(self) -> bool:
        """Detect if agent is in action loop."""
        if len(self.action_history) < 3:
            return False
        
        # Check if last 3 actions are essentially identical
        last_three = self.action_history[-3:]
        action_keys = [f"{action.tool}:{action.args.get('url', action.args)}" 
                      for action in last_three]
        
        return len(set(action_keys)) == 1  # All identical