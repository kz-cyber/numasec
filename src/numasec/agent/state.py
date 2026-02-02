"""
NumaSec.5 - Agent State Management
With Epistemic State Engine (Cognitive Ascension Upgrade)

Tracks the agent's short-term memory, execution path, context window,
and the structured Epistemic State (what the agent KNOWS vs. what it has DONE).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional, List, Dict
from enum import Enum

from numasec.client.providers.base import Message


# ══════════════════════════════════════════════════════════════════════════════
# DATA DEFINITIONS (Epistemic Primitives)
# ══════════════════════════════════════════════════════════════════════════════

class Confidence(str, Enum):
    SPECULATIVE = "SPECULATIVE"  # A guess / hypothesis
    POSSIBLE = "POSSIBLE"        # Weak evidence
    PROBABLE = "PROBABLE"        # Strong evidence, not yet confirmed
    CONFIRMED = "CONFIRMED"      # Exploited / Proven
    DISPROVEN = "DISPROVEN"      # Tested and failed

@dataclass
class TargetModel:
    """What we know about the target system."""
    url: str
    identified_tech: list[str] = field(default_factory=list) # e.g. "PHP", "WordPress"
    auth_mechanisms: list[str] = field(default_factory=list) # e.g. "Cookie", "Bearer"
    known_endpoints: list[str] = field(default_factory=list) # e.g. "/login", "/api"
    
    def summary(self) -> str:
        return (f"URL: {self.url} | Tech: {self.identified_tech} | "
                f"Auth: {self.auth_mechanisms} | Endpoints: {len(self.known_endpoints)}")

@dataclass
class Finding:
    """A confirmed security finding."""
    type: str # e.g. "SQL Injection"
    location: str # e.g. "/search?q="
    severity: str # "HIGH", "CRITICAL", etc.
    evidence: str # Proof
    confidence: Confidence = Confidence.CONFIRMED

@dataclass
class Hypothesis:
    """A working theory about a vulnerability."""
    id: str # e.g. "sqli_login"
    description: str # "SQLi likely in login form due to 500 on quote"
    test_plan: str # "Try boolean blind payloads"
    status: str = "ACTIVE" # ACTIVE, TESTED, ABANDONED
    failures: int = 0 # How many times we tried to prove this and failed

@dataclass
class Budget:
    """Execution constraints and remaining resources."""
    total_iterations: int
    used_iterations: int = 0
    failures_consecutive: int = 0
    
    @property
    def remaining(self) -> int:
        return max(0, self.total_iterations - self.used_iterations)

@dataclass
class EpistemicState:
    """
    The BRAIN of the agent.
    
    Unlike message history (which is a log of events), this is a 
    structured representation of KNOWLEDGE.
    """
    target: TargetModel
    findings: List[Finding] = field(default_factory=list)
    hypotheses: List[Hypothesis] = field(default_factory=list)
    
    # Constraints & Budget
    budget: Budget = field(default_factory=lambda: Budget(total_iterations=30))
    failed_attempts: Dict[str, int] = field(default_factory=dict) # e.g. {"sqli": 5}
    locked_categories: List[str] = field(default_factory=list) # e.g. ["sqli"]
    
    def to_string(self) -> str:
        """Serialize state for LLM injection."""
        data = {
            "TARGET_MODEL": asdict(self.target),
            "FINDINGS": [asdict(f) for f in self.findings],
            "ACTIVE_HYPOTHESES": [asdict(h) for h in self.hypotheses if h.status == "ACTIVE"],
            "CONSTRAINTS": {
                "budget": {
                    "used": self.budget.used_iterations,
                    "remaining": self.budget.remaining,
                    "max": self.budget.total_iterations
                },
                "locked_strategies": self.locked_categories,
                "failures_by_category": {k: f"{v}/3 (LOCKED)" if v >= 3 else f"{v}/3" for k, v in self.failed_attempts.items() if v > 0}
            }
        }
        return json.dumps(data, indent=2)
    
    def lock_category(self, category: str):
        """Permanently disable a strategy."""
        if category not in self.locked_categories:
            self.locked_categories.append(category)

    def record_failure(self, category: str):
        """Record a failure for a category and lock if threshold met."""
        self.failed_attempts[category] = self.failed_attempts.get(category, 0) + 1
        if self.failed_attempts[category] >= 3:
             self.lock_category(category)
             
    def consume_iteration(self):
        """Track usage."""
        self.budget.used_iterations += 1


# ══════════════════════════════════════════════════════════════════════════════
# Action History (For Evidence-First Loop Detection)
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class Action:
    """
    Record of a single action taken by the agent.
    
    Used for Evidence-First loop detection:
    - Tracks not just what action was taken (tool + args)
    - But also what RESULT it produced (hash + excerpt)
    - Enables detecting "same result despite different args"
    """
    
    iteration: int
    tool: str
    args: dict[str, Any]
    result: str
    result_hash: str = ""  # MD5 hash for similarity detection
    result_excerpt: str = ""  # First 200 chars for display
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def __post_init__(self):
        """Compute hash and excerpt after initialization."""
        if not self.result_hash and self.result:
            # Hash the result for similarity detection
            self.result_hash = hashlib.md5(self.result.encode()).hexdigest()[:8]
            
            # Extract meaningful excerpt (first 200 chars, strip whitespace)
            self.result_excerpt = self.result[:200].strip()


# ══════════════════════════════════════════════════════════════════════════════
# Loop Detection
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class TraversedPath:
    """Tracks the path of actions to detect infinite loops."""

    history: list[str] = field(default_factory=list)
    action_counts: dict[str, int] = field(default_factory=dict)
    
    def add(self, tool_name: str, arguments: dict[str, Any]) -> None:
        """Add an action to the path."""
        # Create a deterministic footprint of the action
        # Sort keys to ensure consistent JSON ordering
        args_str = json.dumps(arguments, sort_keys=True)
        fingerprint = f"{tool_name}:{hashlib.md5(args_str.encode()).hexdigest()}"
        
        self.history.append(fingerprint)
        self.action_counts[fingerprint] = self.action_counts.get(fingerprint, 0) + 1
        
    def is_looping(self, window: int = 3, threshold: int = 3) -> bool:
        """
        Detect if we are in a loop.
        
        Logic:
        1. Simple frequency: Have we done the exact same thing > threshold times?
        2. Pattern: Do we see a repeating sequence [A, B, A, B]? (Future enhancement)
        """
        if not self.history:
            return False
            
        last_action = self.history[-1]
        
        # Immediate repetition check
        if self.action_counts.get(last_action, 0) >= threshold:
            return True
            
        # Contextual check (last N actions were identical)
        if len(self.history) >= threshold:
            last_n = self.history[-threshold:]
            if all(x == last_action for x in last_n):
                return True
                
        return False
    
    def clear(self) -> None:
        """Reset path (e.g., when objective changes)."""
        self.history.clear()
        self.action_counts.clear()


# ══════════════════════════════════════════════════════════════════════════════
# Conversation Memory (Legacy - kept for compatibility)
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class ConversationMemory:
    """Track conversation context for intelligent chat mode."""
    
    findings: list[dict] = field(default_factory=list)  # Vulnerabilities found
    tested_vectors: set[str] = field(default_factory=set)  # Attack vectors tried
    user_preferences: dict[str, Any] = field(default_factory=dict)  # e.g., stealth_mode=True
    
    def add_finding(self, vuln_type: str, severity: str, evidence: str):
        """Record a security finding."""
        self.findings.append({
            "type": vuln_type,
            "severity": severity,
            "evidence": evidence[:200],
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    
    def mark_tested(self, vector: str):
        """Mark an attack vector as tested."""
        self.tested_vectors.add(vector)
    
    def was_tested(self, vector: str) -> bool:
        """Check if vector already tested."""
        return vector in self.tested_vectors
    
    def extract_preferences(self, user_input: str):
        """Extract user preferences from natural language."""
        lower = user_input.lower()
        if any(word in lower for word in ["stealth", "quiet", "avoid detection", "careful"]):
            self.user_preferences["stealth_mode"] = True
        if any(word in lower for word in ["fast", "quick", "rapid"]):
            self.user_preferences["speed"] = "fast"
        if any(word in lower for word in ["thorough", "detailed", "comprehensive"]):
            self.user_preferences["depth"] = "deep"
    
    def get_summary(self) -> str:
        """Generate context summary for LLM."""
        return f"""Previous findings: {len(self.findings)} vulnerabilities
Tested vectors: {', '.join(list(self.tested_vectors)[:5])}
Preferences: {self.user_preferences}"""


# ══════════════════════════════════════════════════════════════════════════════
# State Container
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class AgentState:
    """
    The rigid state of the agent.
    
    Acts as the "Context Window" manager.
    """
    
    target: str
    objective: str
    
    # Message History (Short-term memory)
    # We keep a separate list for the LLM context vs the full log
    context_messages: list[Message] = field(default_factory=list)
    
    # Path tracking for loop detection
    path: TraversedPath = field(default_factory=TraversedPath)
    
    # Full action history (for Evidence-First loop detection)
    # Tracks both actions AND their results
    history: list[Action] = field(default_factory=list)
    
    # Conversation Memory (Legacy)
    conversation: ConversationMemory = field(default_factory=ConversationMemory)
    
    # Epistemic State (The BRAIN)
    epistemic: Optional[EpistemicState] = None
    
    # Metadata
    start_time: datetime = field(default_factory=datetime.utcnow)
    iterations: int = 0
    
    # Session Variables (extracted from observations)
    # e.g., {"auth_token": "xyz", "secret": "PASSWORD{...}"}
    variables: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        # Initialize epistemic state if not provided
        if self.epistemic is None:
            self.epistemic = EpistemicState(
                target=TargetModel(url=self.target)
            )

    def add_message(self, role: str, content: str, tool_calls: list = None, tool_call_id: str = None):
        """Add a message to the context."""
        msg = Message(
            role=role,
            content=content,
            tool_calls=tool_calls,
            tool_call_id=tool_call_id
        )
        self.context_messages.append(msg)
        
    def get_context(self, max_messages: int = 20) -> list[Message]:
        """
        Get the messages formatted for the LLM, with sliding window.
        
        CRITICAL CHANGE: This likely needs to be updated to inject Epistemic State.
        But we might handle that in the Agent class loop instead.
        """
        # Always keep System Prompt (index 0)
        if not self.context_messages:
            return []
            
        system = self.context_messages[0]
        recent = self.context_messages[-max_messages:]
        
        # Ensure we don't duplicate system prompt if it's in relevant
        if recent[0].role == "system":
            return recent
            
        return [system] + recent
        
    def update_variable(self, key: str, value: Any):
        """Update a known variable (e.g., captured flag)."""
        self.variables[key] = value
    
    def record_action(self, iteration: int, tool: str, args: dict, result: str):
        """
        Record action with result for Evidence-First detection.
        """
        action = Action(
            iteration=iteration,
            tool=tool,
            args=args,
            result=result
        )
        self.history.append(action)
