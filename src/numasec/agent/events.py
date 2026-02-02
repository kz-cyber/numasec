"""
NumaSec - Agent Events

Events emitted by the agent during the cognitive loop.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class EventType(str, Enum):
    """Types of events emitted by the agent."""
    
    START = "start"
    THINK = "think"  # Reasoning process
    ACTION_PROPOSED = "action_proposed"  # Tool selected
    ACTION_COMPLETE = "action_complete"  # Tool executed
    RESPONSE = "response"  # Agent's textual response to user
    OBSERVATION = "observation"  # New data found
    DISCOVERY = "discovery"  # Important finding
    FLAG = "flag"  # Captured flag
    FINDING = "finding"  # Vulnerability found
    ERROR = "error"
    COMPLETE = "complete"


@dataclass
class Event:
    """An event in the agent loop."""
    
    event_type: EventType
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: __import__("time").time())
    iteration: int = 0
