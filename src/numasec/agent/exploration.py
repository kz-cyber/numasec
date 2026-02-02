"""
NumaSec - UCB1 Exploration

Upper Confidence Bound (UCB1) exploration policy for action selection.
Prevents agent from repeating low-reward actions.

Scientific Basis:
- Paper: "Bandit Based Monte-Carlo Planning" (Kocsis & Szepesvári 2006)
- Used in: AlphaGo, AlphaZero MCTS node selection
- Proven: Mathematically optimal regret bounds

Formula: score(a) = Q(a) + c * sqrt(ln(N) / n(a))

Where:
- Q(a) = average reward for action a (0.0-1.0)
- c = exploration constant (√2 ≈ 1.41 is theoretically optimal)
- N = total actions taken
- n(a) = times action a has been tried
"""

from dataclasses import dataclass
from collections import defaultdict
import math
from typing import Dict
import logging

logger = logging.getLogger("numasec.exploration")


@dataclass
class ActionSignature:
    """
    Unique signature for an action (tool + arg pattern).
    
    We use arg keys only (not values) to identify action types.
    Example: web_request(url, headers) vs web_request(url, data)
    """
    tool: str
    arg_pattern: str  # e.g., "url,headers" (sorted keys)
    
    def __hash__(self):
        return hash((self.tool, self.arg_pattern))
    
    def __eq__(self, other):
        return isinstance(other, ActionSignature) and \
               self.tool == other.tool and \
               self.arg_pattern == other.arg_pattern


class UCBExplorer:
    """
    UCB1-based exploration policy.
    
    Tracks action rewards and uses UCB1 formula to prevent
    repeating actions with low expected reward.
    
    No magic numbers - mathematically optimal exploration.
    """
    
    def __init__(self, exploration_constant: float = 1.41):
        """
        Initialize UCB1 explorer.
        
        Args:
            exploration_constant: c in UCB1 formula (√2 ≈ 1.41 is optimal)
        """
        self.c = exploration_constant  # √2 ≈ 1.41
        self.action_counts: Dict[ActionSignature, int] = defaultdict(int)
        self.action_rewards: Dict[ActionSignature, list] = defaultdict(list)
        self.total_actions = 0
    
    def get_signature(self, tool: str, args: dict) -> ActionSignature:
        """
        Create action signature from tool + arg keys.
        
        Args:
            tool: Tool name
            args: Tool arguments dictionary
            
        Returns:
            ActionSignature for this action type
        """
        # Sort keys for deterministic signature
        arg_pattern = ",".join(sorted(args.keys()))
        return ActionSignature(tool, arg_pattern)
    
    def record_action(self, tool: str, args: dict, reward: float):
        """
        Record action outcome.
        
        Reward scale (from _calculate_reward):
        - 1.0 = Flag found (terminal success)
        - 0.7 = New information discovered
        - 0.3 = Neutral (action ran, no clear info)
        - 0.1 = Error (still informative)
        
        Args:
            tool: Tool name
            args: Tool arguments
            reward: Observed reward (0.0-1.0)
        """
        sig = self.get_signature(tool, args)
        self.action_counts[sig] += 1
        self.action_rewards[sig].append(reward)
        self.total_actions += 1
        
        logger.debug(
            f"Recorded: {sig.tool}({sig.arg_pattern}) → reward={reward:.2f} "
            f"(n={self.action_counts[sig]}, avg={sum(self.action_rewards[sig])/len(self.action_rewards[sig]):.2f})"
        )
    
    def get_ucb_score(self, tool: str, args: dict) -> float:
        """
        Calculate UCB1 score for an action.
        
        Higher score = agent should try this action.
        Balance between:
        - Exploitation: Q(a) - average reward
        - Exploration: c * sqrt(ln(N) / n(a)) - bonus for untried actions
        
        Args:
            tool: Tool name
            args: Tool arguments
            
        Returns:
            UCB1 score (higher = more promising)
        """
        sig = self.get_signature(tool, args)
        n_a = self.action_counts[sig]
        
        if n_a == 0:
            # Untried action gets maximum score (pure exploration)
            return float('inf')
        
        # Average reward (exploitation term)
        Q_a = sum(self.action_rewards[sig]) / n_a
        
        # Exploration bonus (decrease as action is tried more)
        exploration_bonus = self.c * math.sqrt(
            math.log(self.total_actions) / n_a
        )
        
        ucb_score = Q_a + exploration_bonus
        
        return ucb_score
    
    def should_override(self, tool: str, args: dict, threshold: float = 0.25) -> bool:
        """
        Check if action should be overridden due to low UCB score.
        
        Returns True if:
        - Action tried 2+ times (give it 2 chances)
        - Average reward < 0.20 (performing poorly)
        - UCB score < threshold (low overall promise)
        
        Args:
            tool: Tool name
            args: Tool arguments
            threshold: UCB score threshold for override (default 0.25)
            
        Returns:
            True if action should be blocked, False if allowed
        """
        sig = self.get_signature(tool, args)
        n_a = self.action_counts[sig]
        
        if n_a < 2:
            # Give new actions 2 chances before judging
            return False
        
        
        Q_a = sum(self.action_rewards[sig]) / n_a
        
        # CRITICAL FIX #3: Lowered from 0.25 → 0.20
        # Reasoning: Repeated results now give 0.15 reward
        # This threshold must be <= 0.20 to block them after 2-3 attempts
        if Q_a >= 0.20:
            # Reward is acceptable, allow action
            return False
        
        ucb_score = self.get_ucb_score(tool, args)
        
        if ucb_score < threshold:
            logger.warning(
                f"⚠️ UCB1 Override: {sig.tool}({sig.arg_pattern}) has low score "
                f"(Q={Q_a:.2f}, UCB={ucb_score:.2f}, n={n_a})"
            )
            return True
        
        return False
    
    def get_stats(self) -> dict:
        """
        Get exploration statistics.
        
        Returns:
            Dictionary with exploration metrics
        """
        if not self.action_counts:
            return {
                "total_actions": 0,
                "unique_actions": 0,
                "top_actions": []
            }
        
        # Calculate top actions by average reward
        top_actions = []
        for sig in self.action_counts.keys():
            avg_reward = sum(self.action_rewards[sig]) / len(self.action_rewards[sig])
            top_actions.append((
                f"{sig.tool}({sig.arg_pattern})",
                avg_reward,
                self.action_counts[sig]
            ))
        
        # Sort by average reward
        top_actions.sort(key=lambda x: x[1], reverse=True)
        
        return {
            "total_actions": self.total_actions,
            "unique_actions": len(self.action_counts),
            "top_actions": [
                {"action": name, "avg_reward": reward, "count": count}
                for name, reward, count in top_actions[:5]
            ]
        }
    
    def reset(self):
        """Reset all tracking (e.g., for new engagement)."""
        self.action_counts.clear()
        self.action_rewards.clear()
        self.total_actions = 0
        logger.info("UCB1 Explorer reset")
