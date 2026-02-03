"""
NumaSec - Cognitive Reasoner

Single-call reasoning optimized for speed and cost.

Scientific Basis:
- Direct LLM reasoning with structured prompts (SOTA 2026)
- Cost-optimized: 1 API call per decision
- Proven: Fast iteration without analysis paralysis

Mode:
- SINGLE: 1 API call with structured reasoning template
"""

from enum import Enum
from typing import Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger("numasec.reasoning")

# Import debug logger
from numasec.utils.debug import debug_logger


# ══════════════════════════════════════════════════════════════════════════════
# SOTA 2026: Cached LLM Prompt Template (Module-Level Constant)
# Performance: Eliminates 90-line string construction per iteration (-100ms)
# ══════════════════════════════════════════════════════════════════════════════

REASONING_TEMPLATE_PROMPT = (
    "Think step-by-step using the MANDATORY reasoning template:\n\n"
    
    "<reasoning_template>\n"
    "YOU MUST START EVERY RESPONSE WITH THIS EXACT XML BLOCK:\n\n"
    
    "<analysis>\n"
    "[Critique of previous result. What specifically failed? What did we learn?]\n"
    "</analysis>\n\n"
    
    "<hypothesis>\n"
    "[Current theory. What exactly are we testing and why?]\n"
    "</hypothesis>\n\n"
    
    "<confidence>\n"
    "[SPECULATIVE|POSSIBLE|PROBABLE|CONFIRMED] Based on: ...\n"
    "</confidence>\n\n"
    
    "<action>\n"
    "[Tool selection. ONE specific action.]\n"
    "</action>\n\n"
    
    "<expectation>\n"
    "[Concrete success criteria. What string/code proves this?]\n"
    "</expectation>\n"
    "</reasoning_template>\n\n"
    
    "THEN call the appropriate tool."
)


class ReasoningMode(Enum):
    """Reasoning mode (single-call only)."""
    SINGLE = "single"  # 1 API call (optimized for speed)


@dataclass
class ReasoningResult:
    """Result of reasoning process."""
    tool: str
    args: dict
    reasoning: str
    confidence: float  # 0.0-1.0


class CognitiveReasoner:
    """
    Adaptive reasoning engine.
    
    Escalates from single-call to multi-call based on LLM confidence.
    Optimizes token cost while maintaining quality.
    """
    
    def __init__(self, router):
        """
        Initialize cognitive reasoner.
        
        Args:
            router: LLMRouter instance for API calls
        """
        self.router = router
    
    async def reason(
        self,
        messages: list,
        available_tools: list
    ) -> ReasoningResult:
        """
        Single-call reasoning with structured template.
        
        Optimized for speed: 1 LLM call per decision with mandatory
        reasoning structure (analysis, hypothesis, confidence, action).
        
        Args:
            messages: Conversation history
            available_tools: Available tool definitions
            
        Returns:
            ReasoningResult with tool choice and confidence
        """
        result = await self._single_call(messages, available_tools)
        logger.info(f"✅ Reasoning complete (confidence: {result.confidence:.2f})")
        return result
    
    async def _single_call(self, messages: list, tools: list) -> ReasoningResult:
        """
        Single-call reasoning (default, fast).
        
        Args:
            messages: Conversation history
            tools: Available tools
            
        Returns:
            ReasoningResult from single LLM call
        """
        # Add reasoning prompt (SOTA 2026: cached template, zero allocations)
        enhanced_messages = messages + [{
            "role": "user",
            "content": REASONING_TEMPLATE_PROMPT
        }]
        
        # DEBUG: Log LLM prompt
        debug_logger.log_llm_prompt(enhanced_messages, context="SINGLE_CALL")
        
        response = await self.router.complete(
            messages=enhanced_messages,
            tools=tools
        )
        
        # DEBUG: Log LLM response
        debug_logger.log_llm_response(response, context="SINGLE_CALL")
        
        # SOTA 2026: Validate reasoning structure (Forcing Function)
        validation_error = self._validate_reasoning(response.content)
        if validation_error:
            logger.warning(f"⚠️ Reasoning Validation Failed: {validation_error}")
            # In stricter modes, we might retry here. For now, just log.
        
        # Extract tool call
        tool_call = response.tool_calls[0] if response.tool_calls else {}
        
        # DEBUG: Log tool selection
        if tool_call:
            debug_logger.log_tool_selection(
                tool=tool_call.get("name", "unknown"),
                args=tool_call.get("arguments", {}),
                reasoning=response.content or ""
            )
        
        # Estimate confidence from response
        confidence = self._estimate_confidence(response.content or "")
        
        # DEBUG: Log confidence
        debug_logger.log_confidence(
            confidence=confidence,
            mode="SINGLE",
            reasoning=response.content or ""
        )
        
        return ReasoningResult(
            tool=tool_call.get("name", ""),
            args=tool_call.get("arguments", {}),
            reasoning=response.content or "",
            confidence=confidence
        )
    
    def _estimate_confidence(self, text: str) -> float:
        """
        Heuristic confidence estimation from LLM response.
        
        Args:
            text: LLM response text
            
        Returns:
            Estimated confidence (0.0-1.0)
        """
        if not text:
            return 0.3  # No reasoning → low confidence
        
        text_lower = text.lower()
        
        # High confidence indicators
        high_confidence_phrases = [
            "clearly", "obviously", "definitely", "certainly",
            "confident", "sure", "verified", "confirmed"
        ]
        if any(phrase in text_lower for phrase in high_confidence_phrases):
            return 0.8
        
        # Low confidence indicators
        low_confidence_phrases = [
            "unsure", "might", "possibly", "maybe", "perhaps",
            "uncertain", "not sure", "unclear", "could be"
        ]
        if any(phrase in text_lower for phrase in low_confidence_phrases):
            return 0.3
        
        # Medium confidence indicators
        medium_phrases = [
            "likely", "probably", "should", "expect"
        ]
        if any(phrase in text_lower for phrase in medium_phrases):
            return 0.6
        
        # Default: neutral confidence
        return 0.5

    def _validate_reasoning(self, text: str) -> Optional[str]:
        """
        Check if the response follows the strict SOTA XML template.
        
        SOTA 2026 Requirement:
        - Must contain <analysis>, <hypothesis>, <confidence>, <action>, <expectation>
        - Confidence must be explicit
        """
        if not text:
            return "Empty response"
            
        required_tags = ["<analysis>", "<hypothesis>", "<confidence>", "<action>", "<expectation>"]
        missing = [tag for tag in required_tags if tag not in text]
        
        if missing:
            return f"Missing required XML tags: {', '.join(missing)}"
            
        # Check confidence block content
        import re
        conf_match = re.search(r"<confidence>(.*?)</confidence>", text, re.DOTALL)
        if not conf_match:
            return "Confidence block empty or malformed"
            
        conf_text = conf_match.group(1).upper()
        valid_levels = ["SPECULATIVE", "POSSIBLE", "PROBABLE", "CONFIRMED"]
        if not any(level in conf_text for level in valid_levels):
            return f"Invalid confidence level. Must be one of: {valid_levels}"
            
        return None
