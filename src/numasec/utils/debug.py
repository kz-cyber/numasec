"""
NumaSec - Deep Debug Mode

Comprehensive debugging infrastructure to expose agent's complete decision-making process.

Usage:
    export NUMASEC_DEBUG=1  # Enable debug mode
    python3 -m numasec

Debug Features:
    1. LLM Prompts & Responses (full conversation)
    2. Confidence Scores (why escalate to LIGHT mode)
    3. Tool Selection Reasoning (why this tool, not that)
    4. Loop Detection Logic (hash comparisons, thresholds)
    5. RAG Trigger Signals (all 5 signals breakdown)
    6. Error Handling Decisions (why retry, why pivot)
    7. State Snapshots (facts, hints, commitment mode)
"""

import os
import logging
import json
from datetime import datetime
from pathlib import Path

# Debug level: 0=OFF, 1=INFO, 2=VERBOSE, 3=TRACE
DEBUG_LEVEL = int(os.getenv("NUMASEC_DEBUG", "0"))

# Debug log directory (allow override for containers)
DEBUG_LOG_DIR = Path(os.getenv("NUMASEC_DEBUG_DIR", str(Path.home() / ".numasec" / "debug")))
try:
    DEBUG_LOG_DIR.mkdir(parents=True, exist_ok=True)
except (PermissionError, OSError):
    # Fallback to /tmp if home directory not writable (container scenario)
    DEBUG_LOG_DIR = Path("/tmp/numasec_debug")
    DEBUG_LOG_DIR.mkdir(parents=True, exist_ok=True)

DEBUG_LOG_FILE = DEBUG_LOG_DIR / f"debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"


class DebugLogger:
    """Enterprise-grade debug logger for agent introspection."""
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled or DEBUG_LEVEL > 0
        self.level = DEBUG_LEVEL
        self.log_file = DEBUG_LOG_FILE if self.enabled else None
        
        if self.enabled:
            # Create file handler
            self.file_handler = logging.FileHandler(self.log_file)
            self.file_handler.setLevel(logging.DEBUG)
            
            #Console handler for real-time debugging
            self.console_handler = logging.StreamHandler()
            self.console_handler.setLevel(logging.DEBUG if self.level >= 2 else logging.INFO)
            
            # Formatter
            formatter = logging.Formatter(
                '%(asctime)s | %(name)s | %(levelname)s | %(message)s',
                datefmt='%H:%M:%S'
            )
            self.file_handler.setFormatter(formatter)
            self.console_handler.setFormatter(formatter)
            
            print(f"\n{'='*80}")
            print(f"🐛 DEBUG MODE ENABLED (Level {self.level})")
            print(f"📝 Debug log: {self.log_file}")
            print(f"{'='*80}\n")
    
    def log_llm_prompt(self, messages: list, context: str = ""):
        """Log complete LLM prompt."""
        if not self.enabled or self.level < 2:
            return
        
        print(f"\n{'='*80}")
        print(f"📤 LLM PROMPT {f'({context})' if context else ''}")
        print(f"{'='*80}")
        for msg in messages:
            role = msg.get("role", "unknown").upper()
            content = msg.get("content", "")
            print(f"\n[{role}]")
            print(content[:500] + ("..." if len(content) > 500 else ""))
        print(f"{'='*80}\n")
    
    def log_llm_response(self, response, context: str = ""):
        """Log complete LLM response."""
        if not self.enabled or self.level < 2:
            return
        
        print(f"\n{'='*80}")
        print(f"📥 LLM RESPONSE {f'({context})' if context else ''}")
        print(f"{'='*80}")
        print(f"Content: {getattr(response, 'content', '')[:500]}")
        if hasattr(response, 'tool_calls') and response.tool_calls:
            print(f"\nTool Calls: {len(response.tool_calls)}")
            for tc in response.tool_calls:
                print(f"  - {tc.get('name', 'unknown')}: {tc.get('arguments', {})}")
        print(f"{'='*80}\n")
    
    def log_confidence(self, confidence: float, mode: str, reasoning: str = ""):
        """Log confidence score and mode decision."""
        if not self.enabled or self.level < 1:
            return
        
        print(f"\n🎯 CONFIDENCE: {confidence:.2f} | MODE: {mode}")
        if reasoning:
            print(f"   Reasoning: {reasoning[:200]}")
        print()
    
    def log_tool_selection(self, tool: str, args: dict, reasoning: str = ""):
        """Log tool selection with reasoning."""
        if not self.enabled or self.level < 1:
            return
        
        print(f"\n🔧 TOOL SELECTED: {tool}")
        print(f"   Args: {json.dumps(args, indent=2)[:300]}")
        if reasoning:
            print(f"   Why: {reasoning[:200]}")
        print()
    
    def log_loop_detection(self, hash_val: str, count: int, threshold: int, decision: str):
        """Log loop detection logic."""
        if not self.enabled or self.level < 1:
            return
        
        print(f"\n🔁 LOOP DETECTION")
        print(f"   Hash: {hash_val[:8]}...")
        print(f"   Count: {count}/{threshold}")
        print(f"   Decision: {decision}")
        print()
    
    def log_rag_trigger(self, signals: dict, score: float, threshold: float, triggered: bool):
        """Log RAG trigger signals breakdown."""
        if not self.enabled or self.level < 2:
            return
        
        print(f"\n🧠 RAG TRIGGER ANALYSIS")
        print(f"   Signals: {json.dumps(signals, indent=2)}")
        print(f"   Score: {score:.2f} / {threshold:.2f}")
        print(f"   Triggered: {'YES' if triggered else 'NO'}")
        print()
    
    def log_error_handling(self, error_type: str, error_msg: str, decision: str):
        """Log error handling decisions."""
        if not self.enabled:
            return
        
        print(f"\n❌ ERROR HANDLING")
        print(f"   Type: {error_type}")
        print(f"   Message: {error_msg[:200]}")
        print(f"   Decision: {decision}")
        print()
    
    def log_state_snapshot(self, state_dict: dict):
        """Log complete agent state."""
        if not self.enabled or self.level < 3:
            return
        
        print(f"\n📸 STATE SNAPSHOT")
        print(json.dumps(state_dict, indent=2)[:1000])
        print()


# Global debug logger instance
debug_logger = DebugLogger(enabled=DEBUG_LEVEL > 0)
