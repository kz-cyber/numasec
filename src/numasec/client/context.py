"""
NumaSec - Context Manager

Intelligent context/token management for LLM conversations.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from numasec.client.providers.base import Message


logger = logging.getLogger("numasec.context")


@dataclass
class ContextConfig:
    """Context manager configuration."""
    max_tokens: int = 16000  # Context window budget
    preserve_system: bool = True  # Always keep system message
    preserve_recent: int = 4  # Always keep last N messages
    summarize_threshold: int = 10000  # Summarize tool outputs above this
    tool_output_limit: int = 15000  # Max chars per tool output


class ContextManager:
    """
    Intelligent context management for LLM conversations.
    
    Features:
    - Token budget tracking
    - Automatic summarization of long outputs
    - Smart pruning of old context
    - Critical info preservation (findings, credentials)
    
    Usage:
        context = ContextManager()
        context.add_message(Message(role="user", content="..."))
        
        # When context gets too full
        if context.needs_pruning():
            context.prune()
    """
    
    def __init__(self, config: ContextConfig | None = None):
        self.config = config or ContextConfig()
        self.messages: list[Message] = []
        self._critical_findings: list[str] = []  # Never prune these
        self._estimated_tokens = 0
    
    @property
    def token_count(self) -> int:
        """Estimated current token count."""
        return self._estimated_tokens
    
    @property
    def remaining_tokens(self) -> int:
        """Remaining token budget."""
        return self.config.max_tokens - self._estimated_tokens
    
    def _estimate_tokens(self, text: str) -> int:
        """Estimate tokens for text (~4 chars per token)."""
        return len(text) // 4
    
    def add_message(self, message: Message) -> None:
        """Add a message to context."""
        self.messages.append(message)
        self._estimated_tokens += self._estimate_tokens(message.content)
        
        # Extract critical findings
        self._extract_critical_info(message.content)
    
    def add_tool_result(
        self, 
        tool_name: str, 
        result: str, 
        tool_call_id: str
    ) -> Message:
        """
        Add a tool result, with automatic summarization if needed.
        
        Returns the message that was added.
        """
        # Summarize if too long
        if len(result) > self.config.tool_output_limit:
            result = self._summarize_tool_output(tool_name, result)
        
        message = Message(
            role="tool",
            content=result,
            tool_call_id=tool_call_id,
        )
        self.add_message(message)
        return message
    
    def _summarize_tool_output(self, tool_name: str, result: str) -> str:
        """Summarize a long tool output."""
        if tool_name == "web_request":
            return self._summarize_web_response(result)
        
        # Default: truncate with head/tail
        limit = self.config.tool_output_limit
        if len(result) > limit:
            head = limit * 2 // 3
            tail = limit // 3
            return (
                result[:head] + 
                f"\n\n... [TRUNCATED {len(result)} chars] ...\n\n" +
                result[-tail:]
            )
        return result
    
    def _summarize_web_response(self, result: str) -> str:
        """Summarize web_request output, keeping important fields."""
        try:
            data = json.loads(result)
            
            summary = {
                "success": data.get("success"),
                "status_code": data.get("status_code"),
                "url": data.get("url"),
                "cookies": data.get("cookies", {}),
                "form_fields": data.get("form_fields", {}),
            }
            
            body = data.get("body", "")
            limit = self.config.tool_output_limit - 1000  # Reserve space for metadata
            
            if len(body) > limit:
                summary["body"] = body[:limit * 2 // 3] + "\n...[TRUNCATED]...\n" + body[-limit // 3:]
                summary["_note"] = f"Body truncated from {len(body)} chars"
            else:
                summary["body"] = body
            
            return json.dumps(summary, indent=2)
            
        except (json.JSONDecodeError, KeyError):
            # Fallback to default truncation
            return self._summarize_tool_output("default", result)
    
    def _extract_critical_info(self, content: str) -> None:
        """Extract and save critical information that should never be pruned."""
        import re
        
        # Extract flags
        flag_patterns = [
            r'picoCTF\{[^}]+\}',
            r'flag\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'htb\{[^}]+\}',
        ]
        for pattern in flag_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.group() not in self._critical_findings:
                    self._critical_findings.append(match.group())
                    logger.info(f"Critical finding extracted: {match.group()}")
        
        # Extract credentials (simple patterns)
        cred_patterns = [
            r'password["\s:=]+([^\s"\'<>]+)',
            r'passwd["\s:=]+([^\s"\'<>]+)',
            r'token["\s:=]+([^\s"\'<>]+)',
        ]
        for pattern in cred_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                finding = f"CREDENTIAL: {match.group()}"
                if finding not in self._critical_findings:
                    self._critical_findings.append(finding)
    
    def needs_pruning(self) -> bool:
        """Check if context needs pruning."""
        return self._estimated_tokens > self.config.max_tokens * 0.8
    
    def prune(self) -> None:
        """Prune old messages to stay within token budget."""
        if not self.needs_pruning():
            return
        
        # Separate messages by type
        system_msgs = [m for m in self.messages if m.role == "system"]
        other_msgs = [m for m in self.messages if m.role != "system"]
        
        # Keep last N messages
        preserved = other_msgs[-self.config.preserve_recent:]
        prunable = other_msgs[:-self.config.preserve_recent]
        
        # Remove oldest messages until under budget
        target = self.config.max_tokens * 0.6
        while prunable and self._estimated_tokens > target:
            removed = prunable.pop(0)
            self._estimated_tokens -= self._estimate_tokens(removed.content)
        
        # Rebuild message list
        self.messages = system_msgs + prunable + preserved
        
        logger.info(f"Context pruned. {len(self.messages)} messages, ~{self._estimated_tokens} tokens")
    
    def get_messages(self) -> list[Message]:
        """Get all messages for LLM call."""
        return self.messages
    
    def get_critical_findings(self) -> list[str]:
        """Get list of critical findings (flags, credentials)."""
        return self._critical_findings
    
    def clear(self) -> None:
        """Clear all messages."""
        self.messages.clear()
        self._estimated_tokens = 0
