"""
NumaSec - LLM Provider Base Class

Abstract interface for LLM providers (DeepSeek, OpenAI, Claude, Ollama, etc.).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator


@dataclass
class Message:
    """A conversation message."""
    role: str  # "system", "user", "assistant", "tool"
    content: str
    name: str | None = None  # For tool messages
    tool_call_id: str | None = None  # For tool results
    tool_calls: list["ToolCall"] | None = None  # For assistant with tool calls
    
    def to_dict(self) -> dict[str, Any]:
        """Convert message to dict format for LLM APIs."""
        result: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.name:
            result["name"] = self.name
        if self.tool_call_id:
            result["tool_call_id"] = self.tool_call_id
        if self.tool_calls:
            result["tool_calls"] = [
                {"id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": tc.arguments}}
                for tc in self.tool_calls
            ]
        return result


@dataclass
class ToolCall:
    """A tool call from the LLM."""
    id: str
    name: str
    arguments: dict[str, Any]
    
    @classmethod
    def from_openai_format(cls, tc: dict) -> "ToolCall":
        """Create from OpenAI/DeepSeek format."""
        import json
        func = tc.get("function", {})
        try:
            args = json.loads(func.get("arguments", "{}"))
        except json.JSONDecodeError:
            args = {}
        return cls(
            id=tc.get("id", ""),
            name=func.get("name", ""),
            arguments=args
        )


@dataclass
class ToolDefinition:
    """Tool definition for LLM."""
    name: str
    description: str
    parameters: dict[str, Any]
    
    def to_openai_format(self) -> dict:
        """Convert to OpenAI/DeepSeek function format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters
            }
        }
    
    def to_raw_format(self) -> dict:
        """Convert to raw format expected by LLMRouter."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.parameters
        }
    
    @classmethod
    def from_mcp_format(cls, mcp_tool: dict) -> "ToolDefinition":
        """Create from MCP tool definition."""
        return cls(
            name=mcp_tool.get("name", ""),
            description=mcp_tool.get("description", ""),
            parameters=mcp_tool.get("inputSchema", {"type": "object", "properties": {}})
        )


@dataclass
class LLMResponse:
    """Response from an LLM."""
    content: str | None
    tool_calls: list[ToolCall]
    finish_reason: str  # "stop", "tool_calls", "length", "error"
    usage: dict[str, int] = field(default_factory=dict)
    raw: dict = field(default_factory=dict)
    
    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


@dataclass
class LLMChunk:
    """Streaming chunk from LLM."""
    content_delta: str | None
    tool_call_delta: dict | None  # Partial tool call
    finish_reason: str | None


@dataclass 
class ProviderConfig:
    """Base configuration for LLM providers."""
    api_key: str = ""
    model: str = ""
    max_tokens: int = 4096
    temperature: float = 0.1
    timeout: float = 120.0


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.
    
    Provides a unified interface for different LLM APIs.
    All providers support:
    - Chat completions with tool calling
    - Streaming responses
    - Token counting
    """
    
    def __init__(self, config: ProviderConfig):
        self.config = config
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for logging."""
        ...
    
    @property
    @abstractmethod
    def supports_parallel_tools(self) -> bool:
        """Whether this provider supports parallel tool calls."""
        ...
    
    @abstractmethod
    async def chat(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
    ) -> LLMResponse:
        """
        Send a chat completion request.
        
        Args:
            messages: Conversation history
            tools: Available tools for function calling
            
        Returns:
            LLMResponse with content and/or tool calls
        """
        ...
    
    @abstractmethod
    async def stream(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
    ) -> AsyncGenerator[LLMChunk, None]:
        """
        Stream a chat completion response.
        
        Args:
            messages: Conversation history
            tools: Available tools
            
        Yields:
            LLMChunk with incremental content/tool calls
        """
        ...
    
    def count_tokens(self, text: str) -> int:
        """
        Estimate token count for text.
        
        Default implementation uses rough estimate.
        Override for provider-specific tokenizer.
        """
        # Rough estimate: ~4 chars per token
        return len(text) // 4
    
    def count_message_tokens(self, messages: list[Message]) -> int:
        """Estimate tokens for a conversation."""
        total = 0
        for msg in messages:
            total += self.count_tokens(msg.content)
            if msg.tool_calls:
                for tc in msg.tool_calls:
                    total += self.count_tokens(str(tc.arguments))
        return total
    
    async def close(self) -> None:
        """Close any resources (e.g., HTTP client)."""
        pass
    
    async def __aenter__(self) -> "LLMProvider":
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()


class ProviderError(Exception):
    """Base exception for provider errors."""
    pass


class RateLimitError(ProviderError):
    """Rate limit exceeded."""
    def __init__(self, retry_after: float | None = None):
        super().__init__("Rate limit exceeded")
        self.retry_after = retry_after


class TokenLimitError(ProviderError):
    """Token limit exceeded."""
    pass
