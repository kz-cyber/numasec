"""
NumaSec - DeepSeek Provider

DeepSeek LLM provider with function calling support.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator

import httpx

from numasec.client.providers.base import (
    LLMProvider,
    ProviderConfig,
    Message,
    ToolCall,
    ToolDefinition,
    LLMResponse,
    LLMChunk,
    ProviderError,
    RateLimitError,
)


logger = logging.getLogger("numasec.provider.deepseek")


@dataclass
class DeepSeekConfig(ProviderConfig):
    """DeepSeek-specific configuration."""
    api_base: str = "https://api.deepseek.com"
    model: str = "deepseek-chat"
    max_tokens: int = 4096
    temperature: float = 0.1
    timeout: float = 120.0
    
    def __post_init__(self):
        # Auto-load API key from environment
        if not self.api_key:
            self.api_key = os.environ.get("DEEPSEEK_API_KEY", "")


class DeepSeekProvider(LLMProvider):
    """
    DeepSeek LLM provider.
    
    Supports:
    - Chat completions
    - Function calling (tool_calls)
    - Streaming responses
    
    Usage:
        async with DeepSeekProvider(DeepSeekConfig(api_key="...")) as provider:
            response = await provider.chat(messages, tools)
    """
    
    def __init__(self, config: DeepSeekConfig | None = None):
        config = config or DeepSeekConfig()
        super().__init__(config)
        self.config: DeepSeekConfig = config
        self._client: httpx.AsyncClient | None = None
    
    @property
    def name(self) -> str:
        return "deepseek"
    
    @property
    def supports_parallel_tools(self) -> bool:
        return True  # DeepSeek supports parallel tool calls
    
    def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.api_base,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=self.config.timeout,
            )
        return self._client
    
    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    def _format_messages(self, messages: list[Message]) -> list[dict]:
        """Convert messages to DeepSeek API format."""
        formatted = []
        for msg in messages:
            m: dict[str, Any] = {
                "role": msg.role,
                "content": msg.content or "",
            }
            if msg.tool_call_id:
                m["tool_call_id"] = msg.tool_call_id
            if msg.tool_calls:
                m["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments)
                        }
                    }
                    for tc in msg.tool_calls
                ]
            formatted.append(m)
        return formatted
    
    def _format_tools(self, tools: list[ToolDefinition]) -> list[dict]:
        """Convert tools to DeepSeek API format."""
        return [tool.to_openai_format() for tool in tools]
    
    async def chat(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
    ) -> LLMResponse:
        """Send chat completion request."""
        client = self._get_client()
        
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": self._format_messages(messages),
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        }
        
        if tools:
            payload["tools"] = self._format_tools(tools)
            payload["tool_choice"] = "auto"
        
        try:
            response = await client.post("/chat/completions", json=payload)
            
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                raise RateLimitError(float(retry_after) if retry_after else None)
            
            response.raise_for_status()
            data = response.json()
            
        except httpx.HTTPStatusError as e:
            raise ProviderError(f"DeepSeek API error: {e.response.status_code}") from e
        except httpx.RequestError as e:
            raise ProviderError(f"Request failed: {e}") from e
        
        # Parse response
        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        
        tool_calls = []
        if message.get("tool_calls"):
            for tc in message["tool_calls"]:
                tool_calls.append(ToolCall.from_openai_format(tc))
        
        return LLMResponse(
            content=message.get("content"),
            tool_calls=tool_calls,
            finish_reason=choice.get("finish_reason", "stop"),
            usage=data.get("usage", {}),
            raw=data,
        )
    
    async def stream(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
    ) -> AsyncGenerator[LLMChunk, None]:
        """Stream chat completion response."""
        client = self._get_client()
        
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": self._format_messages(messages),
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "stream": True,
        }
        
        if tools:
            payload["tools"] = self._format_tools(tools)
            payload["tool_choice"] = "auto"
        
        try:
            async with client.stream("POST", "/chat/completions", json=payload) as response:
                response.raise_for_status()
                
                async for line in response.aiter_lines():
                    if not line or line == "data: [DONE]":
                        continue
                    
                    if line.startswith("data: "):
                        try:
                            data = json.loads(line[6:])
                            choice = data.get("choices", [{}])[0]
                            delta = choice.get("delta", {})
                            
                            yield LLMChunk(
                                content_delta=delta.get("content"),
                                tool_call_delta=delta.get("tool_calls"),
                                finish_reason=choice.get("finish_reason"),
                            )
                        except json.JSONDecodeError:
                            continue
                            
        except httpx.HTTPStatusError as e:
            raise ProviderError(f"DeepSeek API error: {e.response.status_code}") from e
        except httpx.RequestError as e:
            raise ProviderError(f"Request failed: {e}") from e
